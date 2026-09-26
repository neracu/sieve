"""Incident dashboard API for the Security Guardian demo.

This process does not detect injections or decide approvals. A background
loop reads ``resource://audit-log`` and ``resource://pending-approvals``
from the Security Guardian MCP server about once a second, merges them
into one incident list, and serves that list from memory.

A per-request MCP call would add a session round-trip to every page load
and would not wake stream clients. The refresh loop does both: ``GET
/incidents`` only reads the in-memory dict, and the same loop pushes
server-sent events when an incident is created or updated.

The in-memory dict is the runtime source of truth. Each create or change
is flushed to a JSONL file before it is visible, so a restart restores
history without a live MCP call. ``GET /incidents`` and ``GET /incidents/{id}``
read that store directly. While the MCP server is unreachable,
``GET /incidents/summary`` returns 503 and the stream emits ``mcp_status``.

Environment
-----------
``SIEVE_MCP_URL``
    Streamable HTTP endpoint of the Security Guardian server.
    Default ``http://127.0.0.1:8081/mcp``. Start that server with
    ``python mcp_server.py --http``. Bob's stdio MCP process is a
    different runtime; point this URL at the server you want the
    dashboard to watch.
``SIEVE_INCIDENTS_PATH``
    Append-only JSONL durability file. Default ``sieve_incidents.jsonl``
    in the working directory.
``SIEVE_DASHBOARD_CORS_ORIGINS``
    Comma-separated browser origins allowed to call this API.
    Default ``*`` so a local frontend on any port can reach the demo.
``SIEVE_DASHBOARD_REFRESH_SECONDS``
    Poll interval. Default ``1``.

Run::

    python mcp_server.py --http
    uvicorn sieve.dashboard.dashboard_backend:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import threading
import time
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict

from sieve.core.logger import get_logger

log = get_logger(__name__)

_SUMMARY_LIMIT = 180
_ACTION_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SOURCES = {
    "github_issue": "github_issue",
    "github_pr": "github_pr",
    "web_fetch": "web_fetch",
    "readme": "readme",
    "untrusted": "untrusted",
    "user": "user",
}
_APPROVALS = {
    "paused": ("approval_pending", "pending"),
    "pending": ("approval_pending", "pending"),
    "pending_approval": ("approval_pending", "pending"),
    "approved": ("approval_approved", "approved"),
    "rejected": ("approval_rejected", "rejected"),
    "timed_out": ("approval_timed_out", "timed_out"),
}
_TERMINAL = {"approved", "rejected", "timed_out"}
_STATUSES = ("blocked", "pending_approval", "pending", "approved", "rejected", "timed_out")
_TYPES = (
    "quarantine_block",
    "approval_pending",
    "approval_approved",
    "approval_rejected",
    "approval_timed_out",
)
MCP_UNAVAILABLE = {
    "error": "mcp_unavailable",
    "message": "MCP server is unreachable.",
}
_NOT_FOUND = {"error": "not_found", "message": "Incident not found."}
_BAD_SINCE = {"error": "invalid_params", "message": "since must be an ISO-8601 timestamp."}

IncidentType = Literal[
    "quarantine_block",
    "approval_pending",
    "approval_approved",
    "approval_rejected",
    "approval_timed_out",
]
IncidentStatus = Literal[
    "blocked",
    "pending_approval",
    "pending",
    "approved",
    "rejected",
    "timed_out",
]
DetectorLabel = Literal["L1", "L2", "both"]


class McpUnavailable(Exception):
    """The Security Guardian MCP server could not be read."""


class ResourceSource(Protocol):
    """Reads the two MCP resources the dashboard merges."""

    async def read(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return ``(audit-log payload, pending-approvals payload)``."""

    async def close(self) -> None:
        """Release a held MCP session."""


class Incident(BaseModel):
    """One dashboard row. Raw untrusted content is not a field."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: str
    type: IncidentType
    source: str
    detector: DetectorLabel | None = None
    risk_score: float | None = None
    action: str | None = None
    risk_tier: str | None = None
    context_summary: str
    timestamp: str
    status: IncidentStatus


def normalize_source(value: Any) -> str:
    """Map an upstream source token onto the dashboard vocabulary."""
    if not isinstance(value, str):
        return "unknown"
    key = value.strip().lower().replace("-", "_")
    return _SOURCES.get(key, "unknown")


def normalize_detector(value: Any) -> DetectorLabel | None:
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    if key == "l1":
        return "L1"
    if key == "l2":
        return "L2"
    if key == "both":
        return "both"
    return None


def _bound(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= _SUMMARY_LIMIT:
        return collapsed
    return collapsed[: _SUMMARY_LIMIT - 1].rstrip() + "…"


def _score(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    score = float(value)
    if score != score:
        return None
    return score


def _action(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if _ACTION_RE.fullmatch(text) is None:
        return None
    return text


def _tier(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    tier = value.strip().lower()
    if tier in {"low", "medium", "high"}:
        return tier
    return None


def _timestamp(value: Any) -> str | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return parsed.isoformat()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _uuid(value: Any) -> str | None:
    if not isinstance(value, str) or _UUID_RE.fullmatch(value.strip()) is None:
        return None
    return value.strip()


def _summary(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return _bound(value)


def _quarantine_status(row: dict[str, Any], event: str, reason: str) -> IncidentStatus:
    """Map wrapper action_taken onto the incident status."""
    action = str(row.get("action_taken") or "").strip().upper()
    if action == "PENDING_APPROVAL":
        return "pending_approval"
    if action == "BLOCKED":
        return "blocked"
    if action == "QUARANTINED" or reason.strip().lower() == "approval_required" or event == "QUARANTINED":
        return "pending_approval"
    return "blocked"


def normalize_audit_entry(row: dict[str, Any]) -> Incident | None:
    """Turn one audit-log row into an incident, or None when it is not one."""
    if not isinstance(row, dict):
        return None
    kind = row.get("kind")
    outcome = str(row.get("outcome") or "").strip().lower()
    if kind == "approval" or row.get("approval_id") or outcome in _APPROVALS:
        return _approval_incident(row, outcome)
    event = str(row.get("outcome") or row.get("decision") or "").strip().upper()
    if event not in {"BLOCKED", "QUARANTINED"}:
        return None
    content_id = _uuid(row.get("content_id"))
    timestamp = _timestamp(row.get("timestamp"))
    if content_id is None or timestamp is None:
        return None
    reason = row.get("reason") if isinstance(row.get("reason"), str) else ""
    return Incident(
        id=content_id,
        type="quarantine_block",
        source=normalize_source(row.get("source")),
        detector=normalize_detector(row.get("detector")),
        risk_score=_score(row.get("risk_score")),
        action=None,
        risk_tier=None,
        context_summary=_bound(reason),
        timestamp=timestamp,
        status=_quarantine_status(row, event, reason),
    )


def normalize_pending_entry(row: dict[str, Any]) -> Incident | None:
    """Turn one pending-approvals row into an incident."""
    if not isinstance(row, dict):
        return None
    return _approval_incident(row, str(row.get("status") or "pending"))


def _approval_incident(row: dict[str, Any], outcome: str) -> Incident | None:
    mapped = _APPROVALS.get(outcome.strip().lower())
    if mapped is None:
        return None
    approval_id = _uuid(row.get("approval_id"))
    timestamp = _timestamp(row.get("timestamp") or row.get("requested_at"))
    if approval_id is None or timestamp is None:
        return None
    incident_type, status = mapped
    return Incident(
        id=approval_id,
        type=incident_type,  # type: ignore[arg-type]
        source=normalize_source(row.get("source")),
        detector=None,
        risk_score=None,
        action=_action(row.get("action")),
        risk_tier=_tier(row.get("risk_tier")),
        context_summary=_summary(row.get("context_summary")),
        timestamp=timestamp,
        status=status,  # type: ignore[arg-type]
    )


class IncidentStore:
    """In-memory incidents plus an append-only JSONL backstop."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._items: dict[str, Incident] = {}
        self._lock = threading.Lock()
        self._load()

    def apply(self, audit: dict[str, Any], pending: dict[str, Any]) -> list[Incident]:
        """Upsert resource payloads. Missing rows are kept, not deleted."""
        changed: list[Incident] = []
        entries = audit.get("entries") if isinstance(audit, dict) else None
        approvals = pending.get("approvals") if isinstance(pending, dict) else None
        ordered = _oldest_first(entries if isinstance(entries, list) else [])
        for row in ordered:
            incident = normalize_audit_entry(row) if isinstance(row, dict) else None
            stored = self._upsert(incident) if incident is not None else None
            if stored is not None:
                changed.append(stored)
        for row in approvals if isinstance(approvals, list) else []:
            incident = normalize_pending_entry(row) if isinstance(row, dict) else None
            stored = self._upsert(incident) if incident is not None else None
            if stored is not None:
                changed.append(stored)
        return changed

    def query(
        self,
        *,
        status: str | None,
        incident_type: str | None,
        source: str | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> tuple[list[Incident], int]:
        with self._lock:
            rows = list(self._items.values())
        rows.sort(key=lambda item: (item.timestamp, item.id), reverse=True)
        if status:
            rows = [item for item in rows if item.status == status]
        if incident_type:
            rows = [item for item in rows if item.type == incident_type]
        if source:
            rows = [item for item in rows if item.source == source]
        if since is not None:
            rows = [item for item in rows if _after(item.timestamp, since)]
        total = len(rows)
        return rows[offset : offset + limit], total

    def get(self, incident_id: str) -> Incident | None:
        with self._lock:
            return self._items.get(incident_id)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            rows = list(self._items.values())
        rows.sort(key=lambda item: (item.timestamp, item.id), reverse=True)
        return {"incidents": [item.model_dump() for item in rows], "total": len(rows)}

    def summary(self) -> dict[str, Any]:
        with self._lock:
            rows = list(self._items.values())
        by_status = dict.fromkeys(_STATUSES, 0)
        by_type = dict.fromkeys(_TYPES, 0)
        by_source: dict[str, int] = {}
        for item in rows:
            by_status[item.status] = by_status.get(item.status, 0) + 1
            by_type[item.type] = by_type.get(item.type, 0) + 1
            by_source[item.source] = by_source.get(item.source, 0) + 1
        return {
            "total": len(rows),
            "by_status": by_status,
            "by_type": by_type,
            "by_source": by_source,
        }

    def _upsert(self, incident: Incident) -> Incident | None:
        with self._lock:
            current = self._items.get(incident.id)
            if current is not None and current.status in _TERMINAL and incident.status == "pending":
                return None
            if (
                current is not None
                and current.status == incident.status
                and current.type == incident.type
            ):
                return None
            if current is not None and not incident.context_summary:
                incident = incident.model_copy(update={"context_summary": current.context_summary})
            self._items[incident.id] = incident
            self._append(incident)
            return incident

    def _append(self, incident: Incident) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(incident.model_dump_json() + "\n")
            handle.flush()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            log.warning("Incident JSONL could not be read.", extra={"error": str(exc)})
            return
        for line in lines:
            text = line.strip()
            if not text:
                continue
            try:
                incident = Incident.model_validate(json.loads(text))
            except (ValueError, TypeError):
                continue
            self._items[incident.id] = incident


def _oldest_first(entries: list[Any]) -> list[Any]:
    """Audit resources are newest-first. Apply the oldest decision first."""
    indexed = list(enumerate(row for row in entries if isinstance(row, dict)))
    indexed.sort(key=lambda pair: (str(pair[1].get("timestamp") or ""), -pair[0]))
    return [row for _, row in indexed]


def _after(timestamp: str, since: datetime) -> bool:
    parsed = _parse_time(timestamp)
    if parsed is None:
        return False
    return parsed > since


class HttpMcpResourceClient:
    """Long-lived streamable-HTTP session. Reconnect by calling ``close``."""

    def __init__(self, url: str, timeout: float = 2.0) -> None:
        self.url = url
        self.timeout = timeout
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def read(self) -> tuple[dict[str, Any], dict[str, Any]]:
        session = await self._connect()
        try:
            audit = await _read_json(session, "resource://audit-log")
            pending = await _read_json(session, "resource://pending-approvals")
            return audit, pending
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        self._session = None
        stack = self._stack
        self._stack = None
        if stack is not None:
            await stack.aclose()

    async def _connect(self) -> Any:
        if self._session is not None:
            return self._session
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        stack = AsyncExitStack()
        try:
            http = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout))
            await stack.enter_async_context(http)
            read, write, _get_session_id = await stack.enter_async_context(
                streamable_http_client(self.url, http_client=http)
            )
            session = await stack.enter_async_context(
                ClientSession(read, write, read_timeout_seconds=timedelta(seconds=self.timeout))
            )
            await session.initialize()
        except Exception as exc:
            await stack.aclose()
            raise McpUnavailable("MCP server is unreachable.") from exc
        self._stack = stack
        self._session = session
        return session


async def _read_json(session: Any, uri: str) -> dict[str, Any]:
    try:
        result = await session.read_resource(uri)
    except Exception as exc:
        raise McpUnavailable("MCP server is unreachable.") from exc
    contents = getattr(result, "contents", None) or []
    if not contents:
        raise McpUnavailable("MCP resource was empty.")
    text = getattr(contents[0], "text", None)
    if not isinstance(text, str):
        raise McpUnavailable("MCP resource was not JSON text.")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise McpUnavailable("MCP resource was not JSON text.") from exc
    if not isinstance(payload, dict):
        raise McpUnavailable("MCP resource was not a JSON object.")
    if payload.get("error"):
        raise McpUnavailable("MCP resource failed.")
    return payload


class IncidentFeed:
    """Polls MCP, updates the store, and fans out stream events."""

    def __init__(self, source: ResourceSource, store: IncidentStore, refresh_seconds: float) -> None:
        self.source = source
        self.store = store
        self.refresh_seconds = refresh_seconds
        self.mcp_ok: bool | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self._sub_lock = threading.Lock()
        self._emitted: set[tuple[str, str]] = set()

    async def run(self) -> None:
        failure_streak = 0
        while not self._stop.is_set():
            delay = self.refresh_seconds
            try:
                audit, pending = await self.source.read()
                changed = self.store.apply(audit, pending)
                recovered = self.mcp_ok is not True
                self.mcp_ok = True
                failure_streak = 0
                if recovered:
                    snapshot = self.store.snapshot()
                    self._remember(snapshot["incidents"])
                    self._broadcast({"event": "snapshot", "data": snapshot})
                else:
                    for incident in self._novel(changed):
                        self._broadcast({"event": "upsert", "data": incident.model_dump()})
            except Exception:
                log.warning("MCP refresh failed.", extra={"error_type": "mcp_unavailable"})
                self.mcp_ok = False
                failure_streak += 1
                self._broadcast({"event": "mcp_status", "data": dict(MCP_UNAVAILABLE)})
                delay = min(8.0, self.refresh_seconds * (2 ** (failure_streak - 1)))
            finally:
                self._ready.set()
            self._broadcast({"event": "ping", "data": {}})
            if self._stop.is_set():
                break
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                continue
            else:
                break

    async def ensure_attempted(self, timeout: float) -> None:
        if self._ready.is_set():
            return
        try:
            await asyncio.wait_for(self._ready.wait(), timeout)
        except asyncio.TimeoutError:
            return

    def stop(self) -> None:
        self._stop.set()

    def subscribe(self) -> tuple[asyncio.Queue[dict[str, Any]], list[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        with self._sub_lock:
            self._subscribers.append(queue)
        return queue, [self._connection_event()]

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._sub_lock:
            if queue in self._subscribers:
                self._subscribers.remove(queue)

    def _connection_event(self) -> dict[str, Any]:
        if self.mcp_ok is True:
            return {"event": "snapshot", "data": self.store.snapshot()}
        return {"event": "mcp_status", "data": dict(MCP_UNAVAILABLE)}

    def _remember(self, incidents: list[dict[str, Any]]) -> None:
        """Record id and status pairs already handed to subscribers."""
        for item in incidents:
            incident_id = item.get("id")
            status = item.get("status")
            if isinstance(incident_id, str) and isinstance(status, str):
                self._emitted.add((incident_id, status))

    def _novel(self, incidents: list[Incident]) -> list[Incident]:
        """Return incidents whose id and status have not been emitted yet."""
        fresh: list[Incident] = []
        for incident in incidents:
            key = (incident.id, incident.status)
            if key in self._emitted:
                continue
            self._emitted.add(key)
            fresh.append(incident)
        return fresh

    def _broadcast(self, event: dict[str, Any]) -> None:
        with self._sub_lock:
            stale: list[asyncio.Queue[dict[str, Any]]] = []
            for queue in self._subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    stale.append(queue)
            for queue in stale:
                self._subscribers.remove(queue)


def _sse(event: dict[str, Any]) -> str:
    if event["event"] == "ping":
        return ": ping\n\n"
    payload = json.dumps(event["data"], separators=(",", ":"))
    return f"event: {event['event']}\ndata: {payload}\n\n"


def _cors_origins(value: str) -> list[str]:
    origins = [part.strip() for part in value.split(",") if part.strip()]
    return origins or ["*"]


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = float(raw)
    except ValueError:
        return default
    if parsed <= 0:
        return default
    return parsed


def create_app(
    *,
    source: ResourceSource | None = None,
    incidents_path: str | Path | None = None,
    refresh_seconds: float | None = None,
    cors_origins: str | None = None,
    first_poll_timeout: float = 2.5,
    mcp_url: str | None = None,
) -> FastAPI:
    """Build the dashboard app. Tests pass a fake ``source`` and a temp JSONL path."""
    path = Path(
        incidents_path
        if incidents_path is not None
        else os.environ.get("SIEVE_INCIDENTS_PATH", "sieve_incidents.jsonl")
    )
    interval = (
        refresh_seconds
        if refresh_seconds is not None
        else _env_float("SIEVE_DASHBOARD_REFRESH_SECONDS", 1.0)
    )
    origins = cors_origins if cors_origins is not None else os.environ.get(
        "SIEVE_DASHBOARD_CORS_ORIGINS", "*"
    )
    client = source if source is not None else HttpMcpResourceClient(
        mcp_url or os.environ.get("SIEVE_MCP_URL", "http://127.0.0.1:8081/mcp")
    )
    store = IncidentStore(path)
    feed = IncidentFeed(client, store, interval)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(feed.run())
        await feed.ensure_attempted(first_poll_timeout)
        try:
            yield
        finally:
            feed.stop()
            done, _pending = await asyncio.wait({task}, timeout=1.0)
            if not done:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await client.close()

    app = FastAPI(
        title="Sieve Incident Dashboard",
        version="0.1.0",
        description="Live incident feed for quarantine blocks and approval decisions.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(origins),
        allow_methods=["GET"],
        allow_headers=["*"],
    )
    app.state.feed = feed
    app.state.store = store
    app.state.first_poll_timeout = first_poll_timeout

    @app.get("/incidents", response_model=None)
    async def list_incidents(
        request: Request,
        status: str | None = None,
        type: str | None = Query(default=None),
        source: str | None = None,
        since: str | None = None,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> JSONResponse:
        cutoff, error = _since(since)
        if error is not None:
            return error
        incidents, total = request.app.state.store.query(
            status=status,
            incident_type=type,
            source=source,
            since=cutoff,
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            {
                "incidents": [item.model_dump() for item in incidents],
                "total": total,
            }
        )

    @app.get("/incidents/stream", response_model=None)
    async def stream_incidents(
        request: Request,
        max_seconds: float | None = Query(default=None, gt=0, le=30),
    ) -> StreamingResponse:
        """Push a snapshot, then upserts. ``max_seconds`` closes the stream for tests."""
        await request.app.state.feed.ensure_attempted(request.app.state.first_poll_timeout)
        queue, initial = request.app.state.feed.subscribe()
        deadline = None if max_seconds is None else time.monotonic() + max_seconds

        async def events() -> AsyncIterator[str]:
            try:
                for event in initial:
                    yield _sse(event)
                while True:
                    timeout = None if deadline is None else deadline - time.monotonic()
                    if timeout is not None and timeout <= 0:
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=timeout)
                    except asyncio.TimeoutError:
                        break
                    yield _sse(event)
            finally:
                request.app.state.feed.unsubscribe(queue)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/incidents/summary", response_model=None)
    async def summarize_incidents(request: Request) -> JSONResponse:
        blocked = await _unavailable(request)
        if blocked is not None:
            return blocked
        return JSONResponse(request.app.state.store.summary())

    @app.get("/incidents/{incident_id}", response_model=None)
    async def get_incident(incident_id: str, request: Request) -> JSONResponse:
        incident = request.app.state.store.get(incident_id)
        if incident is None:
            return JSONResponse(status_code=404, content=_NOT_FOUND)
        return JSONResponse(incident.model_dump())

    return app


async def _unavailable(request: Request) -> JSONResponse | None:
    feed: IncidentFeed = request.app.state.feed
    await feed.ensure_attempted(request.app.state.first_poll_timeout)
    if feed.mcp_ok is True:
        return None
    return JSONResponse(status_code=503, content=MCP_UNAVAILABLE)


def _since(value: str | None) -> tuple[datetime | None, JSONResponse | None]:
    if value is None or not value.strip():
        return None, None
    parsed = _parse_time(value)
    if parsed is None:
        return None, JSONResponse(status_code=400, content=_BAD_SINCE)
    return parsed, None


app = create_app()
