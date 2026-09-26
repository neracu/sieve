"""Approval gate for privileged actions triggered by untrusted content.

Quarantine blocks content that detectors score as malicious. This gate is the
next layer: a file write, git push, outbound message, or other side effect
pauses when it was triggered by content that passed through a guard hook,
even when that content was allowed through.

Add a privileged action by appending one :data:`PRIVILEGED_ACTIONS` entry.
Wrap an action with :meth:`ApprovalGate.protect` or call
:meth:`ApprovalGate.intercept`. In API mode the call returns a pending
payload and the action runs only after :meth:`ApprovalGate.approve`.
A reject, an unknown id, or a timeout does not run it.

Raw untrusted text is never copied into the confirmation payload or the
audit log.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, FastAPI, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from sieve.core.config import settings
from sieve.core.logger import get_logger

log = get_logger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SHORT_TOKEN_RE = re.compile(r"^[a-z0-9_]{1,32}$")
_VALID_TIERS = frozenset({"low", "medium", "high"})
_SOURCE_ALIASES = {
    "github_issue": "github_issue",
    "github_pr": "github_pr",
    "web_fetch": "web_fetch",
    "readme": "readme",
    "user": "user",
}
_PENDING_KEYS = (
    "status",
    "action",
    "risk_tier",
    "origin",
    "source",
    "context_summary",
    "approval_id",
)

_current_provenance: ContextVar[Provenance | None] = ContextVar(
    "sieve_action_provenance",
    default=None,
)


class Origin(str, Enum):
    """Whether the action was requested by a person or by untrusted content."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class ApprovalNotFoundError(Exception):
    """Raised when approve/reject is called with an unknown approval id."""

    def __init__(self, approval_id: str) -> None:
        self.approval_id = approval_id
        super().__init__(
            f"Unknown approval_id: {approval_id}. No action was executed."
        )


@dataclass(frozen=True)
class ActionSpec:
    """One registry entry. ``unknown`` actions are fail-safe high risk."""

    action_id: str
    risk_tier: str
    description: str
    privileged: bool = True
    unknown: bool = False


@dataclass(frozen=True)
class Provenance:
    """Origin metadata carried with an action. Raw content is not stored."""

    origin: Origin
    source: str | None = None
    content_id: str | None = None
    content_length: int = 0

    def __post_init__(self) -> None:
        source = normalize_source(self.source) if self.source else None
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "content_id", _safe_content_id(self.content_id))
        length = self.content_length
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            object.__setattr__(self, "content_length", 0)


class _Pending:
    """In-memory paused action. ``raw_content`` is kept only so it can be scrubbed."""

    def __init__(
        self,
        *,
        spec: ActionSpec,
        provenance: Provenance,
        fn: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        raw_content: str | None,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        self.approval_id = str(uuid4())
        self.spec = spec
        self.provenance = provenance
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.raw_content = raw_content
        self.created_at = created_at
        self.expires_at = expires_at
        self.status = "pending_approval"
        self.approver: str | None = None
        self.result: Any = None
        self.error: BaseException | None = None
        self.executed = False
        self.context_summary = _context_summary(spec, provenance)

    def __repr__(self) -> str:
        return (
            f"_Pending(approval_id={self.approval_id!r}, status={self.status!r}, "
            f"action={self.spec.action_id!r})"
        )

    def public(self) -> dict[str, Any]:
        secret = self.raw_content
        payload: dict[str, Any] = {
            "status": self.status,
            "action": _scrub(self.spec.action_id, secret),
            "risk_tier": self.spec.risk_tier,
            "origin": self.provenance.origin.value,
            "source": _scrub(self.provenance.source or "untrusted", secret),
            "context_summary": _scrub(self.context_summary, secret),
            "approval_id": self.approval_id,
        }
        if self.status == "approved":
            payload["result"] = self.result
        return payload


# ── Registry ──────────────────────────────────────────────────────────────────
# Adding a privileged action is one entry here. Core pause/approve logic
# reads this mapping and does not need an edit.


def register_privileged_action(action_id: str, risk_tier: str, description: str) -> ActionSpec:
    """Register a side-effecting action that can require human approval."""
    tier = risk_tier.strip().lower()
    if tier not in _VALID_TIERS:
        raise ValueError(f"risk_tier must be one of {sorted(_VALID_TIERS)}")
    action = action_id.strip()
    summary = description.strip()
    if not action or not summary:
        raise ValueError("action_id and description are required")
    spec = ActionSpec(action_id=action, risk_tier=tier, description=summary, privileged=True)
    PRIVILEGED_ACTIONS[action] = spec
    NON_PRIVILEGED_ACTIONS.pop(action, None)
    return spec


PRIVILEGED_ACTIONS: dict[str, ActionSpec] = {}
NON_PRIVILEGED_ACTIONS: dict[str, str] = {
    "read_file": "Read a file",
    "list_directory": "List directory contents",
}

register_privileged_action("file_write", "medium", "Write or overwrite a file")
register_privileged_action("file_delete", "high", "Delete a file or directory")
register_privileged_action("git_commit", "medium", "Create a git commit")
register_privileged_action("git_push", "high", "Push commits to a remote, including main")
register_privileged_action(
    "send_message",
    "medium",
    "Send a message or notification (Slack, email, or similar)",
)
register_privileged_action(
    "external_api_call",
    "medium",
    "Call an external API that has side effects",
)
register_privileged_action("cicd_config_change", "high", "Modify CI/CD configuration")
register_privileged_action(
    "credential_access",
    "high",
    "Read or use a credential or secret",
)


def normalize_source(source: str | None) -> str | None:
    """Map hook enums onto short source tokens. Free text becomes ``untrusted``."""
    if source is None:
        return None
    key = str(source).strip().lower().replace("-", "_")
    if key in _SOURCE_ALIASES:
        return _SOURCE_ALIASES[key]
    if _SHORT_TOKEN_RE.fullmatch(key):
        return key
    return "untrusted"


def format_prompt(payload: dict[str, Any]) -> str:
    """Human confirmation text. Uses the scrubbed summary only."""
    return (
        "Sieve approval required\n"
        f"  approval_id: {payload['approval_id']}\n"
        f"  action: {payload['action']} (risk: {payload['risk_tier']})\n"
        f"  origin: {payload['origin']}\n"
        f"  source: {payload['source']}\n"
        f"  summary: {payload['context_summary']}\n"
        "Allow this privileged action? [y/N]: "
    )


@contextmanager
def untrusted_origin(
    source: str,
    *,
    content_id: str | None = None,
    content_length: int = 0,
) -> Iterator[Provenance]:
    """Mark the current context as triggered by a guard-hook passage."""
    provenance = Provenance(
        origin=Origin.UNTRUSTED,
        source=source,
        content_id=content_id,
        content_length=content_length,
    )
    token = _current_provenance.set(provenance)
    try:
        yield provenance
    finally:
        _current_provenance.reset(token)


class ApprovalGate:
    """Pause privileged actions that originate from guard-hook content.

    Args:
        timeout_seconds: Idle pending actions become ``timed_out`` and do not run.
        pause_on_trusted: When False, a direct user instruction proceeds.
        tiers_requiring_approval: Untrusted actions in these tiers pause.
        input_fn: Replaces stdin in sync mode. Return ``None`` to time out.
        clock: Injectable clock for tests. Returns an aware datetime.
        audit_path: Optional JSONL file. Empty keeps the log in memory only.
        enabled: When False, actions proceed. Defaults to settings.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float | None = None,
        pause_on_trusted: bool | None = None,
        tiers_requiring_approval: set[str] | frozenset[str] | None = None,
        input_fn: Callable[[], str | None] | None = None,
        clock: Callable[[], datetime] | None = None,
        audit_path: str | None = None,
        enabled: bool | None = None,
    ) -> None:
        self.timeout_seconds = (
            float(settings.approval_timeout_seconds)
            if timeout_seconds is None
            else float(timeout_seconds)
        )
        self.pause_on_trusted = (
            bool(settings.approval_pause_on_trusted)
            if pause_on_trusted is None
            else bool(pause_on_trusted)
        )
        if tiers_requiring_approval is None:
            tiers_requiring_approval = {
                part.strip().lower()
                for part in str(settings.approval_tiers).split(",")
                if part.strip()
            }
        self._tiers = frozenset(tiers_requiring_approval)
        self._input_fn = input_fn
        self._clock = clock or (lambda: datetime.now(tz=timezone.utc))
        self._audit_path = audit_path or ""
        self.enabled = bool(settings.approval_gate_enabled) if enabled is None else bool(enabled)
        self._passage: Provenance | None = None
        self._store: dict[str, _Pending] = {}
        self._audit: list[dict[str, Any]] = []
        self._logged: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    # ── Registry lookup ───────────────────────────────────────────────────────

    def resolve(self, action_id: str) -> ActionSpec:
        """Return the spec for *action_id*. Unknown ids are high-risk privileged."""
        if action_id in PRIVILEGED_ACTIONS:
            return PRIVILEGED_ACTIONS[action_id]
        if action_id in NON_PRIVILEGED_ACTIONS:
            return ActionSpec(
                action_id=action_id,
                risk_tier="low",
                description=NON_PRIVILEGED_ACTIONS[action_id],
                privileged=False,
            )
        label = action_id.strip() if isinstance(action_id, str) and action_id.strip() else "unknown"
        return ActionSpec(
            action_id=label,
            risk_tier="high",
            description="Unknown action treated as high-risk until it is registered.",
            privileged=True,
            unknown=True,
        )

    def note_guard_passage(
        self,
        *,
        source: str,
        content_id: str | None = None,
        content_length: int = 0,
    ) -> Provenance:
        """Remember that untrusted content passed through a guard hook.

        Later :meth:`intercept` calls on this gate pause privileged actions
        until :meth:`clear_guard_passage` or an explicit trusted provenance.
        """
        passage = Provenance(
            origin=Origin.UNTRUSTED,
            source=source,
            content_id=str(content_id) if content_id else None,
            content_length=content_length,
        )
        self._passage = passage
        return passage

    def clear_guard_passage(self) -> None:
        """Drop the remembered guard-hook passage on this gate."""
        self._passage = None

    @property
    def guard_passage(self) -> Provenance | None:
        return self._passage

    # ── Execution ─────────────────────────────────────────────────────────────

    def intercept(
        self,
        action_id: str,
        fn: Callable[..., Any],
        *args: Any,
        provenance: Provenance | None = None,
        mode: str = "async",
        raw_content: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Run *fn* or pause it.

        Async mode returns the pending confirmation dict and does not call
        *fn*. Sync mode prints a prompt and waits for y/n (or *input_fn*).
        Trusted and non-privileged actions return *fn*'s result directly.
        """
        spec = self.resolve(action_id)
        origin = self._resolve_provenance(provenance)
        if not self._needs_pause(spec, origin.origin):
            value = fn(*args, **kwargs)
            self._audit_decision(
                action=spec.action_id,
                origin=origin.origin.value,
                outcome="allowed",
                approver=None,
                risk_tier=spec.risk_tier,
                source=origin.source,
                approval_id=None,
                raw_content=raw_content,
            )
            return value

        created = self._clock()
        seconds = self.timeout_seconds if self.timeout_seconds > 0 else 0.0
        record = _Pending(
            spec=spec,
            provenance=origin,
            fn=fn,
            args=args,
            kwargs=kwargs,
            raw_content=raw_content if isinstance(raw_content, str) else None,
            created_at=created,
            expires_at=created + timedelta(seconds=seconds),
        )
        with self._lock:
            self._store[record.approval_id] = record
            self._audit_locked(record, "paused", None)
        log.info(
            "Approval gate decision.",
            extra={
                "action": spec.action_id,
                "origin": origin.origin.value,
                "outcome": "paused",
                "approval_id": record.approval_id,
            },
        )
        if mode == "sync":
            return self._sync_wait(record)
        return record.public()

    def protect(self, action_id: str, *, mode: str = "async") -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator that wraps an action-executing function with this gate."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                provenance = kwargs.pop("provenance", None)
                raw_content = kwargs.pop("raw_content", None)
                call_mode = kwargs.pop("approval_mode", mode)
                return self.intercept(
                    action_id,
                    lambda: fn(*args, **kwargs),
                    provenance=provenance,
                    mode=call_mode,
                    raw_content=raw_content,
                )

            wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
            wrapper.__name__ = getattr(fn, "__name__", "guarded_action")
            wrapper.__doc__ = fn.__doc__
            wrapper.__sieve_action_id__ = action_id  # type: ignore[attr-defined]
            return wrapper

        return decorator

    # Alias: FastAPI routes and plain call sites use the same wrapper.
    dependency = protect

    def approve(self, approval_id: str | UUID, approver: str = "operator") -> dict[str, Any]:
        """Run a paused action once. A second call returns the same result."""
        return self._resolve(approval_id, "approved", approver)

    def reject(self, approval_id: str | UUID, approver: str = "operator") -> dict[str, Any]:
        """Cancel a paused action. The wrapped function is not called."""
        return self._resolve(approval_id, "rejected", approver)

    def deny(self, approval_id: str | UUID, approver: str = "operator") -> dict[str, Any]:
        """Alias of :meth:`reject`."""
        return self.reject(approval_id, approver=approver)

    def sweep_timeouts(self) -> list[dict[str, Any]]:
        """Mark elapsed pending actions as ``timed_out`` without running them."""
        expired: list[dict[str, Any]] = []
        with self._lock:
            now = self._clock()
            for record in self._store.values():
                if record.status == "pending_approval" and now >= record.expires_at:
                    record.status = "timed_out"
                    record.approver = None
                    self._audit_locked(record, "timed_out", None)
                    expired.append(record.public())
        return expired

    def list_pending(self) -> list[dict[str, Any]]:
        """Return confirmation payloads still waiting for a person."""
        self.sweep_timeouts()
        with self._lock:
            return [
                record.public()
                for record in self._store.values()
                if record.status == "pending_approval"
            ]

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Copy of gate decisions. One entry per decision, with no raw content."""
        with self._lock:
            return [dict(entry) for entry in self._audit]

    def format_prompt(self, payload: dict[str, Any]) -> str:
        return format_prompt(payload)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _needs_pause(self, spec: ActionSpec, origin: Origin) -> bool:
        if not self.enabled or not spec.privileged:
            return False
        if origin == Origin.TRUSTED and not self.pause_on_trusted:
            return False
        if spec.unknown:
            return True
        return spec.risk_tier in self._tiers

    def _resolve_provenance(self, provenance: Provenance | None) -> Provenance:
        if provenance is not None:
            if not isinstance(provenance, Provenance):
                raise TypeError("provenance must be a Provenance instance")
            return provenance
        current = _current_provenance.get()
        if current is not None:
            return current
        if self._passage is not None:
            return self._passage
        return Provenance(origin=Origin.TRUSTED, source="user")

    def _sync_wait(self, record: _Pending) -> dict[str, Any]:
        print(format_prompt(record.public()), end="", flush=True)
        if self._expired(record):
            return self._mark_timed_out(record)
        answer = self._read_answer(record)
        if answer is None:
            return self._mark_timed_out(record)
        if answer.strip().lower() in {"y", "yes"}:
            return self.approve(record.approval_id, approver="stdin")
        return self.reject(record.approval_id, approver="stdin")

    def _read_answer(self, record: _Pending) -> str | None:
        if self._input_fn is not None:
            try:
                answer = self._input_fn()
            except Exception:
                log.warning("Approval prompt input failed; denying the action.")
                return ""
            if answer is None:
                return None
            return str(answer)

        remaining = (record.expires_at - self._clock()).total_seconds()
        if remaining <= 0:
            return None
        box: dict[str, str] = {}

        def _read() -> None:
            try:
                box["line"] = sys.stdin.readline()
            except Exception:
                box["line"] = ""

        thread = threading.Thread(target=_read, name="sieve-approval-stdin", daemon=True)
        thread.start()
        thread.join(timeout=remaining)
        if thread.is_alive():
            return None
        return box.get("line", "")

    def _expired(self, record: _Pending) -> bool:
        return self._clock() >= record.expires_at

    def _mark_timed_out(self, record: _Pending) -> dict[str, Any]:
        with self._lock:
            if record.status == "pending_approval":
                record.status = "timed_out"
                record.approver = None
                self._audit_locked(record, "timed_out", None)
            payload = record.public()
        return payload

    def _resolve(self, approval_id: str | UUID, new_status: str, approver: str) -> dict[str, Any]:
        key = str(approval_id)
        reraise = False
        changed = False
        with self._lock:
            record = self._store.get(key)
            if record is None:
                raise ApprovalNotFoundError(key)
            if record.status != "pending_approval":
                reraise = record.error is not None and record.status == "approved"
                run = False
            elif self._expired(record):
                record.status = "timed_out"
                record.approver = None
                self._audit_locked(record, "timed_out", None)
                changed = True
                run = False
            else:
                record.status = new_status
                record.approver = approver
                self._audit_locked(record, new_status, approver)
                changed = True
                run = new_status == "approved"
        if changed:
            log.info(
                "Approval gate decision.",
                extra={
                    "action": record.spec.action_id,
                    "origin": record.provenance.origin.value,
                    "outcome": record.status,
                    "approval_id": record.approval_id,
                    "approver": record.approver,
                },
            )
        if run:
            self._execute(record)
        if record.error is not None and (run or reraise):
            raise record.error
        return record.public()

    def _execute(self, record: _Pending) -> None:
        try:
            record.result = record.fn(*record.args, **record.kwargs)
        except Exception as exc:
            record.error = exc
            record.result = None
            log.warning(
                "Approved action raised.",
                extra={"approval_id": record.approval_id, "action": record.spec.action_id},
            )
        finally:
            record.executed = True

    def _audit_decision(
        self,
        *,
        action: str,
        origin: str,
        outcome: str,
        approver: str | None,
        risk_tier: str,
        source: str | None,
        approval_id: str | None,
        raw_content: str | None,
    ) -> None:
        entry = {
            "timestamp": self._clock().isoformat(),
            "action": action,
            "origin": origin,
            "outcome": outcome,
            "approver": approver,
            "risk_tier": risk_tier,
            "source": source,
            "approval_id": approval_id,
        }
        entry = {key: _scrub(value, raw_content) if isinstance(value, str) else value for key, value in entry.items()}
        with self._lock:
            if approval_id is not None:
                dedupe = (approval_id, outcome)
                if dedupe in self._logged:
                    return
                self._logged.add(dedupe)
            self._audit.append(entry)
            self._write_audit_file(entry)
        log.info(
            "Approval gate decision.",
            extra={
                "action": action,
                "origin": origin,
                "outcome": outcome,
                "approval_id": approval_id,
                "approver": approver,
            },
        )

    def _audit_locked(self, record: _Pending, outcome: str, approver: str | None) -> None:
        """Append one audit entry. Caller holds ``self._lock``."""
        dedupe = (record.approval_id, outcome)
        if dedupe in self._logged:
            return
        self._logged.add(dedupe)
        entry = {
            "timestamp": self._clock().isoformat(),
            "action": record.spec.action_id,
            "origin": record.provenance.origin.value,
            "outcome": outcome,
            "approver": approver,
            "risk_tier": record.spec.risk_tier,
            "source": record.provenance.source,
            "approval_id": record.approval_id,
        }
        secret = record.raw_content
        entry = {key: _scrub(value, secret) if isinstance(value, str) else value for key, value in entry.items()}
        self._audit.append(entry)
        self._write_audit_file(entry)

    def _write_audit_file(self, entry: dict[str, Any]) -> None:
        if not self._audit_path:
            return
        try:
            with open(self._audit_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
        except OSError as exc:
            log.warning("Approval audit file write failed.", extra={"error": str(exc)})


approval_gate = ApprovalGate()


def observe_guard_hook(scan: Any, source: str, gate: ApprovalGate | None = None) -> None:
    """Record a guard-hook passage without copying the raw text."""
    target = gate if gate is not None else approval_gate
    content = getattr(scan, "content", None)
    content_id = getattr(content, "id", None)
    body = getattr(scan, "body", None)
    target.note_guard_passage(
        source=source,
        content_id=str(content_id) if content_id else None,
        content_length=len(body) if isinstance(body, str) else 0,
    )


class SieveProvenanceMiddleware(BaseHTTPMiddleware):
    """Bind ``X-Sieve-Origin`` and ``X-Sieve-Source`` for the current request."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        origin_header = request.headers.get("x-sieve-origin")
        source_header = request.headers.get("x-sieve-source")
        if origin_header is None and source_header is None:
            return await call_next(request)
        try:
            origin = Origin(origin_header.strip().lower()) if origin_header else Origin.TRUSTED
        except ValueError:
            origin = Origin.UNTRUSTED
        provenance = Provenance(
            origin=origin,
            source=source_header or ("user" if origin == Origin.TRUSTED else None),
        )
        token = _current_provenance.set(provenance)
        try:
            return await call_next(request)
        finally:
            _current_provenance.reset(token)


def build_router(gate: ApprovalGate | None = None) -> APIRouter:
    """Approve and reject endpoints for async / API mode."""
    active = gate if gate is not None else approval_gate
    router = APIRouter(prefix="/api/gate", tags=["approval-gate"])

    @router.get("/approvals")
    def list_approvals() -> list[dict[str, Any]]:
        return active.list_pending()

    @router.post("/approvals/{approval_id}/approve")
    def approve_action(approval_id: str, approver: str = "operator") -> dict[str, Any]:
        try:
            return active.approve(approval_id, approver=approver)
        except ApprovalNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/approvals/{approval_id}/reject")
    def reject_action(approval_id: str, approver: str = "operator") -> dict[str, Any]:
        try:
            return active.reject(approval_id, approver=approver)
        except ApprovalNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return router


def install_approval_gate(app: FastAPI, gate: ApprovalGate | None = None) -> ApprovalGate:
    """Mount the approval routes and the provenance header middleware."""
    active = gate if gate is not None else approval_gate
    app.include_router(build_router(active))
    app.add_middleware(SieveProvenanceMiddleware)
    return active


def _safe_content_id(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if _UUID_RE.fullmatch(text):
        return text
    return None


def _context_summary(spec: ActionSpec, provenance: Provenance) -> str:
    source = provenance.source or "untrusted"
    ref = provenance.content_id or "n/a"
    return (
        f"{spec.description}. "
        f"Source {source}, ref {ref}, "
        f"size {provenance.content_length} characters. "
        "Raw content is withheld."
    )


def _scrub(value: str, secret: str | None) -> str:
    if not secret or secret not in value:
        return value
    return value.replace(secret, "[withheld]")


# Re-export shape for callers that want the pending keys without importing privates.
PENDING_RESPONSE_KEYS = _PENDING_KEYS
