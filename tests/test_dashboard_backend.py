"""Incident dashboard: normalization, HTTP, JSONL, SSE, and MCP failure."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from sieve.dashboard.dashboard_backend import (
    IncidentStore,
    McpUnavailable,
    create_app,
    normalize_audit_entry,
    normalize_pending_entry,
)

_SECRET = "INJECT-SECRET-PAYLOAD-XYZ"
_BLOCK = "11111111-1111-4111-8111-111111111111"
_BLOCK_B = "33333333-3333-4333-8333-333333333333"
_APPROVAL = "22222222-2222-4222-8222-222222222222"
_APPROVED = "44444444-4444-4444-8444-444444444444"
_REJECTED = "55555555-5555-4555-8555-555555555555"
_T0 = "2026-09-26T00:00:00+00:00"
_T1 = "2026-09-26T00:00:10+00:00"
_T2 = "2026-09-26T00:00:20+00:00"
_T3 = "2026-09-26T00:00:30+00:00"
_T4 = "2026-09-26T00:00:40+00:00"


class FakeSource:
    """Stand-in for the MCP resource client."""

    def __init__(
        self,
        audit: dict | None = None,
        pending: dict | None = None,
        *,
        fail: bool = False,
    ) -> None:
        self.audit = audit if audit is not None else {"entries": []}
        self.pending = pending if pending is not None else {"approvals": []}
        self.fail = fail
        self.lock = threading.Lock()

    async def read(self) -> tuple[dict, dict]:
        if self.fail:
            raise McpUnavailable("down")
        with self.lock:
            return json.loads(json.dumps(self.audit)), json.loads(json.dumps(self.pending))

    async def close(self) -> None:
        return None


def _block(
    content_id: str = _BLOCK,
    *,
    source: str = "GITHUB_ISSUE",
    detector: str = "L1",
    score: float = 0.91,
    timestamp: str = _T2,
    reason: str = "malicious",
    event: str = "BLOCKED",
    action_taken: str | None = None,
) -> dict:
    row = {
        "kind": "quarantine",
        "timestamp": timestamp,
        "source": source,
        "decision": event,
        "detector": detector,
        "outcome": event,
        "content_id": content_id,
        "risk_score": score,
        "reason": reason,
        "explanation": _SECRET,
        "raw_text": _SECRET,
        "content": _SECRET,
    }
    if action_taken is not None:
        row["action_taken"] = action_taken
    return row


def _pending(
    approval_id: str = _APPROVAL,
    *,
    timestamp: str = _T1,
    summary: str = "Issue asks to publish the branch.",
    source: str = "untrusted",
) -> dict:
    return {
        "approval_id": approval_id,
        "action": "git_push",
        "risk_tier": "high",
        "context_summary": summary,
        "requested_at": timestamp,
        "status": "pending",
        "origin": "untrusted",
        "source": source,
        "raw_text": _SECRET,
        "content": _SECRET,
    }


def _approval(
    approval_id: str,
    outcome: str,
    *,
    timestamp: str,
    action: str = "git_push",
    summary: str = "Issue asks to publish the branch.",
    source: str = "github_issue",
) -> dict:
    return {
        "kind": "approval",
        "timestamp": timestamp,
        "source": source,
        "decision": action,
        "action": action,
        "outcome": outcome,
        "approval_id": approval_id,
        "risk_tier": "high",
        "context_summary": summary,
        "explanation": _SECRET,
        "raw_text": _SECRET,
    }


def _app(tmp_path: Path, source: FakeSource, refresh: float = 0.05):
    application = create_app(
        source=source,
        incidents_path=tmp_path / "incidents.jsonl",
        refresh_seconds=refresh,
        cors_origins="*",
        first_poll_timeout=1.0,
    )
    return application


def _feed() -> tuple[dict, dict]:
    audit = {
        "entries": [
            _block(_BLOCK, source="GITHUB_ISSUE", detector="L1", score=0.91, timestamp=_T2),
            _block(
                _BLOCK_B,
                source="WEB_FETCH",
                detector="L2",
                score=0.4,
                timestamp=_T0,
                reason="approval_required",
                event="QUARANTINED",
                action_taken="PENDING_APPROVAL",
            ),
            _approval(_APPROVED, "approved", timestamp=_T3, action="file_write", summary="Write the patch."),
            _approval(_REJECTED, "rejected", timestamp=_T4, action="file_delete", summary="Remove the file."),
            _approval(_APPROVAL, "allowed", timestamp=_T4, action="read_file", summary="should be skipped"),
        ]
    }
    pending = {"approvals": [_pending()]}
    return audit, pending


def test_block_event_normalizes_to_quarantine_block():
    incident = normalize_audit_entry(_block())
    assert incident is not None
    assert incident.id == _BLOCK
    assert incident.type == "quarantine_block"
    assert incident.status == "blocked"
    assert incident.source == "github_issue"
    assert incident.detector == "L1"
    assert incident.risk_score == 0.91
    assert incident.action is None
    assert incident.risk_tier is None
    assert incident.context_summary == "malicious"
    assert _SECRET not in incident.model_dump_json()


def test_pending_entry_normalizes_to_approval_pending():
    incident = normalize_pending_entry(_pending())
    assert incident is not None
    assert incident.id == _APPROVAL
    assert incident.type == "approval_pending"
    assert incident.status == "pending"
    assert incident.source == "untrusted"
    assert incident.action == "git_push"
    assert incident.risk_tier == "high"
    assert incident.detector is None
    assert incident.context_summary == "Issue asks to publish the branch."
    assert _SECRET not in incident.model_dump_json()


def test_approval_transition_updates_the_same_incident(tmp_path: Path):
    store = IncidentStore(tmp_path / "incidents.jsonl")
    store.apply({"entries": []}, {"approvals": [_pending()]})
    assert store.get(_APPROVAL) is not None
    assert store.get(_APPROVAL).status == "pending"  # type: ignore[union-attr]
    store.apply(
        {"entries": [_approval(_APPROVAL, "approved", timestamp=_T3)]},
        {"approvals": []},
    )
    restored = IncidentStore(tmp_path / "incidents.jsonl")
    assert list(restored._items) == [_APPROVAL]
    current = restored.get(_APPROVAL)
    assert current is not None
    assert current.status == "approved"
    assert current.type == "approval_approved"
    assert current.context_summary == "Issue asks to publish the branch."
    lines = (tmp_path / "incidents.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[-1])["status"] == "approved"


def test_allowed_audit_row_is_not_an_incident(tmp_path: Path):
    store = IncidentStore(tmp_path / "incidents.jsonl")
    changed = store.apply(
        {"entries": [_approval(_APPROVAL, "allowed", timestamp=_T1)]},
        {"approvals": []},
    )
    assert changed == []
    assert store.get(_APPROVAL) is None


def test_list_filters_pagination_and_sort(tmp_path: Path):
    source = FakeSource(*_feed())
    with TestClient(_app(tmp_path, source)) as client:
        listed = client.get("/incidents", headers={"Origin": "http://localhost:5173"})
        assert listed.status_code == 200
        assert listed.headers["access-control-allow-origin"] == "*"
        body = listed.json()
        assert body["total"] == 5
        stamps = [item["timestamp"] for item in body["incidents"]]
        assert stamps == sorted(stamps, reverse=True)
        ids = [item["id"] for item in body["incidents"]]
        assert ids[0] == _REJECTED
        assert _SECRET not in listed.text

        blocked = client.get("/incidents", params={"status": "blocked"}).json()
        assert blocked["total"] == 1
        assert blocked["incidents"][0]["id"] == _BLOCK
        assert {item["status"] for item in blocked["incidents"]} == {"blocked"}

        waiting = client.get("/incidents", params={"status": "pending_approval"}).json()
        assert waiting["total"] == 1
        assert waiting["incidents"][0]["id"] == _BLOCK_B
        assert waiting["incidents"][0]["status"] == "pending_approval"

        pending = client.get("/incidents", params={"type": "approval_pending"}).json()
        assert pending["total"] == 1
        assert pending["incidents"][0]["id"] == _APPROVAL

        web = client.get("/incidents", params={"source": "web_fetch"}).json()
        assert web["total"] == 1
        assert web["incidents"][0]["id"] == _BLOCK_B

        combined = client.get(
            "/incidents",
            params={"status": "blocked", "type": "quarantine_block", "source": "github_issue"},
        ).json()
        assert combined["total"] == 1
        assert combined["incidents"][0]["id"] == _BLOCK

        after = client.get("/incidents", params={"since": _T1}).json()
        assert after["total"] == 3
        assert _BLOCK_B not in {item["id"] for item in after["incidents"]}
        assert _APPROVAL not in {item["id"] for item in after["incidents"]}

        page = client.get("/incidents", params={"limit": 2, "offset": 1}).json()
        assert page["total"] == 5
        assert [item["id"] for item in page["incidents"]] == ids[1:3]

        one = client.get(f"/incidents/{_BLOCK}")
        assert one.status_code == 200
        assert one.json()["type"] == "quarantine_block"
        assert _SECRET not in one.text

        missing = client.get("/incidents/99999999-9999-4999-8999-999999999999")
        assert missing.status_code == 404
        assert missing.json() == {"error": "not_found", "message": "Incident not found."}

        summary = client.get("/incidents/summary")
        assert summary.status_code == 200
        counts = summary.json()
        assert counts["by_status"]["blocked"] == 1
        assert counts["by_status"]["pending_approval"] == 1
        assert counts["by_status"]["pending"] == 1
        assert counts["by_status"]["approved"] == 1
        assert counts["by_status"]["rejected"] == 1
        assert counts["by_source"]["github_issue"] == 3
        assert _SECRET not in summary.text


def test_malicious_and_suspicious_incidents_have_distinct_statuses(tmp_path: Path):
    from sieve.approval.approval_gate import ApprovalGate
    from sieve.core.types import (
        ActionTaken,
        ContentSource,
        DetectionResult,
        RiskLevel,
        UntrustedContent,
    )
    from sieve.mcp.guardian import GuardianRuntime, audit_log_resource
    from sieve.quarantine.audit_log import AuditLogger
    from sieve.quarantine.wrapper import QuarantineWrapper

    class _Fixed:
        def __init__(self, risk: RiskLevel, score: float, name: str) -> None:
            self._risk = risk
            self._score = score
            self._name = name

        def scan(self, content: UntrustedContent) -> DetectionResult:
            return DetectionResult(
                content_id=content.id,
                is_flagged=True,
                risk_level=self._risk,
                detected_patterns=["stub"],
                raw_score=self._score,
                explanation="stub",
                detector_name=self._name,
            )

    audit = AuditLogger(path="")
    malicious_wrapper = QuarantineWrapper(
        detectors=[_Fixed(RiskLevel.MALICIOUS, 0.91, "L1HeuristicDetector")],
        audit_logger=audit,
    )
    suspicious_wrapper = QuarantineWrapper(
        detectors=[_Fixed(RiskLevel.SUSPICIOUS, 0.40, "L2CompositeDetector")],
        audit_logger=audit,
    )
    malicious = malicious_wrapper.process(
        UntrustedContent(source=ContentSource.GITHUB_ISSUE, raw_text="malicious payload")
    )
    suspicious = suspicious_wrapper.process(
        UntrustedContent(source=ContentSource.WEB_FETCH, raw_text="suspicious payload")
    )
    assert malicious.action_taken == ActionTaken.BLOCKED
    assert suspicious.action_taken == ActionTaken.PENDING_APPROVAL

    runtime = GuardianRuntime(
        wrapper=malicious_wrapper,
        gate=ApprovalGate(audit_path=""),
        audit_logger=audit,
    )
    payload = audit_log_resource(runtime)
    actions = {entry["content_id"]: entry.get("action_taken") for entry in payload["entries"]}
    assert actions[str(malicious.content.id)] == "BLOCKED"
    assert actions[str(suspicious.content.id)] == "PENDING_APPROVAL"

    source = FakeSource(payload, {"approvals": []})
    with TestClient(_app(tmp_path, source)) as client:
        body = client.get("/incidents").json()
        by_id = {item["id"]: item for item in body["incidents"]}
        assert by_id[str(malicious.content.id)]["status"] == "blocked"
        assert by_id[str(suspicious.content.id)]["status"] == "pending_approval"

        blocked = client.get("/incidents", params={"status": "blocked"}).json()
        assert blocked["total"] == 1
        assert blocked["incidents"][0]["id"] == str(malicious.content.id)
        assert blocked["incidents"][0]["status"] == "blocked"

        waiting = client.get("/incidents", params={"status": "pending_approval"}).json()
        assert waiting["total"] == 1
        assert waiting["incidents"][0]["id"] == str(suspicious.content.id)
        assert waiting["incidents"][0]["status"] == "pending_approval"


def test_restart_restores_incidents_from_jsonl(tmp_path: Path):
    path = tmp_path / "incidents.jsonl"
    source = FakeSource({"entries": [_block()]}, {"approvals": []})
    with TestClient(create_app(source=source, incidents_path=path, refresh_seconds=0.05)) as client:
        body = client.get("/incidents").json()
        assert body["total"] == 1
        assert body["incidents"][0]["id"] == _BLOCK
    empty = FakeSource()
    with TestClient(create_app(source=empty, incidents_path=path, refresh_seconds=0.05)) as client:
        body = client.get("/incidents").json()
        assert body["total"] == 1
        assert body["incidents"][0]["status"] == "blocked"
        assert _SECRET not in client.get("/incidents").text


def test_http_approval_updates_same_id(tmp_path: Path):
    source = FakeSource({"entries": []}, {"approvals": [_pending()]})
    with TestClient(_app(tmp_path, source)) as client:
        first = client.get("/incidents").json()
        assert first["total"] == 1
        assert first["incidents"][0]["status"] == "pending"
        with source.lock:
            source.pending = {"approvals": []}
            source.audit = {"entries": [_approval(_APPROVAL, "approved", timestamp=_T3)]}
        deadline = time.monotonic() + 2
        current = first
        while time.monotonic() < deadline:
            current = client.get("/incidents").json()
            if current["incidents"] and current["incidents"][0]["status"] == "approved":
                break
            time.sleep(0.05)
        assert current["total"] == 1
        assert current["incidents"][0]["id"] == _APPROVAL
        assert current["incidents"][0]["type"] == "approval_approved"


def test_stream_snapshot_then_upserts(tmp_path: Path):
    source = FakeSource({"entries": []}, {"approvals": [_pending()]})

    def publish() -> None:
        time.sleep(0.25)
        with source.lock:
            source.audit = {"entries": [_block()]}
        time.sleep(0.35)
        with source.lock:
            source.pending = {"approvals": []}
            source.audit = {
                "entries": [_block(), _approval(_APPROVAL, "approved", timestamp=_T3)]
            }

    with TestClient(_app(tmp_path, source)) as client:
        threading.Thread(target=publish, daemon=True).start()
        response = client.get("/incidents/stream", params={"max_seconds": 1.2})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    body = response.text
    assert "event: snapshot" in body
    assert "approval_pending" in body
    assert "quarantine_block" in body
    assert "approval_approved" in body
    assert _SECRET not in body


def _sse_events(body: str, name: str) -> list[dict]:
    events: list[dict] = []
    current: str | None = None
    for line in body.splitlines():
        if line.startswith("event: "):
            current = line[7:]
        elif line.startswith("data: ") and current == name:
            events.append(json.loads(line[6:]))
            current = None
    return events


def _jsonl_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_stream_emits_new_quarantines_once(tmp_path: Path):
    path = tmp_path / "incidents.jsonl"
    source = FakeSource({"entries": []}, {"approvals": [_pending()]})
    malicious = _block(_BLOCK, action_taken="BLOCKED")
    suspicious = _block(
        _BLOCK_B,
        source="WEB_FETCH",
        detector="L2",
        score=0.4,
        timestamp=_T0,
        reason="approval_required",
        event="QUARANTINED",
        action_taken="PENDING_APPROVAL",
    )
    seen: dict[str, int] = {}

    def publish() -> None:
        time.sleep(0.35)
        seen["before"] = len(_jsonl_lines(path))
        with source.lock:
            source.audit = {"entries": [malicious, suspicious]}
            source.pending = {"approvals": [_pending()]}

    application = create_app(
        source=source,
        incidents_path=path,
        refresh_seconds=0.05,
        first_poll_timeout=1.0,
    )
    with TestClient(application) as client:
        threading.Thread(target=publish, daemon=True).start()
        response = client.get("/incidents/stream", params={"max_seconds": 1.2})

    assert response.status_code == 200
    assert seen["before"] == 1
    assert len(_jsonl_lines(path)) == seen["before"] + 2
    upserts = _sse_events(response.text, "upsert")
    by_id = {item["id"]: item for item in upserts}
    assert by_id[_BLOCK]["status"] == "blocked"
    assert by_id[_BLOCK_B]["status"] == "pending_approval"
    assert _APPROVAL not in by_id
    assert response.text.count(_APPROVAL) == 1


def test_responses_do_not_leak_raw_content(tmp_path: Path):
    poisoned = _block("66666666-6666-4666-8666-666666666666", reason="malicious")
    poisoned["detected_patterns"] = [_SECRET]
    poisoned["source"] = _SECRET
    source = FakeSource(
        {"entries": [poisoned, _block()]},
        {"approvals": [_pending(summary="Bounded summary only.")]},
    )
    with TestClient(_app(tmp_path, source)) as client:
        listed = client.get("/incidents")
        single = client.get(f"/incidents/{_BLOCK}")
        summary = client.get("/incidents/summary")
        for response in (listed, single, summary):
            assert response.status_code == 200
            assert _SECRET not in response.text
        unknown = [item for item in listed.json()["incidents"] if item["source"] == "unknown"]
        assert unknown
        assert all(len(item["context_summary"]) <= 180 for item in listed.json()["incidents"])
        streamed = client.get("/incidents/stream", params={"max_seconds": 0.2})
        assert streamed.status_code == 200
        assert _SECRET not in streamed.text


def test_history_is_readable_while_mcp_is_down(tmp_path: Path):
    path = tmp_path / "incidents.jsonl"
    source = FakeSource({"entries": [_block()]}, {"approvals": []})
    with TestClient(create_app(source=source, incidents_path=path, refresh_seconds=0.05)) as client:
        seeded = client.get("/incidents")
        assert seeded.status_code == 200
        assert seeded.json()["total"] == 1
    down = FakeSource(fail=True)
    with TestClient(create_app(source=down, incidents_path=path, refresh_seconds=0.05)) as client:
        listed = client.get("/incidents")
        assert listed.status_code == 200
        body = listed.json()
        assert body["total"] == 1
        assert body["incidents"][0]["id"] == _BLOCK
        one = client.get(f"/incidents/{_BLOCK}")
        assert one.status_code == 200
        assert one.json()["id"] == _BLOCK
        assert one.json()["status"] == "blocked"


def test_mcp_unavailable_returns_503_and_stream_status(tmp_path: Path):
    source = FakeSource(fail=True)
    with TestClient(_app(tmp_path, source)) as client:
        listed = client.get("/incidents")
        assert listed.status_code == 200
        assert listed.json() == {"incidents": [], "total": 0}
        missing = client.get("/incidents/99999999-9999-4999-8999-999999999999")
        assert missing.status_code == 404
        assert missing.json() == {"error": "not_found", "message": "Incident not found."}
        summary = client.get("/incidents/summary")
        assert summary.status_code == 503
        assert summary.json() == {
            "error": "mcp_unavailable",
            "message": "MCP server is unreachable.",
        }
        streamed = client.get("/incidents/stream", params={"max_seconds": 0.2})
        assert streamed.status_code == 200
        assert "event: mcp_status" in streamed.text
        assert "mcp_unavailable" in streamed.text
