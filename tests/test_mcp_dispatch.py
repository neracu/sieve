"""Host tool calls must be quarantined by the MCP dispatcher."""

from __future__ import annotations

import json
from pathlib import Path

from sieve.hooks.github_hook import GitHubGuardHook
from sieve.mcp.server import github_get_issue

_FIXTURES = Path(__file__).parent / "fixtures" / "injections.json"


def test_host_github_get_issue_quarantines_injection(monkeypatch):
    """Calling github_get_issue — not sieve_fetch_issue — still quarantines."""
    payload_text = json.loads(_FIXTURES.read_text(encoding="utf-8"))[0]["payload"]
    issue = {
        "number": 1,
        "title": "Looks like a normal bug",
        "body": payload_text,
        "user": {"login": "attacker"},
        "comments": [],
    }

    monkeypatch.setattr(
        GitHubGuardHook,
        "_fetch_issue_payload",
        lambda self, owner, repo, issue_number: issue,
    )

    result = github_get_issue("acme", "backend", 1)

    assert result["status"] in {"QUARANTINED", "BLOCKED"}
    assert result["is_flagged"] is True
    assert result["quarantined_text"] != payload_text
    assert "[SIEVE:QUARANTINED]" in result["content"]
    assert result["content"] == result["quarantined_text"]
