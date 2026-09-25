"""MCP server entry point for Sieve.

Exposes the following MCP tools to a connected AI agent:

- ``sieve_scan``         — Scan arbitrary text for prompt injection.
- ``sieve_fetch_issue``  — Fetch & scan a GitHub Issue body.
- ``sieve_fetch_pr``     — Fetch & scan a GitHub PR body.
- ``sieve_fetch_url``    — Fetch & scan a web page.
- ``sieve_read_readme``  — Read & scan a local README / Markdown file.
- ``sieve_list_incidents`` — Return recent incident logs.
- ``sieve_list_approvals`` — Return pending approval requests.
- ``sieve_approve``      — Approve a pending action.
- ``sieve_deny``         — Deny a pending action.

Run with::

    python -m sieve.mcp.server          # stdio transport (default)
    python -m sieve.mcp.server --sse    # SSE transport on port 8080

TODO: Install the ``mcp`` package (``pip install mcp``) and replace the
      stub ``register_tool`` calls below with the real MCP SDK API once the
      dependency is finalised.
"""

from __future__ import annotations

import json
import sys

from sieve.core.config import settings
from sieve.core.logger import configure_logging, get_logger
from sieve.core.types import ContentSource, UntrustedContent

configure_logging(level=settings.log_level, fmt=settings.log_format)
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Tool handler implementations
# ---------------------------------------------------------------------------


def _handle_scan(text: str, source: str = "WEB_FETCH") -> dict:
    from sieve.quarantine.wrapper import QuarantineWrapper

    src = ContentSource(source.upper()) if source.upper() in ContentSource._value2member_map_ else ContentSource.WEB_FETCH
    content = UntrustedContent(source=src, raw_text=text)
    wrapper = QuarantineWrapper()
    result = wrapper.process(content)
    return {
        "risk_level": result.final_risk_level.value,
        "action_taken": result.action_taken.value,
        "is_flagged": result.final_risk_level.value != "SAFE",
        "detected_patterns": result.incident_log.detected_patterns,
        "explanation": result.incident_log.explanation,
        "quarantined_text": result.quarantined_text,
    }


def _handle_fetch_issue(owner: str, repo: str, issue_number: int) -> dict:
    from sieve.hooks.github_hook import GitHubHook

    result = GitHubHook().fetch_issue(owner, repo, issue_number)
    return _scan_result_to_dict(result)


def _handle_fetch_pr(owner: str, repo: str, pr_number: int) -> dict:
    from sieve.hooks.github_hook import GitHubHook

    result = GitHubHook().fetch_pr(owner, repo, pr_number)
    return _scan_result_to_dict(result)


def _handle_fetch_url(url: str) -> dict:
    from sieve.hooks.web_hook import WebHook

    result = WebHook().fetch(url)
    return _scan_result_to_dict(result)


def _handle_read_readme(path: str) -> dict:
    from sieve.hooks.readme_hook import ReadmeHook

    result = ReadmeHook().read_file(path)
    return _scan_result_to_dict(result)


def _handle_list_incidents() -> list[dict]:
    # TODO: persist incidents; for now return empty list as a stub.
    return []


def _handle_list_approvals() -> list[dict]:
    from sieve.approval.gate import gate

    return [r.model_dump(mode="json") for r in gate.list_pending()]


def _handle_approve(request_id: str, resolved_by: str = "operator") -> dict:
    from uuid import UUID

    from sieve.approval.gate import gate

    req = gate.approve(UUID(request_id), resolved_by=resolved_by)
    return req.model_dump(mode="json")


def _handle_deny(request_id: str, resolved_by: str = "operator") -> dict:
    from uuid import UUID

    from sieve.approval.gate import ApprovalDeniedError, gate

    try:
        gate.deny(UUID(request_id), resolved_by=resolved_by)
    except ApprovalDeniedError as exc:
        return exc.request.model_dump(mode="json")
    return {}  # unreachable


def _scan_result_to_dict(result) -> dict:  # type: ignore[no-untyped-def]
    return {
        "risk_level": result.final_risk_level.value,
        "action_taken": result.action_taken.value,
        "is_flagged": result.final_risk_level.value != "SAFE",
        "detected_patterns": result.incident_log.detected_patterns,
        "explanation": result.incident_log.explanation,
        "quarantined_text": result.quarantined_text,
    }


# ---------------------------------------------------------------------------
# MCP server bootstrap
# ---------------------------------------------------------------------------

TOOL_REGISTRY = {
    "sieve_scan": {
        "description": "Scan arbitrary text for prompt injection.",
        "handler": _handle_scan,
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The text to scan."},
                "source": {
                    "type": "string",
                    "enum": ["GITHUB_ISSUE", "GITHUB_PR", "WEB_FETCH", "README"],
                    "default": "WEB_FETCH",
                },
            },
            "required": ["text"],
        },
    },
    "sieve_fetch_issue": {
        "description": "Fetch and scan a GitHub Issue body.",
        "handler": _handle_fetch_issue,
        "input_schema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "issue_number": {"type": "integer"},
            },
            "required": ["owner", "repo", "issue_number"],
        },
    },
    "sieve_fetch_pr": {
        "description": "Fetch and scan a GitHub PR body.",
        "handler": _handle_fetch_pr,
        "input_schema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
            },
            "required": ["owner", "repo", "pr_number"],
        },
    },
    "sieve_fetch_url": {
        "description": "Fetch and scan a web page for prompt injection.",
        "handler": _handle_fetch_url,
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    "sieve_read_readme": {
        "description": "Read and scan a local README or Markdown file.",
        "handler": _handle_read_readme,
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "sieve_list_incidents": {
        "description": "Return recent Sieve incident logs.",
        "handler": _handle_list_incidents,
        "input_schema": {"type": "object", "properties": {}},
    },
    "sieve_list_approvals": {
        "description": "Return pending approval requests.",
        "handler": _handle_list_approvals,
        "input_schema": {"type": "object", "properties": {}},
    },
    "sieve_approve": {
        "description": "Approve a pending privileged-action request.",
        "handler": _handle_approve,
        "input_schema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "resolved_by": {"type": "string", "default": "operator"},
            },
            "required": ["request_id"],
        },
    },
    "sieve_deny": {
        "description": "Deny a pending privileged-action request.",
        "handler": _handle_deny,
        "input_schema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "resolved_by": {"type": "string", "default": "operator"},
            },
            "required": ["request_id"],
        },
    },
}


def _stdio_loop() -> None:
    """Minimal JSON-RPC stdio loop (stub — replace with real MCP SDK)."""
    log.info("Sieve MCP server starting (stdio).")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            tool_name = request.get("method", "")
            params = request.get("params", {})
            req_id = request.get("id")

            if tool_name not in TOOL_REGISTRY:
                response = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}
            else:
                result = TOOL_REGISTRY[tool_name]["handler"](**params)
                response = {"jsonrpc": "2.0", "id": req_id, "result": result}
        except Exception as exc:  # noqa: BLE001
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    _stdio_loop()
