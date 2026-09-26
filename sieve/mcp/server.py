"""MCP server entry point for Sieve.

Every tool call enters through :func:`dispatch_tool`. Host tools that return
externally sourced text (``github_get_issue``, pull requests, issue and review
comments, ``web_fetch``, README reads) are scanned by
:class:`~sieve.quarantine.wrapper.QuarantineWrapper` before the result is
returned. The ``sieve_*`` tools remain available for explicit scans.

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

``python -m sieve.mcp.server`` starts the Security Guardian MCP server
(stdio). ``--http`` serves the same tools over streamable HTTP. The functions
below remain the legacy dispatcher for host-tool quarantine tests.
"""

from __future__ import annotations

import asyncio
import json
import sys

from sieve.core.config import settings
from sieve.core.logger import configure_logging, get_logger
from sieve.core.types import ContentSource, UntrustedContent

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Tool handler implementations
# ---------------------------------------------------------------------------


def _handle_scan(text: str, source: str = "WEB_FETCH") -> dict:
    from sieve.quarantine.wrapper import QuarantineWrapper, release_view

    src = ContentSource(source.upper()) if source.upper() in ContentSource._value2member_map_ else ContentSource.WEB_FETCH
    content = UntrustedContent(source=src, raw_text=text)
    wrapper = QuarantineWrapper()
    result = wrapper.process(content)
    return release_view(result)


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
    from sieve.quarantine.wrapper import ScanResult, release_view

    if isinstance(result, ScanResult):
        return release_view(result)
    hook = getattr(result, "_result", None)
    if hook is not None:
        return _hook_to_agent(hook)
    raise TypeError(f"Cannot release result of type {type(result)!r}")


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


class UnknownToolError(LookupError):
    """Raised when :func:`dispatch_tool` is asked to run an unknown tool."""

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(tool_name)


def _hook_to_agent(result) -> dict:  # type: ignore[no-untyped-def]
    """Shape a guard-hook result the way the agent consumes tool output."""
    from sieve.core.types import HookExecutionStatus

    meta = result.metadata or {}
    reason = str(meta.get("reason", ""))
    body = meta.get("body", result.processed_content)
    action = {
        HookExecutionStatus.CLEAN: "ALLOWED",
        HookExecutionStatus.QUARANTINED: "QUARANTINED",
        HookExecutionStatus.BLOCKED: "BLOCKED",
    }[result.status]
    view = {
        "status": result.status.value,
        "risk_level": result.detection_result.risk_level.value,
        "risk_score": meta.get("risk_score", result.detection_result.raw_score),
        "action_taken": action,
        "is_flagged": result.status != HookExecutionStatus.CLEAN,
        "detectors_fired": list(meta.get("detectors_fired") or []),
        "detected_patterns": list(result.detection_result.detected_patterns),
        "explanation": result.detection_result.explanation,
        "reason": reason,
        "approval_required": bool(meta.get("approval_required", False)),
        "body": body,
        "source": result.source.value,
    }
    if result.status == HookExecutionStatus.CLEAN and meta.get("include_original_payload", True):
        view["original_payload"] = result.original_payload
        view["quarantined_text"] = body
        view["content"] = body
    elif reason.startswith("detector_error:"):
        view["body"] = None
        view["content"] = None
        view["quarantined_text"] = None
    else:
        view["quarantined_text"] = body
        view["content"] = body
    return view


def dispatch_tool(tool_name: str, arguments: dict | None = None):  # type: ignore[no-untyped-def]
    """Dispatch *tool_name* and quarantine external text before returning it.

    Host read tools are guarded here, so the agent receives the wrapper's
    decision whether it called ``github_get_issue`` or ``sieve_fetch_issue``.
    """
    from sieve.hooks.github_hook import (
        _ISSUE_COMMENT_TOOL_NAMES,
        _ISSUE_TOOL_NAMES,
        _PR_COMMENT_TOOL_NAMES,
        _PR_TOOL_NAMES,
        GitHubGuardHook,
    )
    from sieve.hooks.readme_hook import _README_TOOL_NAMES, ReadmeGuardHook
    from sieve.hooks.web_hook import _WEB_FETCH_TOOL_NAMES, WebFetchGuardHook

    params = dict(arguments or {})
    key = tool_name.strip().lower()
    github_tools = (
        _ISSUE_TOOL_NAMES | _PR_TOOL_NAMES | _ISSUE_COMMENT_TOOL_NAMES | _PR_COMMENT_TOOL_NAMES
    )

    if key in github_tools:
        guarded = asyncio.run(GitHubGuardHook().intercept_read_call(tool_name, params))
        return _hook_to_agent(guarded)
    if key in _WEB_FETCH_TOOL_NAMES:
        guarded = asyncio.run(WebFetchGuardHook().intercept_web_fetch_call(tool_name, params))
        return _hook_to_agent(guarded)
    if key in _README_TOOL_NAMES:
        guarded = asyncio.run(ReadmeGuardHook().intercept_readme_read_call(tool_name, params))
        return _hook_to_agent(guarded)

    entry = TOOL_REGISTRY.get(tool_name)
    if entry is None:
        raise UnknownToolError(tool_name)
    return entry["handler"](**params)


def github_get_issue(owner: str, repo: str, issue_number: int) -> dict:
    """Host tool: return a GitHub issue only after quarantine."""
    return dispatch_tool(
        "github_get_issue",
        {"owner": owner, "repo": repo, "issue_number": issue_number},
    )


def github_get_pull_request(owner: str, repo: str, pull_number: int) -> dict:
    """Host tool: return a GitHub pull request only after quarantine."""
    return dispatch_tool(
        "github_get_pull_request",
        {"owner": owner, "repo": repo, "pull_number": pull_number},
    )


def web_fetch(url: str, timeout: int = 20) -> dict:
    """Host tool: return a fetched page only after quarantine."""
    return dispatch_tool("web_fetch", {"url": url, "timeout": timeout})


def read_file(path: str, repo: str = "") -> dict:
    """Host tool: return README / file text only after quarantine."""
    return dispatch_tool("read_file", {"path": path, "repo": repo})


def _blocked_handler_result(exc: BaseException) -> dict:
    """Tool-call result for a failure outside ``QuarantineWrapper.process``."""
    return {
        "status": "BLOCKED",
        "body": None,
        "content": None,
        "quarantined_text": None,
        "reason": f"handler_error: {exc}",
        "is_flagged": True,
        "risk_level": "MALICIOUS",
        "action_taken": "BLOCKED",
    }


def handle_stdio_request(line: str) -> dict:
    """Run one JSON-RPC tool call and always return a result object.

    Parse errors, unknown tools, and exceptions raised above ``process``
    become ``status=BLOCKED`` on ``result``. They are not JSON-RPC errors.
    """
    req_id = None
    try:
        request = json.loads(line)
        if not isinstance(request, dict):
            raise TypeError("request must be a JSON object")
        req_id = request.get("id")
        params = request.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise TypeError("params must be an object")
        result = dispatch_tool(str(request.get("method", "")), params)
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    except Exception as exc:  # noqa: BLE001
        log.error("Tool call failed closed.", extra={"error": str(exc)})
        return {"jsonrpc": "2.0", "id": req_id, "result": _blocked_handler_result(exc)}


def _serialize_response(response: dict) -> str:
    """Encode *response*. A dump failure is itself a BLOCKED result."""
    try:
        return json.dumps(response) + "\n"
    except Exception as exc:  # noqa: BLE001
        log.error("Response serialization failed closed.", extra={"error": str(exc)})
        fallback = {
            "jsonrpc": "2.0",
            "id": response.get("id"),
            "result": _blocked_handler_result(exc),
        }
        return json.dumps(fallback) + "\n"


def _stdio_loop() -> None:
    """Legacy JSON-RPC stdio loop used by fail-closed handler tests."""
    configure_logging(level=settings.log_level, fmt=settings.log_format)
    log.info("Sieve MCP server starting (stdio).")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        sys.stdout.write(_serialize_response(handle_stdio_request(line)))
        sys.stdout.flush()


if __name__ == "__main__":
    from sieve.mcp.guardian import main

    main()
