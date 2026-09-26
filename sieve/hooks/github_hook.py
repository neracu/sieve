"""GitHub Guard Hook — intercept GitHub Issue / PR payloads.

This module replaces the earlier ``GitHubHook`` stub with a fully async
``GitHubGuardHook`` that:

1. Accepts raw GitHub API payloads (issues, pull-requests) **or** live
   API arguments via :meth:`intercept_read_call`.
2. Consolidates all untrusted text fields (title, body, comments, diff
   filenames) into a single :class:`~sieve.core.types.UntrustedContent` blob.
3. Runs that blob through the L1 heuristic detector (and L2 watsonx when
   an API key is present) via :class:`~sieve.quarantine.wrapper.QuarantineWrapper`.
4. Returns a :class:`~sieve.core.types.HookExecutionResult` whose ``status``
   field is one of ``CLEAN``, ``QUARANTINED``, or ``BLOCKED``.

The module also exposes ``wrap_github_tool`` — a decorator / async wrapper
that transparently guards any coroutine whose first positional argument is a
GitHub API payload dict.

Usage::

    from sieve.hooks.github_hook import GitHubGuardHook, wrap_github_tool

    hook = GitHubGuardHook()

    # Inspect a payload dict you already have:
    result = await hook.inspect_issue(issue_payload)

    # Intercept a live tool call by name:
    result = await hook.intercept_read_call(
        "github_get_issue",
        {"owner": "acme", "repo": "backend", "issue_number": 42},
    )

    # Decorator form — wraps any async function that returns a GitHub payload:
    @wrap_github_tool("issue")
    async def get_issue(owner: str, repo: str, issue_number: int) -> dict: ...
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Awaitable, Callable

from sieve.core.config import settings
from sieve.core.logger import get_logger
from sieve.core.types import (
    ActionTaken,
    ContentSource,
    DetectionResult,
    HookExecutionResult,
    HookExecutionStatus,
    RiskLevel,
    UntrustedContent,
)
from sieve.quarantine.wrapper import QuarantineWrapper, ScanResult

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Tool names that the intercept_read_call dispatcher understands.
_ISSUE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "github_get_issue",
        "get_issue",
        "read_issue",
        "fetch_issue",
        "mcp_github_get_issue",
    }
)

_PR_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "github_get_pull_request",
        "get_pull_request",
        "read_pull_request",
        "fetch_pr",
        "mcp_github_get_pull_request",
    }
)

_ISSUE_COMMENT_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "github_list_issue_comments",
        "github_get_issue_comments",
        "list_issue_comments",
        "get_issue_comments",
        "mcp_github_list_issue_comments",
    }
)

_PR_COMMENT_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "github_list_review_comments",
        "github_get_pull_request_comments",
        "list_review_comments",
        "get_pull_request_comments",
        "mcp_github_list_review_comments",
    }
)


def _status_from_scan(scan: ScanResult) -> HookExecutionStatus:
    """Map a :class:`~sieve.quarantine.wrapper.ScanResult` to a
    :class:`~sieve.core.types.HookExecutionStatus`."""
    if scan.action_taken == ActionTaken.ALLOWED:
        return HookExecutionStatus.CLEAN
    if scan.final_risk_level == RiskLevel.MALICIOUS:
        return HookExecutionStatus.BLOCKED
    return HookExecutionStatus.QUARANTINED


def _aggregate_detection(scan: ScanResult) -> DetectionResult:
    """Return the highest-risk :class:`~sieve.core.types.DetectionResult`
    from the scan, falling back to the first result if all are SAFE."""
    if not scan.detection_results:
        # Synthesise a SAFE stub so HookExecutionResult is always populated.
        return DetectionResult(
            content_id=scan.content.id,
            is_flagged=False,
            risk_level=RiskLevel.SAFE,
        )
    risk_order = {RiskLevel.SAFE: 0, RiskLevel.SUSPICIOUS: 1, RiskLevel.MALICIOUS: 2}
    return max(scan.detection_results, key=lambda r: risk_order[r.risk_level])


def _extract_issue_text(payload: dict[str, Any]) -> str:
    """Consolidate all user-controlled text fields from an Issue payload.

    Combines title, body, and any embedded comments list so that injections
    hidden in comments are also caught.
    """
    parts: list[str] = []

    title = (payload.get("title") or "").strip()
    if title:
        parts.append(f"[TITLE] {title}")

    body = (payload.get("body") or "").strip()
    if body:
        parts.append(f"[BODY]\n{body}")

    # Some callers embed a ``comments`` list directly in the payload.
    # The GitHub issue API uses this key for a comment *count*, not the bodies.
    _append_comment_bodies(parts, payload.get("comments"), "COMMENT")

    return "\n\n".join(parts)


def _extract_pr_text(payload: dict[str, Any]) -> str:
    """Consolidate all user-controlled text fields from a PR payload.

    Combines title, body, and any diff/file summaries so injections hidden
    in PR descriptions or synthetic diff metadata are caught.
    """
    parts: list[str] = []

    title = (payload.get("title") or "").strip()
    if title:
        parts.append(f"[TITLE] {title}")

    body = (payload.get("body") or "").strip()
    if body:
        parts.append(f"[BODY]\n{body}")

    # Optional: diff file summary list (e.g. from a pre-processed payload).
    files = payload.get("files") or payload.get("changed_files_detail") or []
    if not isinstance(files, list):
        files = []
    for f in files:
        if not isinstance(f, dict):
            continue
        filename = (f.get("filename") or "").strip()
        patch = (f.get("patch") or "").strip()
        if filename:
            parts.append(f"[FILE] {filename}")
        if patch:
            parts.append(f"[PATCH]\n{patch}")

    # Conversation comments and review comments are separate lists. Scan both.
    # Author and id stay in metadata so they do not sit inside the scanned text.
    _append_comment_bodies(parts, payload.get("comments"), "COMMENT")
    _append_comment_bodies(parts, payload.get("review_comments"), "REVIEW COMMENT")

    return "\n\n".join(parts)


def _comment_body(comment: Any) -> str:
    if isinstance(comment, dict):
        return str(comment.get("body") or "").strip()
    return str(comment).strip()


def _append_comment_bodies(parts: list[str], comments: Any, label: str) -> None:
    """Append comment bodies with separators. Author and id are not included."""
    if not isinstance(comments, list):
        return
    index = 0
    for comment in comments:
        body = _comment_body(comment)
        if not body:
            continue
        index += 1
        parts.append(f"[{label} {index}]\n{body}")


def _comment_refs(comments: Any) -> list[dict[str, Any]]:
    """Author and id for the quarantine log. Empty when *comments* is a count."""
    if not isinstance(comments, list):
        return []
    refs: list[dict[str, Any]] = []
    for comment in comments:
        if isinstance(comment, dict):
            user = comment.get("user") if isinstance(comment.get("user"), dict) else {}
            refs.append({"id": comment.get("id"), "author": user.get("login")})
        else:
            refs.append({"id": None, "author": None})
    return refs


def _next_page_url(link_header: str) -> str | None:
    """Return the GitHub ``Link`` header URL marked ``rel="next"``."""
    for part in link_header.split(","):
        if 'rel="next"' not in part:
            continue
        start = part.find("<")
        end = part.find(">")
        if start != -1 and end > start:
            return part[start + 1 : end]
    return None


def _extract_issue_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull structured metadata fields from an Issue payload."""
    meta: dict[str, Any] = {}
    if "number" in payload:
        meta["issue_number"] = payload["number"]
    if "html_url" in payload:
        meta["url"] = payload["html_url"]
    user = payload.get("user") or {}
    if isinstance(user, dict) and user.get("login"):
        meta["author"] = user["login"]
    repo_info = payload.get("repository") or {}
    if isinstance(repo_info, dict):
        if repo_info.get("full_name"):
            meta["repository"] = repo_info["full_name"]
        elif repo_info.get("name"):
            meta["repository"] = repo_info["name"]
    if "labels" in payload:
        meta["labels"] = [
            lbl.get("name", str(lbl)) if isinstance(lbl, dict) else str(lbl)
            for lbl in (payload["labels"] or [])
        ]
    comment_refs = _comment_refs(payload.get("comments"))
    if comment_refs:
        meta["comment_refs"] = comment_refs
    return meta


def _extract_pr_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull structured metadata fields from a PR payload."""
    meta: dict[str, Any] = {}
    if "number" in payload:
        meta["pr_number"] = payload["number"]
    if "html_url" in payload:
        meta["url"] = payload["html_url"]
    user = payload.get("user") or {}
    if isinstance(user, dict) and user.get("login"):
        meta["author"] = user["login"]
    head = payload.get("head") or {}
    if isinstance(head, dict):
        if head.get("label"):
            meta["head_branch"] = head["label"]
        repo = head.get("repo") or {}
        if isinstance(repo, dict) and repo.get("full_name"):
            meta["repository"] = repo["full_name"]
    base = payload.get("base") or {}
    if isinstance(base, dict) and base.get("label"):
        meta["base_branch"] = base["label"]
    if "changed_files" in payload:
        meta["changed_files"] = payload["changed_files"]
    comment_refs = _comment_refs(payload.get("comments"))
    if comment_refs:
        meta["comment_refs"] = comment_refs
    review_refs = _comment_refs(payload.get("review_comments"))
    if review_refs:
        meta["review_comment_refs"] = review_refs
    return meta


# ---------------------------------------------------------------------------
# Primary class
# ---------------------------------------------------------------------------


class GitHubGuardHook:
    """Async guard hook for GitHub Issue and PR content.

    Designed to sit between a Bob tool call and the raw GitHub API response.
    All public methods are coroutines so the hook can be embedded naturally
    in async MCP server handlers.

    Args:
        token:     GitHub personal-access token (falls back to
                   ``settings.github_token``).
        detectors: Custom detector list forwarded to
                   :class:`~sieve.quarantine.wrapper.QuarantineWrapper`.
                   Defaults to the standard L1 (+ L2 when key is set) pipeline.
    """

    def __init__(
        self,
        token: str | None = None,
        *,
        detectors: list | None = None,
    ) -> None:
        self._token = token or settings.github_token
        self._wrapper = QuarantineWrapper(detectors=detectors)

    # ── Public async API ──────────────────────────────────────────────────────

    async def inspect_issue(
        self,
        issue_payload: dict[str, Any],
        *,
        extra_metadata: dict[str, Any] | None = None,
    ) -> HookExecutionResult:
        """Scan a raw GitHub Issue API payload for prompt injection.

        The payload is the dict returned directly by the GitHub REST API
        ``GET /repos/{owner}/{repo}/issues/{issue_number}`` endpoint, optionally
        with a ``"comments"`` key containing an embedded list of comment objects.

        Args:
            issue_payload:  Raw GitHub Issue API response dict.
            extra_metadata: Additional key-value pairs merged into the metadata
                            of the returned result (e.g. ``{"owner": "acme"}``).

        Returns:
            :class:`~sieve.core.types.HookExecutionResult` with ``status``
            of ``CLEAN``, ``QUARANTINED``, or ``BLOCKED``.
        """
        text = _extract_issue_text(issue_payload)
        meta = {**_extract_issue_metadata(issue_payload), **(extra_metadata or {})}

        log.debug(
            "Inspecting issue payload.",
            extra={"issue_number": meta.get("issue_number"), "text_len": len(text)},
        )

        content = UntrustedContent(
            source=ContentSource.GITHUB_ISSUE,
            raw_text=text,
            metadata=meta,
        )
        scan = await asyncio.get_running_loop().run_in_executor(
            None, self._wrapper.process, content
        )
        return self._build_result(
            scan, ContentSource.GITHUB_ISSUE, issue_payload, meta
        )

    async def inspect_pr(
        self,
        pr_payload: dict[str, Any],
        *,
        extra_metadata: dict[str, Any] | None = None,
    ) -> HookExecutionResult:
        """Scan a raw GitHub Pull Request API payload for prompt injection.

        Accepts the dict returned by ``GET /repos/{owner}/{repo}/pulls/{pull_number}``,
        with optional ``"files"`` / ``"review_comments"`` keys for richer coverage.

        Args:
            pr_payload:     Raw GitHub PR API response dict.
            extra_metadata: Additional key-value pairs merged into the metadata.

        Returns:
            :class:`~sieve.core.types.HookExecutionResult` with ``status``
            of ``CLEAN``, ``QUARANTINED``, or ``BLOCKED``.
        """
        text = _extract_pr_text(pr_payload)
        meta = {**_extract_pr_metadata(pr_payload), **(extra_metadata or {})}

        log.debug(
            "Inspecting PR payload.",
            extra={"pr_number": meta.get("pr_number"), "text_len": len(text)},
        )

        content = UntrustedContent(
            source=ContentSource.GITHUB_PR,
            raw_text=text,
            metadata=meta,
        )
        scan = await asyncio.get_running_loop().run_in_executor(
            None, self._wrapper.process, content
        )
        return self._build_result(
            scan, ContentSource.GITHUB_PR, pr_payload, meta
        )

    async def intercept_read_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> HookExecutionResult:
        """Intercept a named Bob/MCP tool call that reads GitHub content.

        Fetches the live GitHub payload (using the token in settings), then
        delegates to :meth:`inspect_issue` or :meth:`inspect_pr` based on
        *tool_name*.

        Supported tool names:
            - Issue tools: ``github_get_issue``, ``get_issue``, ``read_issue``,
              ``fetch_issue``, ``mcp_github_get_issue``
            - PR tools: ``github_get_pull_request``, ``get_pull_request``,
              ``read_pull_request``, ``fetch_pr``, ``mcp_github_get_pull_request``
            - Comment tools: ``github_list_issue_comments``,
              ``github_list_review_comments``, and their aliases

        Args:
            tool_name:  The MCP/Bob tool name being intercepted.
            arguments:  The tool's argument dict (must include ``owner``,
                        ``repo``, and either ``issue_number`` or ``pull_number``
                        / ``pr_number``).

        Returns:
            :class:`~sieve.core.types.HookExecutionResult`.

        Raises:
            ValueError: If *tool_name* is not a recognised GitHub read tool.
        """
        tool_lower = tool_name.lower()

        if tool_lower in _ISSUE_TOOL_NAMES:
            payload = await asyncio.get_running_loop().run_in_executor(
                None,
                self._fetch_issue_payload,
                arguments["owner"],
                arguments["repo"],
                int(arguments.get("issue_number", arguments.get("number", 0))),
            )
            return await self.inspect_issue(payload, extra_metadata={"tool_name": tool_name})

        if tool_lower in _PR_TOOL_NAMES:
            pr_num = int(
                arguments.get("pull_number")
                or arguments.get("pr_number")
                or arguments.get("number", 0)
            )
            payload = await asyncio.get_running_loop().run_in_executor(
                None,
                self._fetch_pr_payload,
                arguments["owner"],
                arguments["repo"],
                pr_num,
            )
            return await self.inspect_pr(payload, extra_metadata={"tool_name": tool_name})

        if tool_lower in _ISSUE_COMMENT_TOOL_NAMES:
            issue_number = int(arguments.get("issue_number", arguments.get("number", 0)))
            comments = await asyncio.get_running_loop().run_in_executor(
                None,
                self._fetch_issue_comments,
                arguments["owner"],
                arguments["repo"],
                issue_number,
            )
            payload = {"number": issue_number, "title": "", "body": "", "comments": comments}
            return await self.inspect_issue(payload, extra_metadata={"tool_name": tool_name})

        if tool_lower in _PR_COMMENT_TOOL_NAMES:
            pr_num = int(
                arguments.get("pull_number")
                or arguments.get("pr_number")
                or arguments.get("number", 0)
            )
            comments = await asyncio.get_running_loop().run_in_executor(
                None,
                self._fetch_pr_comments,
                arguments["owner"],
                arguments["repo"],
                pr_num,
            )
            payload = {
                "number": pr_num,
                "title": "",
                "body": "",
                "review_comments": comments,
            }
            return await self.inspect_pr(payload, extra_metadata={"tool_name": tool_name})

        raise ValueError(
            f"Tool '{tool_name}' is not a recognised GitHub read tool. "
            f"Known issue tools: {sorted(_ISSUE_TOOL_NAMES)}. "
            f"Known PR tools: {sorted(_PR_TOOL_NAMES)}. "
            f"Known comment tools: {sorted(_ISSUE_COMMENT_TOOL_NAMES | _PR_COMMENT_TOOL_NAMES)}."
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_result(
        scan: ScanResult,
        source: ContentSource,
        original_payload: dict[str, Any],
        metadata: dict[str, Any],
    ) -> HookExecutionResult:
        status = _status_from_scan(scan)
        detection = _aggregate_detection(scan)

        log.info(
            "GitHub guard hook result.",
            extra={
                "source": source.value,
                "status": status.value,
                "risk_level": scan.final_risk_level.value,
                "patterns": scan.incident_log.detected_patterns,
            },
        )
        from sieve.approval.approval_gate import observe_guard_hook

        observe_guard_hook(scan, source.value)

        return HookExecutionResult(
            status=scan.status,
            source=source,
            original_payload=original_payload if scan.include_original_payload else None,
            processed_content=scan.body,
            detection_result=detection,
            metadata={
                **metadata,
                "reason": scan.reason,
                "approval_required": scan.approval_required,
                "risk_score": scan.risk_score,
                "detectors_fired": list(scan.detectors_fired),
                "include_original_payload": scan.include_original_payload,
            },
        )

    def _fetch_issue_payload(
        self, owner: str, repo: str, issue_number: int
    ) -> dict[str, Any]:
        import httpx

        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}"
        response = httpx.get(url, headers=self._auth_headers(), timeout=15)
        response.raise_for_status()
        payload = dict(response.json())
        # The issue object stores a comment count. Replace it with the bodies
        # so the combined payload is what QuarantineWrapper scans.
        if isinstance(payload.get("comments"), int):
            payload["comment_count"] = payload["comments"]
        payload["comments"] = self._fetch_issue_comments(owner, repo, issue_number)
        return payload

    def _fetch_pr_payload(
        self, owner: str, repo: str, pr_number: int
    ) -> dict[str, Any]:
        import httpx

        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
        response = httpx.get(url, headers=self._auth_headers(), timeout=15)
        response.raise_for_status()
        payload = dict(response.json())
        if isinstance(payload.get("comments"), int):
            payload["comment_count"] = payload["comments"]
        if isinstance(payload.get("review_comments"), int):
            payload["review_comment_count"] = payload["review_comments"]
        payload["comments"] = self._fetch_issue_comments(owner, repo, pr_number)
        payload["review_comments"] = self._fetch_pr_comments(owner, repo, pr_number)
        payload["files"] = self._fetch_pr_files(owner, repo, pr_number)
        return payload

    def _fetch_pr_files(
        self, owner: str, repo: str, pr_number: int
    ) -> list[dict[str, Any]]:
        return self._fetch_json_list(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
        )

    def _fetch_issue_comments(
        self, owner: str, repo: str, issue_number: int
    ) -> list[dict[str, Any]]:
        return self._fetch_json_list(
            f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
        )

    def _fetch_pr_comments(
        self, owner: str, repo: str, pr_number: int
    ) -> list[dict[str, Any]]:
        return self._fetch_json_list(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
        )

    def _fetch_json_list(self, url: str) -> list[dict[str, Any]]:
        import httpx

        items: list[dict[str, Any]] = []
        separator = "&" if "?" in url else "?"
        next_url: str | None = url if "per_page=" in url else f"{url}{separator}per_page=100"
        for _page in range(10):
            if not next_url:
                break
            response = httpx.get(next_url, headers=self._auth_headers(), timeout=15)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list):
                items.extend(item for item in data if isinstance(item, dict))
            headers = getattr(response, "headers", None) or {}
            if hasattr(headers, "get"):
                link = headers.get("Link") or headers.get("link") or ""
            else:
                link = ""
            next_url = _next_page_url(str(link))
        return items

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers


# ---------------------------------------------------------------------------
# Decorator helper
# ---------------------------------------------------------------------------

_PayloadKind = str  # "issue" | "pr"


def wrap_github_tool(
    kind: _PayloadKind,
    *,
    hook: GitHubGuardHook | None = None,
) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], Callable[..., Awaitable[HookExecutionResult]]]:
    """Decorator that transparently guards a coroutine returning a GitHub payload.

    The wrapped function must be an ``async`` function that returns a
    ``dict`` representing a raw GitHub Issue or PR API response.  The
    decorator replaces that return value with a
    :class:`~sieve.core.types.HookExecutionResult`.

    Args:
        kind:  ``"issue"`` or ``"pr"`` — which payload extractor to use.
        hook:  Optional pre-constructed :class:`GitHubGuardHook` instance.
               A default instance is created lazily if not provided.

    Example::

        @wrap_github_tool("issue")
        async def my_get_issue(owner: str, repo: str, issue_number: int) -> dict:
            ...  # calls GitHub API, returns raw dict

        result = await my_get_issue("acme", "backend", 42)
        # result is now a HookExecutionResult

    Raises:
        ValueError: If *kind* is not ``"issue"`` or ``"pr"``.
    """
    if kind not in ("issue", "pr"):
        raise ValueError(f"wrap_github_tool: kind must be 'issue' or 'pr', got {kind!r}.")

    def decorator(
        func: Callable[..., Awaitable[dict[str, Any]]],
    ) -> Callable[..., Awaitable[HookExecutionResult]]:
        _hook = hook  # captured from outer scope; resolved lazily below

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> HookExecutionResult:
            nonlocal _hook
            if _hook is None:
                _hook = GitHubGuardHook()

            payload: dict[str, Any] = await func(*args, **kwargs)

            if kind == "issue":
                return await _hook.inspect_issue(payload)
            return await _hook.inspect_pr(payload)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Legacy synchronous shim (backward-compatibility with GitHubHook callers)
# ---------------------------------------------------------------------------


class GitHubHook:
    """Synchronous shim kept for backward compatibility.

    New code should use :class:`GitHubGuardHook` instead.
    """

    def __init__(self, token: str | None = None) -> None:
        self._guard = GitHubGuardHook(token=token)

    def fetch_issue(
        self,
        owner: str,
        repo: str,
        issue_number: int,
        *,
        extra_metadata: dict | None = None,
    ) -> ScanResult:
        payload = self._guard._fetch_issue_payload(owner, repo, issue_number)
        result = asyncio.run(
            self._guard.inspect_issue(payload, extra_metadata=extra_metadata)
        )
        # Return a ScanResult-like object for callers that expect the old API.
        return _HookResultAsScanResult(result)

    def fetch_pr(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        *,
        extra_metadata: dict | None = None,
    ) -> ScanResult:
        payload = self._guard._fetch_pr_payload(owner, repo, pr_number)
        result = asyncio.run(
            self._guard.inspect_pr(payload, extra_metadata=extra_metadata)
        )
        return _HookResultAsScanResult(result)


class _HookResultAsScanResult:
    """Thin adapter exposing ``quarantined_text`` on a ``HookExecutionResult``."""

    def __init__(self, result: HookExecutionResult) -> None:
        self._result = result

    @property
    def quarantined_text(self) -> str:
        return self._result.processed_content

    @property
    def final_risk_level(self) -> RiskLevel:
        return self._result.detection_result.risk_level

    @property
    def action_taken(self) -> ActionTaken:
        _map = {
            HookExecutionStatus.CLEAN: ActionTaken.ALLOWED,
            HookExecutionStatus.QUARANTINED: ActionTaken.QUARANTINED,
            HookExecutionStatus.BLOCKED: ActionTaken.BLOCKED,
        }
        return _map[self._result.status]
