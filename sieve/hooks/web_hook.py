"""Web Fetch Guard Hook — intercept and scan web content for prompt injection.

This module replaces the earlier ``WebHook`` stub with a fully async
``WebFetchGuardHook`` that:

1. Accepts a URL + raw HTML/text **or** live tool-call arguments via
   :meth:`intercept_web_fetch_call`.
2. Extracts hidden injection vectors *before* scanning:
   - HTML comments  ``<!-- ... -->``
   - Invisible DOM elements (``display:none``, ``visibility:hidden``,
     ``opacity:0``, ``font-size:0``)
   - Zero-width unicode characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD)
   - Suspicious base64-encoded blocks (≥ 40 chars of pure b64 alphabet)
3. Runs all extracted text through the L1 heuristic (and L2 watsonx when
   a key is configured) detector pipeline via
   :class:`~sieve.quarantine.wrapper.QuarantineWrapper`.
4. Returns a :class:`~sieve.core.types.HookExecutionResult` with status
   ``CLEAN``, ``QUARANTINED``, or ``BLOCKED``.

The module also exposes ``wrap_web_fetch_tool`` — a decorator that guards
any async coroutine returning ``(url, html_text)`` or ``{"url": ..., "content": ...}``.

Usage::

    from sieve.hooks.web_hook import WebFetchGuardHook, wrap_web_fetch_tool

    hook = WebFetchGuardHook()

    # Inspect content you already have:
    result = await hook.inspect_web_content("https://example.com", raw_html)

    # Intercept a live tool call by name:
    result = await hook.intercept_web_fetch_call(
        "web_fetch", {"url": "https://example.com"}
    )

    # Decorator form — wraps any async function that returns (url, html) or a dict:
    @wrap_web_fetch_tool
    async def my_fetch(url: str) -> str: ...
"""

from __future__ import annotations

import asyncio
import base64
import functools
import re
from typing import Any, Awaitable, Callable

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
# Known tool names for the intercept dispatcher
# ---------------------------------------------------------------------------

_WEB_FETCH_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "web_fetch",
        "fetch_url",
        "http_get",
        "browse_web",
        "open_url",
        "get_webpage",
        "mcp_web_fetch",
        "web_search_fetch",
    }
)

# ---------------------------------------------------------------------------
# Hidden-vector extraction — regex patterns
# ---------------------------------------------------------------------------

# HTML comments: <!-- anything -->
_RE_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Inline style attributes that hide content
_HIDDEN_STYLE_KEYWORDS = (
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"opacity\s*:\s*0(?:\.0+)?(?:\s|;|\")",
    r"font-size\s*:\s*0(?:px|pt|em|rem)?(?:\s|;|\")",
    r"color\s*:\s*transparent",
    r"width\s*:\s*0(?:px)?(?:\s|;|\")",
    r"height\s*:\s*0(?:px)?(?:\s|;|\")",
    r"overflow\s*:\s*hidden",
)
_RE_HIDDEN_STYLE = re.compile(
    r"<[^>]+style\s*=\s*[\"'][^\"']*(?:" + "|".join(_HIDDEN_STYLE_KEYWORDS) + r")[^\"']*[\"'][^>]*>(.*?)</\w+>",
    re.DOTALL | re.IGNORECASE,
)

# Hidden attribute (HTML5 hidden attribute)
_RE_HIDDEN_ATTR = re.compile(
    r"<[^>]+\bhidden\b[^>]*>(.*?)</\w+>",
    re.DOTALL | re.IGNORECASE,
)

# aria-hidden="true"
_RE_ARIA_HIDDEN = re.compile(
    r'<[^>]+aria-hidden\s*=\s*["\']true["\'][^>]*>(.*?)</\w+>',
    re.DOTALL | re.IGNORECASE,
)

# Zero-width / invisible unicode characters
_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff\u00ad\u2060\u180e"
_RE_ZERO_WIDTH = re.compile(f"[{re.escape(_ZERO_WIDTH_CHARS)}]+")

# Base64 blocks: ≥40 contiguous chars from the base64 alphabet (with optional padding)
_RE_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Strip all remaining HTML tags to get visible plain text
_RE_ALL_TAGS = re.compile(r"<[^>]+>", re.DOTALL)

# Collapse whitespace
_RE_WHITESPACE = re.compile(r"\s{3,}")


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _extract_html_comments(html: str) -> list[str]:
    """Return all non-empty HTML comment bodies."""
    return [m.strip() for m in _RE_HTML_COMMENT.findall(html) if m.strip()]


def _extract_hidden_elements(html: str) -> list[str]:
    """Return text content of DOM elements hidden via CSS or HTML attributes."""
    found: list[str] = []
    for pattern in (_RE_HIDDEN_STYLE, _RE_HIDDEN_ATTR, _RE_ARIA_HIDDEN):
        for match in pattern.finditer(html):
            text = _RE_ALL_TAGS.sub(" ", match.group(1)).strip()
            if text:
                found.append(text)
    return found


def _extract_zero_width_sequences(text: str) -> list[str]:
    """Return zero-width character sequences that could encode hidden payloads."""
    return [m.group() for m in _RE_ZERO_WIDTH.finditer(text) if len(m.group()) >= 3]


def _extract_base64_blocks(text: str) -> list[str]:
    """Return base64 blocks and their decoded plaintext (if decodable as UTF-8)."""
    decoded: list[str] = []
    for m in _RE_BASE64_BLOCK.finditer(text):
        blob = m.group()
        # Pad to a multiple of 4 before decoding
        padded = blob + "=" * (-len(blob) % 4)
        try:
            plain = base64.b64decode(padded).decode("utf-8", errors="strict")
            # Only keep if it decodes to printable ASCII / UTF-8
            if plain.isprintable() or "\n" in plain:
                decoded.append(plain)
        except Exception:  # noqa: BLE001
            pass
    return decoded


def _html_to_visible_text(html: str) -> str:
    """Strip tags and collapse whitespace to get the visible page text."""
    text = _RE_HTML_COMMENT.sub(" ", html)
    text = _RE_ALL_TAGS.sub(" ", text)
    text = _RE_WHITESPACE.sub(" ", text)
    return text.strip()


def build_scan_text(url: str, raw_html_or_text: str) -> tuple[str, dict[str, Any]]:
    """Parse *raw_html_or_text* and build the consolidated scan blob.

    Returns:
        A ``(scan_text, extraction_metadata)`` tuple where *scan_text* is the
        full string to feed to the detector pipeline and *extraction_metadata*
        records what was extracted (for the incident log).
    """
    is_html = bool(re.search(r"<(?:html|head|body|div|span|p|script|style)\b", raw_html_or_text, re.I))

    parts: list[str] = []
    meta: dict[str, Any] = {"url": url, "is_html": is_html}

    # ── Visible text (always included) ────────────────────────────────────────
    visible = _html_to_visible_text(raw_html_or_text) if is_html else raw_html_or_text.strip()
    if visible:
        parts.append(f"[VISIBLE_TEXT]\n{visible}")

    # ── HTML comments ─────────────────────────────────────────────────────────
    comments = _extract_html_comments(raw_html_or_text)
    meta["html_comment_count"] = len(comments)
    for idx, c in enumerate(comments, 1):
        parts.append(f"[HTML_COMMENT_{idx}]\n{c}")

    # ── Hidden DOM elements ───────────────────────────────────────────────────
    hidden_elems = _extract_hidden_elements(raw_html_or_text)
    meta["hidden_element_count"] = len(hidden_elems)
    for idx, h in enumerate(hidden_elems, 1):
        parts.append(f"[HIDDEN_ELEMENT_{idx}]\n{h}")

    # ── Zero-width sequences ──────────────────────────────────────────────────
    zw_seqs = _extract_zero_width_sequences(raw_html_or_text)
    meta["zero_width_sequence_count"] = len(zw_seqs)
    if zw_seqs:
        parts.append(f"[ZERO_WIDTH_SEQUENCES]\n{' '.join(repr(s) for s in zw_seqs)}")

    # ── Base64 blocks ─────────────────────────────────────────────────────────
    b64_decoded = _extract_base64_blocks(raw_html_or_text)
    meta["base64_block_count"] = len(b64_decoded)
    for idx, decoded in enumerate(b64_decoded, 1):
        parts.append(f"[BASE64_DECODED_{idx}]\n{decoded}")

    return "\n\n".join(parts), meta


# ---------------------------------------------------------------------------
# Shared result-building helpers (mirrors github_hook pattern)
# ---------------------------------------------------------------------------


def _status_from_scan(scan: ScanResult) -> HookExecutionStatus:
    if scan.action_taken == ActionTaken.ALLOWED:
        return HookExecutionStatus.CLEAN
    if scan.final_risk_level == RiskLevel.MALICIOUS:
        return HookExecutionStatus.BLOCKED
    return HookExecutionStatus.QUARANTINED


def _aggregate_detection(scan: ScanResult) -> DetectionResult:
    if not scan.detection_results:
        return DetectionResult(
            content_id=scan.content.id,
            is_flagged=False,
            risk_level=RiskLevel.SAFE,
        )
    risk_order = {RiskLevel.SAFE: 0, RiskLevel.SUSPICIOUS: 1, RiskLevel.MALICIOUS: 2}
    return max(scan.detection_results, key=lambda r: risk_order[r.risk_level])


# ---------------------------------------------------------------------------
# Primary class
# ---------------------------------------------------------------------------


class WebFetchGuardHook:
    """Async guard hook for external web content.

    Sits between a Bob/MCP ``web_fetch`` tool call and the raw HTTP response.
    All public methods are coroutines for seamless integration in async servers.

    Args:
        detectors: Custom detector list forwarded to
                   :class:`~sieve.quarantine.wrapper.QuarantineWrapper`.
                   Defaults to the standard L1 (+ L2 when key is set) pipeline.
    """

    def __init__(self, *, detectors: list | None = None) -> None:
        self._wrapper = QuarantineWrapper(detectors=detectors)

    # ── Public async API ──────────────────────────────────────────────────────

    async def inspect_web_content(
        self,
        url: str,
        raw_html_or_text: str,
        *,
        extra_metadata: dict[str, Any] | None = None,
    ) -> HookExecutionResult:
        """Scan raw HTML or plain text fetched from *url* for injection.

        The method extracts hidden vectors (comments, invisible elements,
        zero-width chars, base64 blocks) and feeds everything to the detector
        pipeline before returning a result.

        Args:
            url:              The URL the content was fetched from.
            raw_html_or_text: Raw HTTP response body (HTML or plain text).
            extra_metadata:   Additional key-value pairs merged into the result.

        Returns:
            :class:`~sieve.core.types.HookExecutionResult` with ``status``
            of ``CLEAN``, ``QUARANTINED``, or ``BLOCKED``.
        """
        scan_text, extraction_meta = build_scan_text(url, raw_html_or_text)
        meta = {**extraction_meta, **(extra_metadata or {})}

        log.debug(
            "Inspecting web content.",
            extra={
                "url": url,
                "text_len": len(scan_text),
                "comments": meta.get("html_comment_count", 0),
                "hidden_elements": meta.get("hidden_element_count", 0),
                "base64_blocks": meta.get("base64_block_count", 0),
            },
        )

        content = UntrustedContent(
            source=ContentSource.WEB_FETCH,
            raw_text=scan_text,
            metadata=meta,
        )
        scan = await asyncio.get_running_loop().run_in_executor(
            None, self._wrapper.process, content
        )
        return self._build_result(scan, url, raw_html_or_text, meta)

    async def intercept_web_fetch_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> HookExecutionResult:
        """Intercept a named Bob/MCP tool call that fetches web content.

        Fetches the URL from *arguments*, then delegates to
        :meth:`inspect_web_content`.

        Supported tool names (case-insensitive):
            ``web_fetch``, ``fetch_url``, ``http_get``, ``browse_web``,
            ``open_url``, ``get_webpage``, ``mcp_web_fetch``,
            ``web_search_fetch``

        Args:
            tool_name:  The MCP/Bob tool name being intercepted.
            arguments:  The tool's argument dict — must contain ``"url"`` or
                        ``"uri"``; optional ``"timeout"`` (seconds).

        Returns:
            :class:`~sieve.core.types.HookExecutionResult`.

        Raises:
            ValueError: If *tool_name* is not a recognised web-fetch tool.
        """
        if tool_name.lower() not in _WEB_FETCH_TOOL_NAMES:
            raise ValueError(
                f"Tool '{tool_name}' is not a recognised web-fetch tool. "
                f"Known tools: {sorted(_WEB_FETCH_TOOL_NAMES)}."
            )

        url = arguments.get("url") or arguments.get("uri") or ""
        if not url:
            raise ValueError(f"Tool '{tool_name}' arguments must include a 'url' key.")

        timeout = int(arguments.get("timeout", 20))
        raw_html = await asyncio.get_running_loop().run_in_executor(
            None, self._http_get, url, timeout
        )
        return await self.inspect_web_content(
            url, raw_html, extra_metadata={"tool_name": tool_name}
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_result(
        scan: ScanResult,
        url: str,
        raw_html_or_text: str,
        metadata: dict[str, Any],
    ) -> HookExecutionResult:
        status = _status_from_scan(scan)
        detection = _aggregate_detection(scan)

        log.info(
            "Web guard hook result.",
            extra={
                "url": url,
                "status": status.value,
                "risk_level": scan.final_risk_level.value,
                "patterns": scan.incident_log.detected_patterns,
            },
        )
        from sieve.approval.approval_gate import observe_guard_hook

        observe_guard_hook(scan, ContentSource.WEB_FETCH.value)

        return HookExecutionResult(
            status=scan.status,
            source=ContentSource.WEB_FETCH,
            original_payload=(
                {"url": url, "raw_content": raw_html_or_text}
                if scan.include_original_payload
                else None
            ),
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

    @staticmethod
    def _http_get(url: str, timeout: int) -> str:
        import httpx

        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        return response.text


# ---------------------------------------------------------------------------
# Decorator helper
# ---------------------------------------------------------------------------


def wrap_web_fetch_tool(
    func: Callable[..., Awaitable[str]] | None = None,
    *,
    hook: WebFetchGuardHook | None = None,
) -> Callable:
    """Decorator that transparently guards a coroutine fetching web content.

    The wrapped function must be an ``async`` function whose first positional
    argument is a URL string and which returns the raw HTML/text string.
    The decorator replaces that return value with a
    :class:`~sieve.core.types.HookExecutionResult`.

    Can be used with or without arguments::

        # Without arguments (uses a default WebFetchGuardHook):
        @wrap_web_fetch_tool
        async def my_fetch(url: str) -> str:
            ...  # returns raw HTML

        # With a pre-built hook:
        shared_hook = WebFetchGuardHook()

        @wrap_web_fetch_tool(hook=shared_hook)
        async def my_fetch(url: str) -> str: ...

    The wrapped function's ``url`` is resolved from:
    1. A keyword argument ``url=``.
    2. The first positional argument (assumed to be the URL string).

    Returns:
        The decorated function, whose return value is a
        :class:`~sieve.core.types.HookExecutionResult`.
    """
    def decorator(fn: Callable[..., Awaitable[str]]) -> Callable[..., Awaitable[HookExecutionResult]]:
        _hook: WebFetchGuardHook | None = hook

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> HookExecutionResult:
            nonlocal _hook
            if _hook is None:
                _hook = WebFetchGuardHook()

            # Resolve URL from kwargs or first positional arg
            url: str = kwargs.get("url") or (args[0] if args else "")
            raw_html: str = await fn(*args, **kwargs)
            return await _hook.inspect_web_content(url, raw_html)

        return wrapper

    # Support both @wrap_web_fetch_tool and @wrap_web_fetch_tool(hook=...)
    if func is not None:
        # Called as @wrap_web_fetch_tool (no parentheses)
        return decorator(func)
    # Called as @wrap_web_fetch_tool(...) with keyword args
    return decorator


# ---------------------------------------------------------------------------
# Legacy synchronous shim (backward-compatibility with WebHook callers)
# ---------------------------------------------------------------------------


class WebHook:
    """Synchronous shim kept for backward compatibility.

    New code should use :class:`WebFetchGuardHook` instead.
    """

    def __init__(self) -> None:
        self._guard = WebFetchGuardHook()

    def fetch(
        self,
        url: str,
        *,
        timeout: int = 20,
        extra_metadata: dict | None = None,
    ) -> ScanResult:
        raw_html = self._guard._http_get(url, timeout)
        result = asyncio.run(
            self._guard.inspect_web_content(url, raw_html, extra_metadata=extra_metadata)
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
