"""README Guard Hook — intercept and scan README / Markdown files for prompt injection.

This module replaces the earlier ``ReadmeHook`` stub with a fully async
``ReadmeGuardHook`` that:

1. Accepts a raw Markdown string **or** a filesystem path via
   :meth:`inspect_readme`, or live tool-call arguments via
   :meth:`intercept_readme_read_call`.
2. Applies markdown-aware extraction *before* scanning, isolating:
   - Hidden markdown reference-style comments ``[//]: # (...)``
   - HTML comments ``<!-- ... -->``
   - Blockquote bodies (``> ...``)
   - Fenced code blocks `` ``` ... ``` `` and indented code blocks
   - Zero-width Unicode sequences (U+200B, U+200C, U+200D, U+FEFF, …)
   - Suspicious base64-encoded blobs (≥ 40-char runs from the b64 alphabet)
   - Imperative system-override sentences in the visible text
3. Runs the consolidated text through the L1 heuristic (and L2 watsonx when
   a key is configured) detector pipeline via
   :class:`~sieve.quarantine.wrapper.QuarantineWrapper`.
4. Returns a :class:`~sieve.core.types.HookExecutionResult` with status
   ``CLEAN``, ``QUARANTINED``, or ``BLOCKED``.

The module also exposes ``wrap_readme_tool`` — a dual-mode decorator that
guards any async coroutine returning Markdown text.

Usage::

    from sieve.hooks.readme_hook import ReadmeGuardHook, wrap_readme_tool

    hook = ReadmeGuardHook()

    # Inspect a string:
    result = await hook.inspect_readme(markdown_text, repo_identifier="acme/backend")

    # Inspect a file path:
    result = await hook.inspect_readme("/path/to/README.md")

    # Intercept a live tool call:
    result = await hook.intercept_readme_read_call(
        "read_file", {"path": "/path/to/README.md"}
    )

    # Decorator — wraps any async function returning Markdown text:
    @wrap_readme_tool
    async def get_readme(repo: str) -> str: ...
"""

from __future__ import annotations

import asyncio
import base64
import functools
import re
from pathlib import Path
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

_README_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "read_file",
        "read_readme",
        "get_readme",
        "fetch_readme",
        "open_file",
        "cat_file",
        "mcp_read_file",
        "view_file",
        "get_file_contents",
    }
)

# Filename patterns we consider README/documentation files
_README_FILENAME_RE = re.compile(
    r"(?:^|[\\/])(readme|contributing|security|changelog|license|docs?/"
    r"|\.github/)[^/]*\.(md|rst|txt|adoc|asciidoc)?$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Markdown-aware extraction — regex patterns
# ---------------------------------------------------------------------------

# Hidden markdown reference-link comments: [//]: # (content)
# Also covers: [comment]: # (content), [_]: # (content)
_RE_MD_COMMENT = re.compile(
    r"^\s*\[[^\]]*\]\s*:\s*#\s*[\(\{\"'](.+?)[\)\}\"']\s*$",
    re.MULTILINE,
)

# HTML comments (can appear in Markdown rendered as HTML)
_RE_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Fenced code blocks: ```lang\n...\n``` or ~~~lang\n...\n~~~
_RE_FENCED_BLOCK = re.compile(
    r"^(`{3,}|~{3,})[^\n]*\n(.*?)^\1\s*$",
    re.DOTALL | re.MULTILINE,
)

# Indented code blocks (4 spaces or 1 tab)
_RE_INDENTED_BLOCK = re.compile(r"^(?:    |\t)(.+)$", re.MULTILINE)

# Blockquotes: "> text" (one or more levels)
_RE_BLOCKQUOTE = re.compile(r"^>+\s?(.+)$", re.MULTILINE)

# Zero-width / invisible unicode characters
_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff\u00ad\u2060\u180e"
_RE_ZERO_WIDTH = re.compile(f"[{re.escape(_ZERO_WIDTH_CHARS)}]+")

# Base64 blocks: ≥40 contiguous chars from the base64 alphabet
_RE_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Strip inline Markdown formatting to get plain text
_RE_MD_FORMATTING = re.compile(
    r"(?:"
    r"\[([^\]]+)\]\([^)]+\)"   # [text](url)  → keep text
    r"|!\[[^\]]*\]\([^)]+\)"   # ![alt](url)  → drop
    r"|`{1,3}[^`]+`{1,3}"      # `inline code`
    r"|\*{1,3}[^*]+\*{1,3}"    # *bold/italic*
    r"|_{1,3}[^_]+_{1,3}"      # _bold/italic_
    r"|#+\s"                    # ## Heading prefix
    r"|[-*+]\s"                 # list bullets
    r"|\d+\.\s"                 # numbered list
    r")"
)

# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _extract_md_comments(text: str) -> list[str]:
    """Return bodies of hidden markdown reference-style comments."""
    return [m.strip() for m in _RE_MD_COMMENT.findall(text) if m.strip()]


def _extract_html_comments(text: str) -> list[str]:
    """Return bodies of HTML comments embedded in the Markdown."""
    return [m.strip() for m in _RE_HTML_COMMENT.findall(text) if m.strip()]


def _extract_code_blocks(text: str) -> list[str]:
    """Return text content of fenced and indented code blocks."""
    found: list[str] = []
    for m in _RE_FENCED_BLOCK.finditer(text):
        content = m.group(2).strip()
        if content:
            found.append(content)
    for m in _RE_INDENTED_BLOCK.finditer(text):
        line = m.group(1).strip()
        if line:
            found.append(line)
    return found


def _extract_blockquotes(text: str) -> list[str]:
    """Return text content of blockquote lines."""
    return [m.strip() for m in _RE_BLOCKQUOTE.findall(text) if m.strip()]


def _extract_zero_width_sequences(text: str) -> list[str]:
    """Return zero-width character sequences (runs ≥ 3 chars)."""
    return [m.group() for m in _RE_ZERO_WIDTH.finditer(text) if len(m.group()) >= 3]


def _extract_base64_blocks(text: str) -> list[str]:
    """Return decoded text from base64 blobs that parse as valid UTF-8."""
    decoded: list[str] = []
    for m in _RE_BASE64_BLOCK.finditer(text):
        blob = m.group()
        padded = blob + "=" * (-len(blob) % 4)
        try:
            plain = base64.b64decode(padded).decode("utf-8", errors="strict")
            if plain.isprintable() or "\n" in plain:
                decoded.append(plain)
        except Exception:  # noqa: BLE001
            pass
    return decoded


def _md_to_visible_text(text: str) -> str:
    """Strip markdown syntax to get the plain visible text."""
    # Remove HTML comments first
    result = _RE_HTML_COMMENT.sub(" ", text)
    # Remove hidden md comments
    result = _RE_MD_COMMENT.sub(" ", result)
    # Remove fenced code blocks (keep content visible for pattern matching)
    result = _RE_FENCED_BLOCK.sub(lambda m: m.group(2), result)
    # Simplify inline formatting
    result = _RE_MD_FORMATTING.sub(lambda m: m.group(1) or " ", result)
    # Collapse whitespace lines
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()


def build_scan_text(
    markdown: str,
    repo_identifier: str = "",
) -> tuple[str, dict[str, Any]]:
    """Parse *markdown* and build a consolidated scan blob.

    Returns:
        A ``(scan_text, extraction_metadata)`` tuple where *scan_text* is the
        string fed to the detector pipeline and *extraction_metadata* records
        the counts of each extracted vector category.
    """
    parts: list[str] = []
    meta: dict[str, Any] = {"repo_identifier": repo_identifier}

    # ── Visible text ──────────────────────────────────────────────────────────
    visible = _md_to_visible_text(markdown)
    if visible:
        parts.append(f"[VISIBLE_TEXT]\n{visible}")

    # ── Hidden markdown comments ──────────────────────────────────────────────
    md_comments = _extract_md_comments(markdown)
    meta["md_comment_count"] = len(md_comments)
    for idx, c in enumerate(md_comments, 1):
        parts.append(f"[MD_COMMENT_{idx}]\n{c}")

    # ── HTML comments ─────────────────────────────────────────────────────────
    html_comments = _extract_html_comments(markdown)
    meta["html_comment_count"] = len(html_comments)
    for idx, c in enumerate(html_comments, 1):
        parts.append(f"[HTML_COMMENT_{idx}]\n{c}")

    # ── Blockquotes ───────────────────────────────────────────────────────────
    blockquotes = _extract_blockquotes(markdown)
    meta["blockquote_count"] = len(blockquotes)
    for idx, b in enumerate(blockquotes, 1):
        parts.append(f"[BLOCKQUOTE_{idx}]\n{b}")

    # ── Code blocks ───────────────────────────────────────────────────────────
    code_blocks = _extract_code_blocks(markdown)
    meta["code_block_count"] = len(code_blocks)
    for idx, cb in enumerate(code_blocks, 1):
        parts.append(f"[CODE_BLOCK_{idx}]\n{cb}")

    # ── Zero-width sequences ──────────────────────────────────────────────────
    zw_seqs = _extract_zero_width_sequences(markdown)
    meta["zero_width_sequence_count"] = len(zw_seqs)
    if zw_seqs:
        parts.append(f"[ZERO_WIDTH_SEQUENCES]\n{' '.join(repr(s) for s in zw_seqs)}")

    # ── Base64 blocks ─────────────────────────────────────────────────────────
    b64_decoded = _extract_base64_blocks(markdown)
    meta["base64_block_count"] = len(b64_decoded)
    for idx, decoded in enumerate(b64_decoded, 1):
        parts.append(f"[BASE64_DECODED_{idx}]\n{decoded}")

    return "\n\n".join(parts), meta


# ---------------------------------------------------------------------------
# Shared result-building helpers (mirrors github_hook / web_hook pattern)
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


class ReadmeGuardHook:
    """Async guard hook for README and Markdown documentation files.

    Sits between a Bob/MCP file-read tool call and the Markdown content
    delivered to the agent.  All public methods are coroutines.

    Args:
        detectors: Custom detector list forwarded to
                   :class:`~sieve.quarantine.wrapper.QuarantineWrapper`.
                   Defaults to the standard L1 (+ L2 when key is set) pipeline.
    """

    def __init__(self, *, detectors: list | None = None) -> None:
        self._wrapper = QuarantineWrapper(detectors=detectors)

    # ── Public async API ──────────────────────────────────────────────────────

    async def inspect_readme(
        self,
        content_or_path: str,
        repo_identifier: str = "",
        *,
        extra_metadata: dict[str, Any] | None = None,
    ) -> HookExecutionResult:
        """Scan a README string or filesystem path for prompt injection.

        When *content_or_path* looks like a readable file path it is read from
        disk; otherwise the value itself is treated as raw Markdown text.

        Args:
            content_or_path: Raw Markdown text **or** an absolute/relative path
                             to a Markdown file on disk.
            repo_identifier: A human-readable label for the repository
                             (e.g. ``"acme/backend"``).  Stored in metadata.
            extra_metadata:  Additional key-value pairs merged into the result.

        Returns:
            :class:`~sieve.core.types.HookExecutionResult` with status
            ``CLEAN``, ``QUARANTINED``, or ``BLOCKED``.
        """
        markdown, source_label = self._resolve_content(content_or_path)
        scan_text, extraction_meta = build_scan_text(markdown, repo_identifier)
        meta: dict[str, Any] = {
            "source_label": source_label,
            **extraction_meta,
            **(extra_metadata or {}),
        }

        log.debug(
            "Inspecting README content.",
            extra={
                "source_label": source_label,
                "repo": repo_identifier,
                "text_len": len(scan_text),
                "md_comments": meta.get("md_comment_count", 0),
                "html_comments": meta.get("html_comment_count", 0),
                "base64_blocks": meta.get("base64_block_count", 0),
            },
        )

        content = UntrustedContent(
            source=ContentSource.README,
            raw_text=scan_text,
            metadata=meta,
        )
        scan = await asyncio.get_running_loop().run_in_executor(
            None, self._wrapper.process, content
        )
        return self._build_result(scan, markdown, meta)

    async def intercept_readme_read_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> HookExecutionResult:
        """Intercept a named Bob/MCP tool call that reads a README file.

        Reads the file indicated in *arguments*, then delegates to
        :meth:`inspect_readme`.

        Supported tool names (case-insensitive):
            ``read_file``, ``read_readme``, ``get_readme``, ``fetch_readme``,
            ``open_file``, ``cat_file``, ``mcp_read_file``, ``view_file``,
            ``get_file_contents``

        Args:
            tool_name:  The MCP/Bob tool name being intercepted.
            arguments:  The tool's argument dict — must contain ``"path"`` or
                        ``"file"`` or ``"filename"``.

        Returns:
            :class:`~sieve.core.types.HookExecutionResult`.

        Raises:
            ValueError: If *tool_name* is not a recognised README read tool.
            ValueError: If no path key is found in *arguments*.
        """
        if tool_name.lower() not in _README_TOOL_NAMES:
            raise ValueError(
                f"Tool '{tool_name}' is not a recognised README read tool. "
                f"Known tools: {sorted(_README_TOOL_NAMES)}."
            )

        path = (
            arguments.get("path")
            or arguments.get("file")
            or arguments.get("filename")
            or ""
        )
        if not path:
            raise ValueError(
                f"Tool '{tool_name}' arguments must include a 'path', 'file', or 'filename' key."
            )

        repo = arguments.get("repo") or arguments.get("repo_identifier") or ""
        return await self.inspect_readme(
            path,
            repo_identifier=repo,
            extra_metadata={"tool_name": tool_name},
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _resolve_content(content_or_path: str) -> tuple[str, str]:
        """Return ``(markdown_text, source_label)``.

        If *content_or_path* is a path to an existing file, read it.
        Otherwise treat the value as raw Markdown text.
        """
        p = Path(content_or_path)
        if len(content_or_path) < 1024 and p.exists() and p.is_file():
            return p.read_text(encoding="utf-8"), str(p.resolve())
        return content_or_path, "<inline>"

    @staticmethod
    def _build_result(
        scan: ScanResult,
        original_markdown: str,
        metadata: dict[str, Any],
    ) -> HookExecutionResult:
        status = _status_from_scan(scan)
        detection = _aggregate_detection(scan)

        log.info(
            "README guard hook result.",
            extra={
                "source_label": metadata.get("source_label"),
                "status": status.value,
                "risk_level": scan.final_risk_level.value,
                "patterns": scan.incident_log.detected_patterns,
            },
        )

        return HookExecutionResult(
            status=scan.status,
            source=ContentSource.README,
            original_payload=(
                {"markdown": original_markdown} if scan.include_original_payload else None
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


# ---------------------------------------------------------------------------
# Decorator helper
# ---------------------------------------------------------------------------


def wrap_readme_tool(
    func: Callable[..., Awaitable[str]] | None = None,
    *,
    hook: ReadmeGuardHook | None = None,
    repo_identifier: str = "",
) -> Callable:
    """Decorator that transparently guards a coroutine returning Markdown text.

    The wrapped function must be an ``async`` function returning a raw Markdown
    string.  The decorator replaces that return value with a
    :class:`~sieve.core.types.HookExecutionResult`.

    Can be used with or without arguments::

        # Without arguments (uses a default ReadmeGuardHook):
        @wrap_readme_tool
        async def get_readme(repo: str) -> str:
            ...  # returns raw markdown

        # With a pre-built hook and repo label:
        shared_hook = ReadmeGuardHook()

        @wrap_readme_tool(hook=shared_hook, repo_identifier="acme/backend")
        async def get_readme(repo: str) -> str: ...

    Returns:
        The decorated function whose return value is a
        :class:`~sieve.core.types.HookExecutionResult`.
    """
    def decorator(fn: Callable[..., Awaitable[str]]) -> Callable[..., Awaitable[HookExecutionResult]]:
        _hook: ReadmeGuardHook | None = hook

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> HookExecutionResult:
            nonlocal _hook
            if _hook is None:
                _hook = ReadmeGuardHook()

            markdown: str = await fn(*args, **kwargs)
            repo = kwargs.get("repo_identifier") or repo_identifier
            return await _hook.inspect_readme(markdown, repo_identifier=repo)

        return wrapper

    if func is not None:
        # Called as @wrap_readme_tool (no parentheses)
        return decorator(func)
    # Called as @wrap_readme_tool(...) with keyword args
    return decorator


# ---------------------------------------------------------------------------
# Legacy synchronous shim (backward-compatibility with ReadmeHook callers)
# ---------------------------------------------------------------------------


class ReadmeHook:
    """Synchronous shim kept for backward compatibility.

    New code should use :class:`ReadmeGuardHook` instead.
    """

    def __init__(self) -> None:
        self._guard = ReadmeGuardHook()

    def read_file(
        self,
        path: str | Path,
        *,
        encoding: str = "utf-8",
        extra_metadata: dict | None = None,
    ) -> ScanResult:
        resolved = Path(path).resolve()
        raw_text = resolved.read_text(encoding=encoding)
        result = asyncio.run(
            self._guard.inspect_readme(
                raw_text,
                repo_identifier=str(resolved),
                extra_metadata=extra_metadata,
            )
        )
        return _HookResultAsScanResult(result)

    def read_string(
        self,
        text: str,
        *,
        label: str = "<inline>",
        extra_metadata: dict | None = None,
    ) -> ScanResult:
        result = asyncio.run(
            self._guard.inspect_readme(
                text,
                repo_identifier=label,
                extra_metadata=extra_metadata,
            )
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
