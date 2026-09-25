"""README file interceptor.

Scans the content of README files (or any local/fetched Markdown file) for
embedded prompt-injection payloads before passing the text to the agent.

Usage::

    from sieve.hooks.readme_hook import ReadmeHook

    hook = ReadmeHook()
    result = hook.read_file("path/to/README.md")
"""

from __future__ import annotations

from pathlib import Path

from sieve.core.logger import get_logger
from sieve.core.types import ContentSource, UntrustedContent
from sieve.quarantine.wrapper import QuarantineWrapper

log = get_logger(__name__)


class ReadmeHook:
    """Intercept README / Markdown reads and scan for injected instructions."""

    def __init__(self) -> None:
        self._wrapper = QuarantineWrapper()

    def read_file(
        self,
        path: str | Path,
        *,
        encoding: str = "utf-8",
        extra_metadata: dict | None = None,
    ) -> "QuarantineWrapper.ScanResult":  # noqa: F821
        """Read *path* from disk and scan its contents.

        Args:
            path:           Path to the README or Markdown file.
            encoding:       File encoding (default ``utf-8``).
            extra_metadata: Optional extra fields merged into the log entry.

        Returns:
            A :class:`~sieve.quarantine.wrapper.ScanResult` with scan results.
        """
        resolved = Path(path).resolve()
        raw_text = resolved.read_text(encoding=encoding)
        content = UntrustedContent(
            source=ContentSource.README,
            raw_text=raw_text,
            metadata={"path": str(resolved), **(extra_metadata or {})},
        )
        return self._wrapper.process(content)

    def read_string(
        self,
        text: str,
        *,
        label: str = "<inline>",
        extra_metadata: dict | None = None,
    ) -> "QuarantineWrapper.ScanResult":  # noqa: F821
        """Scan an already-loaded string as if it were a README.

        Useful for testing or for content fetched via a different mechanism.
        """
        content = UntrustedContent(
            source=ContentSource.README,
            raw_text=text,
            metadata={"label": label, **(extra_metadata or {})},
        )
        return self._wrapper.process(content)
