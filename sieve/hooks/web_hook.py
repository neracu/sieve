"""Web-fetch interceptor.

Wraps arbitrary HTTP GET requests made by the agent so that the retrieved
page content passes through the Sieve detection pipeline before being returned.

Usage::

    from sieve.hooks.web_hook import WebHook

    hook = WebHook()
    result = hook.fetch("https://example.com/potentially-malicious-page")
"""

from __future__ import annotations

from sieve.core.logger import get_logger
from sieve.core.types import ContentSource, UntrustedContent
from sieve.quarantine.wrapper import QuarantineWrapper

log = get_logger(__name__)


class WebHook:
    """Intercept web-fetch calls and scan the returned HTML/text."""

    def __init__(self) -> None:
        self._wrapper = QuarantineWrapper()

    def fetch(
        self,
        url: str,
        *,
        timeout: int = 20,
        extra_metadata: dict | None = None,
    ) -> "QuarantineWrapper.ScanResult":  # noqa: F821
        """Fetch *url* and scan the response body for injection.

        Args:
            url:            The URL to fetch.
            timeout:        HTTP request timeout in seconds.
            extra_metadata: Optional extra fields merged into the log entry.

        Returns:
            A :class:`~sieve.quarantine.wrapper.ScanResult` with scan results.
        """
        raw_text = self._http_get(url, timeout=timeout)
        content = UntrustedContent(
            source=ContentSource.WEB_FETCH,
            raw_text=raw_text,
            metadata={"url": url, **(extra_metadata or {})},
        )
        return self._wrapper.process(content)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _http_get(self, url: str, *, timeout: int) -> str:
        import httpx

        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        return response.text
