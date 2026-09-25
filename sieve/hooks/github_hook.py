"""GitHub Issue / PR body interceptor.

Wraps the GitHub REST API call to fetch issue or PR bodies and routes the
raw text through the Sieve detection pipeline before returning it to the
caller.

Usage::

    from sieve.hooks.github_hook import GitHubHook

    hook = GitHubHook()
    result = hook.fetch_issue("owner", "repo", issue_number=42)
    # result.quarantined_text is safe to pass to the agent
"""

from __future__ import annotations

from sieve.core.config import settings
from sieve.core.logger import get_logger
from sieve.core.types import ContentSource, UntrustedContent
from sieve.quarantine.wrapper import QuarantineWrapper

log = get_logger(__name__)


class GitHubHook:
    """Intercept GitHub Issue and PR content before it reaches the agent."""

    def __init__(self, token: str | None = None) -> None:
        self._token = token or settings.github_token
        self._wrapper = QuarantineWrapper()

    # ── Public API ────────────────────────────────────────────────────────────

    def fetch_issue(
        self,
        owner: str,
        repo: str,
        issue_number: int,
        *,
        extra_metadata: dict | None = None,
    ) -> "QuarantineWrapper.ScanResult":  # noqa: F821
        """Fetch a GitHub Issue body and scan it for injection.

        Args:
            owner:          Repository owner (user or org).
            repo:           Repository name.
            issue_number:   GitHub issue number.
            extra_metadata: Optional extra fields merged into the log entry.

        Returns:
            A :class:`~sieve.quarantine.wrapper.ScanResult` with the
            (possibly sanitised) text and the detection metadata.
        """
        raw_body = self._get_issue_body(owner, repo, issue_number)
        content = UntrustedContent(
            source=ContentSource.GITHUB_ISSUE,
            raw_text=raw_body,
            metadata={
                "owner": owner,
                "repo": repo,
                "issue_number": issue_number,
                **(extra_metadata or {}),
            },
        )
        return self._wrapper.process(content)

    def fetch_pr(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        *,
        extra_metadata: dict | None = None,
    ) -> "QuarantineWrapper.ScanResult":  # noqa: F821
        """Fetch a GitHub PR body and scan it for injection.

        Args:
            owner:          Repository owner.
            repo:           Repository name.
            pr_number:      Pull-request number.
            extra_metadata: Optional extra fields merged into the log entry.
        """
        raw_body = self._get_pr_body(owner, repo, pr_number)
        content = UntrustedContent(
            source=ContentSource.GITHUB_PR,
            raw_text=raw_body,
            metadata={
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                **(extra_metadata or {}),
            },
        )
        return self._wrapper.process(content)

    # ── Internal / HTTP layer ─────────────────────────────────────────────────

    def _get_issue_body(self, owner: str, repo: str, number: int) -> str:
        """TODO: implement GitHub REST API call using httpx."""
        import httpx

        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{number}"
        response = httpx.get(url, headers=self._auth_headers(), timeout=15)
        response.raise_for_status()
        return response.json().get("body") or ""

    def _get_pr_body(self, owner: str, repo: str, number: int) -> str:
        """TODO: implement GitHub REST API call using httpx."""
        import httpx

        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
        response = httpx.get(url, headers=self._auth_headers(), timeout=15)
        response.raise_for_status()
        return response.json().get("body") or ""

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers
