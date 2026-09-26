"""Audit log writer for Sieve quarantine events.

Every blocked or quarantined scan decision is written to a dedicated
append-only file so that security operators can review flagged content
without it ever appearing in console/API output.

The file is separate from the main application log to satisfy the
no-leakage requirement: raw flagged text (or the content ID that lets an
operator retrieve it) is recorded *only* here, never in ``log.info/error``
calls or API responses sent back to the calling agent.

Configuration
-------------
``SIEVE_AUDIT_LOG_PATH`` (preferred) or ``AUDIT_LOG_PATH``
    Path to the audit log file.  Defaults to ``sieve_audit.log`` in the
    current working directory.  Set to an empty string or ``/dev/null`` to
    disable.

Format
------
One JSON object per line, UTF-8 encoded, always flushed after each write:

.. code-block:: json

    {
        "timestamp": "2024-01-15T10:23:45.123456+00:00",
        "event": "BLOCKED",
        "source": "GITHUB_ISSUE",
        "detector": "L1",
        "risk_score": 0.85,
        "detected_patterns": ["imperative_override", "credential_exfil"],
        "content_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "content_len": 312,
        "explanation": "[L1HeuristicDetector] ..."
    }

Note: ``raw_text`` is intentionally **not** included in this format. To
retrieve the actual text for forensics, correlate ``content_id`` with any
external storage that received it before the scan.  The ``content_len``
field is provided so operators know how much content was withheld.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from sieve.core.config import settings
from sieve.core.logger import get_logger

if TYPE_CHECKING:
    from sieve.quarantine.wrapper import ScanResult

log = get_logger(__name__)

# Sentinel value used by tests to suppress all file I/O.
_AUDIT_LOG_DISABLED = ""
# In-memory window so callers can read recent decisions without the file.
_RECENT_MAX = 200


def detector_label(fired: list[str]) -> str:
    """Collapse detector names to ``L1``, ``L2``, ``both``, or the first name."""
    names = [str(name) for name in fired if name]
    has_l1 = any("l1" in name.lower() or name.lower() == "l1heuristicdetector" for name in names)
    has_l2 = any(
        "l2" in name.lower() or name.lower() in ("l2compositedetector", "l2watsonxdetector")
        for name in names
    )
    if has_l1 and has_l2:
        return "both"
    if has_l1:
        return "L1"
    if has_l2:
        return "L2"
    return names[0] if names else "unknown"


class AuditLogger:
    """Thread-safe append-only writer for quarantine audit events.

    A single module-level instance (``audit_logger``) is provided for
    convenience.  Tests may construct their own instance with a custom
    *path* to isolate I/O.

    Args:
        path: Absolute or relative path to the audit log file.  Pass an
              empty string to disable file output entirely (useful in tests).
    """

    def __init__(self, path: str | None = None) -> None:
        if path is None:
            path = getattr(settings, "audit_log_path", "sieve_audit.log")
        self._path = path
        self._lock = threading.Lock()
        self._recent: list[dict] = []
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, scan: ScanResult) -> None:
        """Write an audit entry for a blocked or quarantined *scan* result.

        Safe to call from any thread.  Silently swallows I/O errors so that
        a broken audit log never takes down the main pipeline.

        Args:
            scan: The completed :class:`~sieve.quarantine.wrapper.ScanResult`.
        """
        from sieve.core.types import HookExecutionStatus

        if scan.status == HookExecutionStatus.CLEAN:
            return  # Only record non-clean decisions.

        entry = self._build_entry(scan)
        with self._lock:
            self._recent.append(entry)
            if len(self._recent) > _RECENT_MAX:
                del self._recent[: len(self._recent) - _RECENT_MAX]
        if not self._path or self._path == _AUDIT_LOG_DISABLED:
            return  # Disabled — memory still holds the safe entry.

        try:
            line = json.dumps(entry, default=str) + "\n"
            with self._lock, Path(self._path).open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
        except Exception as exc:  # noqa: BLE001
            # Audit log failure must never block the main pipeline.
            log.warning(
                "Audit log write failed.",
                extra={"path": self._path, "error": str(exc)},
            )

    def recent(self, limit: int = 50) -> list[dict]:
        """Newest safe entries first. Raw content is never stored here."""
        size = limit if isinstance(limit, int) and not isinstance(limit, bool) else 50
        size = max(0, min(size, _RECENT_MAX))
        with self._lock:
            window = list(self._recent[-size:])
        window.reverse()
        return [dict(item) for item in window]

    def _load(self) -> None:
        """Read an existing log into memory. Missing or unreadable files stay empty."""
        if not self._path or self._path == _AUDIT_LOG_DISABLED:
            return
        path = Path(self._path)
        if not path.is_file():
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            log.warning("Audit log could not be read.", extra={"path": self._path, "error": str(exc)})
            return
        loaded: list[dict] = []
        for line in lines:
            text = line.strip()
            if not text:
                continue
            try:
                item = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                loaded.append(item)
        if len(loaded) > _RECENT_MAX:
            loaded = loaded[-_RECENT_MAX:]
        self._recent = loaded

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_entry(scan: ScanResult) -> dict:
        """Construct the audit log dict from *scan*.

        Raw content is intentionally omitted.  Only forensic metadata is
        recorded so that this file can be stored with relaxed access
        controls while the actual raw payload stays in a separate secure
        store.
        """
        return {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "event": scan.status.value,
            "source": scan.content.source.value,
            "detector": detector_label(scan.detectors_fired),
            "risk_score": scan.risk_score,
            "detected_patterns": list(scan.incident_log.detected_patterns),
            "content_id": str(scan.content.id),
            # Length recorded so operators know how large the withheld payload was.
            "content_len": len(scan.incident_log.raw_text_excerpt)
            or len(getattr(scan.content, "raw_text", "")),
            "explanation": scan.incident_log.explanation,
            "reason": scan.reason,
            "action_taken": scan.action_taken.value,
        }


# Module-level singleton used by QuarantineWrapper.
audit_logger = AuditLogger()
