"""Structured logging configuration for Sieve.

Supports two output formats controlled by ``settings.log_format``:
- ``"text"``  — human-readable coloured output (default for development)
- ``"json"``  — newline-delimited JSON for log aggregators
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A002
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Attach any extra keyword arguments passed to the logger call.
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and not key.startswith("_"):
                payload[key] = value
        return json.dumps(payload, default=str)


class _TextFormatter(logging.Formatter):
    _LEVEL_COLORS = {
        "DEBUG": "\033[36m",    # cyan
        "INFO": "\033[32m",     # green
        "WARNING": "\033[33m",  # yellow
        "ERROR": "\033[31m",    # red
        "CRITICAL": "\033[35m", # magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:  # noqa: A002
        color = self._LEVEL_COLORS.get(record.levelname, "")
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        prefix = f"{color}{record.levelname:<8}{self._RESET} {ts} [{record.name}]"
        return f"{prefix}  {record.getMessage()}"


def configure_logging(level: str = "INFO", fmt: str = "text", stream=None) -> None:
    """Configure the root logger for Sieve.

    Call this once at application startup (e.g. in the MCP server entry point
    or the dashboard ``lifespan`` handler).

    Args:
        level: Python logging level string (``"DEBUG"``, ``"INFO"``, …).
        fmt:   ``"json"`` or ``"text"``.
        stream: Destination for log records. Defaults to stdout. The MCP
                stdio server passes stderr so protocol frames stay clean.
    """
    handler = logging.StreamHandler(sys.stdout if stream is None else stream)
    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(_TextFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger.

    Usage::

        from sieve.core.logger import get_logger
        log = get_logger(__name__)
        log.info("Scanning content", extra={"source": "GITHUB_ISSUE"})
    """
    return logging.getLogger(name)
