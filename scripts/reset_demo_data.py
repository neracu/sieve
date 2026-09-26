"""Reset demo data before recording.

Truncates the incidents JSONL file and the audit log to empty files so the
dashboard and MCP resources start from a clean slate. The files are not
deleted — they are zeroed — because the running server opens them with "a"
and would fail on the next write if they disappeared.

After truncation the script optionally verifies against a live dashboard
(GET /incidents → total=0) and a live MCP server
(resource://audit-log and resource://pending-approvals both empty).

Usage
-----
One-command clean slate before recording:

    python scripts/reset_demo_data.py

With live verification (dashboard + MCP must already be running):

    python scripts/reset_demo_data.py --verify

Override default file paths if you have custom env vars set:

    SIEVE_INCIDENTS_PATH=my_incidents.jsonl \
    SIEVE_AUDIT_LOG_PATH=my_audit.log \
    python scripts/reset_demo_data.py

Environment variables
---------------------
SIEVE_INCIDENTS_PATH   Path to the incidents JSONL file.  Default: sieve_incidents.jsonl
SIEVE_AUDIT_LOG_PATH   Path to the audit log file.        Default: sieve_audit.log
AUDIT_LOG_PATH         Fallback alias for SIEVE_AUDIT_LOG_PATH.
SIEVE_DASHBOARD_URL    Dashboard base URL for --verify.   Default: http://127.0.0.1:8000
SIEVE_MCP_URL          MCP streamable-HTTP URL for --verify.
                       Default: http://127.0.0.1:8081/mcp
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve file paths from env vars (same precedence as the running servers)
# ---------------------------------------------------------------------------

def _incidents_path() -> Path:
    return Path(os.environ.get("SIEVE_INCIDENTS_PATH", "sieve_incidents.jsonl"))


def _audit_path() -> Path:
    raw = (
        os.environ.get("SIEVE_AUDIT_LOG_PATH")
        or os.environ.get("AUDIT_LOG_PATH")
        or "sieve_audit.log"
    )
    return Path(raw)


# ---------------------------------------------------------------------------
# Reset helpers
# ---------------------------------------------------------------------------

def truncate(path: Path, label: str) -> None:
    """Zero-out *path*, creating it if it doesn't exist yet."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    print(f"  ✓  {label}: {path} truncated")


def reset_files() -> None:
    print("Resetting demo data files …")
    truncate(_incidents_path(), "incidents JSONL")
    truncate(_audit_path(), "audit log")
    print()


# ---------------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------------

def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def verify_dashboard(base_url: str) -> bool:
    url = base_url.rstrip("/") + "/incidents"
    try:
        payload = _get_json(url)
    except Exception as exc:
        print(f"  ✗  Dashboard unreachable at {url}: {exc}")
        return False
    total = payload.get("total")
    if total == 0:
        print("  ✓  GET /incidents → total=0")
        return True
    print(f"  ✗  GET /incidents → total={total!r} (expected 0; restart the dashboard to flush in-memory state)")
    return False


def verify_mcp(mcp_url: str) -> bool:
    """Read resource://audit-log and resource://pending-approvals via HTTP."""
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError:
        print("  ⚠  mcp package not importable; skipping MCP resource verification")
        return True

    import asyncio
    from contextlib import AsyncExitStack
    from datetime import timedelta

    import httpx

    async def _check() -> tuple[bool, bool]:
        stack = AsyncExitStack()
        try:
            http = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
            await stack.enter_async_context(http)
            read, write, _get_sid = await stack.enter_async_context(
                streamable_http_client(mcp_url, http_client=http)
            )
            session = await stack.enter_async_context(
                ClientSession(read, write, read_timeout_seconds=timedelta(seconds=5))
            )
            await session.initialize()

            async def _read(uri: str) -> dict:
                result = await session.read_resource(uri)
                contents = getattr(result, "contents", None) or []
                text = getattr(contents[0], "text", None) if contents else None
                return json.loads(text) if isinstance(text, str) else {}

            audit = await _read("resource://audit-log")
            pending = await _read("resource://pending-approvals")
            return audit, pending
        finally:
            await stack.aclose()

    try:
        audit, pending = asyncio.run(_check())
    except Exception as exc:
        print(f"  ✗  MCP server unreachable at {mcp_url}: {exc}")
        return False

    audit_entries = audit.get("entries", [])
    pending_approvals = pending.get("approvals", [])
    ok = True
    if audit_entries:
        print(f"  ✗  resource://audit-log has {len(audit_entries)} entries (restart the MCP server to flush in-memory state)")
        ok = False
    else:
        print("  ✓  resource://audit-log is empty")
    if pending_approvals:
        print(f"  ✗  resource://pending-approvals has {len(pending_approvals)} entries (restart the MCP server)")
        ok = False
    else:
        print("  ✓  resource://pending-approvals is empty")
    return ok


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Truncate demo data files and (optionally) verify the running services.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After truncation, query the live dashboard and MCP server to confirm they are clean.",
    )
    parser.add_argument(
        "--dashboard-url",
        default=os.environ.get("SIEVE_DASHBOARD_URL", "http://127.0.0.1:8000"),
        help="Dashboard base URL (used with --verify).",
    )
    parser.add_argument(
        "--mcp-url",
        default=os.environ.get("SIEVE_MCP_URL", "http://127.0.0.1:8081/mcp"),
        help="MCP streamable-HTTP URL (used with --verify).",
    )
    args = parser.parse_args()

    reset_files()

    if not args.verify:
        print("Files reset. Restart the dashboard and MCP server to also flush in-memory state.")
        print("Re-run with --verify after restarting to confirm everything is clean.")
        return

    print("Verifying live services …")
    dashboard_ok = verify_dashboard(args.dashboard_url)
    mcp_ok = verify_mcp(args.mcp_url)
    print()

    if dashboard_ok and mcp_ok:
        print("✅  Demo environment is clean and ready to record.")
    else:
        print("⚠️   Some checks failed. Restart the affected server(s) and re-run with --verify.")
        sys.exit(1)


if __name__ == "__main__":
    main()
