# Dashboard + Bob workflow

## What actually works

| Piece | Role |
|-------|------|
| **Bob** (`/.bob/mcp.json`) | Spawns **stdio** MCP (`python -m sieve.mcp.server`). Scans/blocks in chat. |
| **HTTP MCP** (`python mcp_server.py --http`) | Same tools on `http://127.0.0.1:8081/mcp`. **Required for the dashboard.** |
| **Dashboard** (`make run-dashboard`) | Polls HTTP MCP `resource://audit-log` every ~1s. |

Bob (stdio) and the HTTP server are **different processes**, but they append to the same
``SIEVE_AUDIT_LOG_PATH`` (see ``.bob/mcp.json``). The HTTP MCP reloads that file on every
``resource://audit-log`` read, so the dashboard picks up Bob blocks within ~1s.

Run HTTP MCP and the dashboard from the **project root** (or set the same
``SIEVE_AUDIT_LOG_PATH`` in ``.env``).

## Reliable demo (two screens)

**Terminal 1** (project root):

```bash
source .venv/bin/activate
python mcp_server.py --http
```

**Terminal 2**:

```bash
make run-dashboard
```

**Browser:** `http://127.0.0.1:8000/dashboard`

**Before recording:**

```bash
make reset-demo
# restart terminal 1 and 2, then:
curl -s http://127.0.0.1:8000/incidents   # expect "total": 0
```

**Bob:** MCP enabled, prompt with injection → blocked in chat.

**Dashboard line item** (same machine, HTTP already running):

```bash
python scripts/pulse_dashboard_incident.py
```

Refresh dashboard → `blocked` count increases.

## Checks

```bash
curl -s http://127.0.0.1:8000/incidents/summary   # 503 → HTTP MCP not on :8081
wc -l sieve_audit.log                            # grows when scans run (stdio or HTTP)
```

## Bob-only (no dashboard)

Enable MCP in `.bob/mcp.json` (no `"disabled": true`). Do **not** run `python -m sieve.mcp.server` manually — Bob starts it.
