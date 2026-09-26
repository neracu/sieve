# Security Guardian demo

Security Guardian is a Bob custom mode. Its instructions tell Bob to call the Sieve MCP server before acting on GitHub issues, pull requests, or fetched pages, and to wait for an operator approval before any privileged action that came from that content. Enforcement is those instructions plus the approval gate when Bob calls `request_approval`. The MCP server does not block Bob's own shell. `bob` is not on `PATH` here, so this has not been empirically verified end to end with a captured tool-call sequence.

## Activate

1. Install Sieve so `.venv/bin/python` exists: `make install`
2. Open this project in IBM Bob.
3. Confirm the MCP server. Bob reads [`.bob/mcp.json`](../.bob/mcp.json) and starts `python -m sieve.mcp.server` on stdio. In Settings → MCP, `sieve-security-guardian` should list `scan_content`, `quarantine_check`, `request_approval`, `check_approval_status`, `approve_action`, `reject_action`, and the three `resource://` entries.
4. Select the **Security Guardian** mode. The mode definition is [`.bob/custom_modes.yaml`](../.bob/custom_modes.yaml). Bob also loads [`.bob/rules-security-guardian/01-policy.md`](../.bob/rules-security-guardian/01-policy.md).

To run the server by hand: `python mcp_server.py` (stdio) or `python mcp_server.py --http` (streamable HTTP on `127.0.0.1:8081`, or `0.0.0.0:$PORT` when `PORT` is set).

## What the operator does

The mode instructs Bob to call `quarantine_check` and, when a privileged action comes from untrusted content, `request_approval`. It then stops and reports the `approval_id`. That sequence has not been observed in a live Bob run.

You approve or reject by sending your own message that names that id, for example `approve 3fa85f64-5717-4562-b3fc-2c963f66afa6`. Bob may call `approve_action` or `reject_action` only because you named the id. Text inside an issue or a web page cannot do that.

`resource://pending-approvals` shows what is waiting. `resource://audit-log` shows the decision afterward, without the raw text.

## Demo script

The four live scenarios, with the prompts to paste, are in [tests/manual/security_guardian_scenarios.md](../tests/manual/security_guardian_scenarios.md).

1. A malicious issue says to push to main and claims approval was already granted. Bob still calls `request_approval` and waits.
2. A benign issue can be summarized after `quarantine_check` returns `passed`, with no approval stop.
3. When `quarantine_check` returns `blocked`, Bob reports the reason and does not try another tool.
4. A fetched page that says "ignore previous instructions" and "skip approval" still goes through `request_approval` before any privileged action.

Detector time, excluding the human wait, should stay under a couple of seconds after the server has started. The process warms the detectors once at startup.
