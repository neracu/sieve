# Sieve — Injection Tripwire 🛡️

> **A security Bob-module that detects, sanitises, and gates untrusted external
> content to protect AI agents from prompt-injection attacks.**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Overview

Sieve intercepts content from untrusted external sources — GitHub Issues, Pull
Request bodies, web pages, and README files — before it reaches an AI agent's
context window.  It routes each piece of content through a two-layer detection
pipeline:

| Layer | Detector | Mechanism |
|-------|----------|-----------|
| L1 | `L1HeuristicDetector` | Regex / pattern matching (zero latency, no external calls) |
| L2 | `L2WatsonxDetector` | IBM watsonx.ai / Granite semantic analysis (triggered on suspicious/malicious L1 hits) |

Flagged content is **quarantined** (wrapped with a safety header) or sent to a
**human approval gate** before the agent is allowed to act on it.  An incident
log is maintained and surfaced through a lightweight FastAPI dashboard.

---

## Architecture

```
External Content
      │
      ▼
 ┌──────────┐     ┌────────────────────┐     ┌───────────────────┐
 │  Hook    │────▶│  QuarantineWrapper │────▶│  Incident Log     │
 │ (GitHub/ │     │  L1 Heuristics     │     │  (IncidentLog)    │
 │  Web /   │     │  L2 watsonx.ai     │     └───────────────────┘
 │  README) │     └────────┬───────────┘
 └──────────┘              │
                           ▼
                   ┌───────────────┐
                   │ SAFE → pass   │
                   │ SUSPICIOUS →  │──▶ quarantined_text (tagged)
                   │   quarantine  │
                   │ MALICIOUS →   │──▶ ApprovalGate (human sign-off)
                   └───────────────┘
```

---

## Quick Start

```bash
# 1. Clone and enter
git clone https://github.com/your-org/sieve.git && cd sieve

# 2. Create venv and install
make install

# 3. Copy and fill in secrets
cp .env.example .env
# edit .env — set WATSONX_API_KEY, WATSONX_PROJECT_ID, GITHUB_TOKEN

# 4. Run tests
make test

# 5. Start the dashboard
make run-dashboard
# → http://127.0.0.1:8000/docs
```

---

## Project Structure

```
sieve/
├── core/            # Config, logging, shared Pydantic models
├── detectors/       # L1 heuristics + L2 watsonx.ai detectors
├── hooks/           # GitHub, web-fetch, and README interceptors
├── quarantine/      # Pipeline orchestrator + ScanResult container
├── approval/        # Human-in-the-loop approval gate
├── mcp/             # MCP server entry point (AI agent tool exposure)
└── dashboard/       # FastAPI REST backend for incident monitoring
tests/
├── conftest.py      # Shared pytest fixtures
├── test_sanity.py   # Bootstrap + unit + integration sanity tests
└── fixtures/        # Sample injection and legitimate content JSON
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WATSONX_API_KEY` | _(empty)_ | IBM watsonx.ai API key |
| `WATSONX_PROJECT_ID` | _(empty)_ | watsonx.ai project ID |
| `WATSONX_URL` | `https://us-south.ml.cloud.ibm.com` | watsonx.ai endpoint |
| `WATSONX_MODEL_ID` | `ibm/granite-13b-instruct-v2` | Granite model to use |
| `GITHUB_TOKEN` | _(empty)_ | GitHub PAT for authenticated API calls |
| `QUARANTINE_THRESHOLD` | `SUSPICIOUS` | Minimum risk level that triggers quarantine |
| `APPROVAL_GATE_ENABLED` | `true` | Enable human approval for MALICIOUS actions |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `LOG_FORMAT` | `text` | `text` (human) or `json` (structured) |
| `DASHBOARD_PORT` | `8000` | FastAPI dashboard port |

See [`.env.example`](.env.example) for the full list.

---

## Makefile Targets

| Target | Description |
|---|---|
| `make install` | Create venv and install dependencies |
| `make test` | Run the full pytest suite |
| `make test-sanity` | Run only the sanity tests |
| `make lint` | Run `ruff` linter |
| `make run-dashboard` | Start the FastAPI dashboard (dev mode) |
| `make run-mcp` | Start the MCP server (stdio) |
| `make clean` | Remove build artefacts and caches |

---

## Detection Patterns (L1)

The heuristic detector flags the following families of injection patterns:

- **Direct instruction overrides** — "ignore all previous instructions", "forget everything"
- **Role / persona hijacking** — "you are now", "act as", "pretend to be"
- **System-prompt leakage probes** — "reveal your system prompt", "print your instructions"
- **Data exfiltration triggers** — URLs with token/secret/key query params, "send all data to"
- **Privilege escalation** — "execute as root", "run as admin"
- **Header injection** — CRLF sequences followed by HTTP header names

All patterns are configurable in [`sieve/detectors/l1_heuristics.py`](sieve/detectors/l1_heuristics.py).

---

## Security Guardian mode

Bob can call this pipeline as an MCP server instead of hardcoding the checks into its own tools. The **Security Guardian** custom mode tells Bob to quarantine untrusted GitHub and web content, then wait for an operator approval before a privileged action that came from that content.

Setup, the mode switch, and the demo script are in [docs/security_guardian.md](docs/security_guardian.md). Start the server with `make run-mcp` or `python mcp_server.py`.

## License

MIT © IBM Hackathon Team
