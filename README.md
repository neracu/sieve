# Sieve — Injection Tripwire

**IBM Bob 2.0 Hackathon submission · lablab.ai**

---

## 1. Problem Statement

Modern coding agents — including IBM Bob, Claude Code, Gemini CLI, and GitHub Copilot — routinely read external content as part of normal maintenance work: fetching a GitHub issue to reproduce a bug, loading a PR for review, visiting a linked documentation page. That workflow is the attack surface.

This is a recurring pattern across multiple vendors, not an isolated incident. CVE-2026-55607 (GHSA-7835-87q9-rgvv, CVSS 7.7 High) — disclosed June 25, 2026, fixed in Claude Code 2.1.163 — demonstrated that a malicious repository containing prompt-injection content could steer Claude Code through Git worktree operations: creating a worktree named `.git`, exploiting symlink manipulation and fsmonitor execution, and writing to `~/.zshenv` to achieve code execution outside the seatbelt sandbox. The exploitation required cloning a malicious repo and running the agent against it — a routine operation in any code-review or onboarding workflow. Months later, CVE-2026-70335 (GHSA-w79w-rj9h-vg4f) disclosed an OS command injection in GitHub Copilot and VS Code allowing local privilege escalation, confirmed via Microsoft Security Response Center. Across both incidents the trigger was the same: content read from an external source was treated as instructions. A public audit of MCP configuration files found 24,000+ exposed secrets — further evidence that agents routinely handle external content without distinguishing data from directives.

The core failure mode is simple: **agents do not distinguish untrusted data from instructions**.

---

## 2. Solution Overview

Sieve intercepts external content Bob reads, scores it with a two-layer detector (L1 regex/heuristics + L2 deterministic composite score), and blocks or quarantines content before it can influence agent behavior — with a live dashboard showing every decision.

The L2 layer is a **deterministic, non-ML composite score**: POS-based imperative detection (spaCy), Shannon entropy over sliding windows, TF-IDF cosine similarity against a labeled injection corpus, and structural position flags (hidden HTML comments, Markdown image/link titles, tail-position payloads). These four signals are combined with a fixed weighted sum; the same input always produces the same output. This is a deliberate design choice. An LLM-based classifier would itself be a prompt-injection target and would add an external API dependency to the security path. A deterministic function is explainable, auditable, and not vulnerable to adversarial manipulation of the classifier itself.

---

## 3. Architecture

```
Bob (agent)
    │
    │  tool call: quarantine_check(content, source)
    ▼
MCP Server  (sieve-security-guardian, stdio or HTTP)
    │
    ├─► Guard Hook  (source-aware: github_issue / github_pr / web_fetch / readme)
    │
    ├─► L1 Heuristic Detector
    │       regex / heuristics, 45+ patterns, sub-millisecond
    │
    ├─► L2 Composite Detector
    │       POS imperative ratio · Shannon entropy · TF-IDF similarity · structural flags
    │       deterministic weighted sum, no external calls
    │
    ▼
QuarantineWrapper  →  decision: ALLOWED / BLOCKED / PENDING_APPROVAL
    │
    ├─► Audit log  (append-only JSONL, SIEVE_AUDIT_LOG_PATH)
    │
    ├─► MCP Resources:  resource://audit-log
    │                   resource://pending-approvals
    │                   resource://privileged-actions
    │
    └─► Dashboard Backend  (polls MCP resources, ~1 s)
            │
            ├─► GET /incidents          (REST, filter + paginate)
            ├─► GET /incidents/{id}
            ├─► GET /incidents/stream   (Server-Sent Events)
            └─► GET /dashboard          (single-page UI)
```

### MCP tools

| Tool | Purpose |
|---|---|
| `scan_content` | Risk assessment only — does not block or return the body |
| `quarantine_check` | Full quarantine decision — blocked results withhold the text |
| `request_approval` | Register a privileged action with the approval gate |
| `check_approval_status` | Poll for `pending`, `approved`, `rejected`, or `timed_out` |
| `approve_action` | Operator-only: approve a pending request by ID |
| `reject_action` | Operator-only: reject a pending request by ID |

### MCP resources

| Resource | Contents |
|---|---|
| `resource://audit-log` | Recent quarantine and approval decisions (no raw content) |
| `resource://pending-approvals` | Approval requests still waiting |
| `resource://privileged-actions` | Read-only registry of privileged actions and risk tiers |

### Custom Mode: Security Guardian

`.bob/custom_modes.yaml` defines a **Security Guardian** mode. When active, Bob is instructed to call `quarantine_check` on every GitHub issue body, PR body, and `web_fetch` result before treating the content as instructions or acting on it. If the result is `blocked`, Bob stops and reports the reason, detector, and risk score. If the result is `passed`, Bob may summarize the content but must still call `request_approval` with `origin=untrusted` before executing any privileged action derived from it.

Privileged actions named in the mode instructions: `file_write`, `file_delete`, `git_commit`, `git_push`, `shell`, `shell_exec`, `run_command`, `send_message`, `external_api_call`, `cicd_config_change`, `credential_access`. Unknown action names are also treated as privileged.

**Confirmed scope:** this works in Agent mode and Security Guardian mode when Bob is instructed (via prompt or via the custom mode) to route untrusted content through `quarantine_check`. It is not a transparent interception of every native Bob tool call at the dispatcher level without Bob being instructed to call it.

---

## 4. Detection Details

### L1 — Heuristic detector

Regex-based, runs entirely locally with no external calls. 45+ compiled patterns across 13 categories:

1. Imperative override phrasings (`ignore previous instructions`, `disregard all prior rules`, …)
2. System/AI override commands (`system override`, `new system prompt`, `reset your context`, …)
3. Role/persona hijacking (`you are now a …`, `act as …`, `pretend you are …`)
4. System-prompt leakage probes (`reveal your prompt`, `print secrets`, `output encoded …`)
5. Env/credential file exfiltration (`read .env`, `dump environment variables`, …)
6. Credential/secret exfiltration (`leak api keys`, `send secrets to …`, `dump credentials`)
7. Privilege escalation (`execute as root`, `run as sudo`, …)
8. Hidden HTML markup (HTML comments, CSS `display:none`, `aria-hidden`, `hidden` attribute)
9. Zero-width / invisible Unicode (U+200B, U+200C, U+200D, U+FEFF, U+2060, and related)
10. Encoded payload indicators (base64 blobs ≥ 20 chars that decode to injection keywords)
11. System-bracket prefixes and fake errors (`[SYSTEM NOTE: …]`, `[SYSTEM ERROR: …]`, `security constraints bypassed`)
12. Shell/OS command exfiltration (`curl -X POST`, `cat ~/.ssh/…`, `rm -rf /…`, `process.env`, `exfiltrate`)
13. CRLF / header injection

**Scoring:** each malicious pattern hit contributes 0.15 to the raw score; suspicious hits contribute 0.10. A single malicious hit floors the score at 0.70 (guaranteed `MALICIOUS`). Thresholds: ≥ 0.70 → MALICIOUS, ≥ 0.30 → SUSPICIOUS, < 0.30 → SAFE.

The scanner also strips zero-width characters from the input before matching, so interleaved invisible characters cannot defeat phrase detection.

### L2 — Composite detector

Four normalized signals combined with a fixed weighted sum:

| Signal | Weight | Method |
|---|---|---|
| POS imperative ratio | 0.30 | spaCy `en_core_web_sm` — base-form verbs with no explicit subject; regex verb lexicon fallback when spaCy is absent |
| Shannon entropy anomaly | 0.05 | Max of 64-char sliding windows; threshold 4.60 bits/char on low-space, base64-alphabet windows |
| TF-IDF cosine similarity | 0.60 | Bigram TF-IDF, max cosine similarity over 480-char chunks against the 9-fixture injection corpus |
| Structural context | 0.05 | HTML comments with injection phrases, Markdown hidden comments, image/link title payloads, tail-position injection |

`risk = 0.30 × POS + 0.05 × Entropy + 0.60 × TFIDF + 0.05 × Structural`

Thresholds: ≥ 0.50 → MALICIOUS, ≥ 0.30 → SUSPICIOUS. A confirmed entropy anomaly floors risk at 0.35 (above SUSPICIOUS); a confirmed tail payload floors risk at 0.50 (MALICIOUS).

The POS contribution is capped at 0.25 unless the text also matches the L1 injection-phrase vocabulary. This prevents legitimate imperative phrasing in normal maintainer text (`"Please review this PR"`, `"Run the tests before merging"`) from being scored as suspicious by the POS signal alone.

**Calibration:** weights were chosen by exhaustive sweep against a 35-row labeled fixture set — 9 malicious injection payloads and 26 legitimate maintainer sentences and paragraphs. All 9 injection fixtures score at or above the MALICIOUS threshold. False-positive rate on the 26 legitimate samples: **0/26 (0.00)**.

### Fail-closed guarantee

Any detector exception or classification failure causes the `QuarantineWrapper` to return `BLOCKED` with `body=None`. The exception is logged but never re-raised to the caller, and the raw content is never passed through on error.

---

## 5. Live Demo / Dashboard

The dashboard is a single-page live view served at `GET /dashboard`. It shows incidents in real time via Server-Sent Events — no manual refresh is needed; new blocks and quarantine events appear automatically as they occur.

Each row shows: incident type, source (github_issue / github_pr / web_fetch / readme), detector that fired (L1 / L2 / both), risk score, status, and timestamp. The view is filterable by status (All / Blocked / Pending Approval).

### Incidents API

| Endpoint | Description |
|---|---|
| `GET /incidents` | List incidents with optional `status`, `type`, `source`, `since` filters and `limit`/`offset` pagination |
| `GET /incidents/{id}` | Single incident by ID |
| `GET /incidents/stream` | Server-Sent Events stream; pushes `snapshot` on connect, then `upsert` events on change |

The dashboard backend reads `resource://audit-log` and `resource://pending-approvals` from the MCP server approximately once per second and merges them into a persistent JSONL file. `GET /incidents` and `GET /incidents/{id}` read from the in-memory store backed by that file. **These endpoints work even when the MCP server is down** — they return whatever was previously persisted. When the MCP server is unreachable, `GET /incidents/summary` returns 503 and the SSE stream emits `mcp_status` events.

---

## 6. Tech Stack

- **Python 3.11+**
- **FastAPI** — MCP HTTP transport and dashboard backend
- **spaCy** (`en_core_web_sm`) — POS tagging for L2 imperative detection
- **scikit-learn** — TF-IDF vectorizer and cosine similarity for L2
- **MCP** (`mcp>=1.13`) — Model Context Protocol server (stdio and streamable HTTP)
- **JSONL file-based persistence** — audit log and incidents store; no database required
- **Server-Sent Events** — live incident stream to the dashboard
- **Vanilla HTML/CSS/JS dashboard** — no frontend framework

---

## 7. Known Limitations

These are stated explicitly, not as failures but as the honest current scope.

- **Custom Mode enforcement is instructional, not structural.** The Security Guardian mode and prompt instructions tell Bob to call `quarantine_check` before treating external content as instructions. This is confirmed to work in Agent mode and Security Guardian mode. It is not yet a transparent, syscall-level interception that fires regardless of whether Bob was instructed to use it.

- **Not every external-content read path is covered.** The demonstrated and tested paths are: GitHub issue body, issue comments, PR body, PR review comments, PR diff, `web_fetch`, and local README/Markdown reads. Arbitrary tool names outside the known allowlist, and a full repository-clone path, are not currently wired through the guard.

- **Conservative SUSPICIOUS classification is intentional.** Some legitimate text containing security-related nouns and imperative phrasing may be classified as SUSPICIOUS and routed to pending-approval rather than auto-allowed. This is a deliberate fail-safe tradeoff. It is not a silent false block: the quarantine header explains the reason and the operator can approve. The 0/26 false-positive rate applies to the 26-sample calibration set; real-world rates depend on input distribution.

- **Approval enforcement relies on Bob following the gate protocol.** An adversarial or misconfigured agent could bypass `request_approval` the same way it could bypass any instructed step. The gate is a countermeasure, not a hard sandbox.

---

## 8. How to Run

### Prerequisites

- Python 3.11+
- (Optional) `GITHUB_TOKEN` for live GitHub issue/PR fetches

### Install

```bash
git clone <repo-url>
cd sieve-ibmbobhackathon

python3 -m venv .venv
source .venv/bin/activate

make install
# or: pip install -r requirements.txt && pip install -e .

# Download the spaCy model (required for L2 POS detection)
python -m spacy download en_core_web_sm
```

### Environment variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `SIEVE_AUDIT_LOG_PATH` | `sieve_audit.log` | Append-only quarantine audit log |
| `SIEVE_INCIDENTS_PATH` | `sieve_incidents.jsonl` | Dashboard incident persistence |
| `SIEVE_MCP_URL` | `http://127.0.0.1:8081/mcp` | MCP server URL for the dashboard backend |
| `GITHUB_TOKEN` | _(empty)_ | GitHub API access for live issue/PR fetches |
| `QUARANTINE_THRESHOLD` | `SUSPICIOUS` | Minimum risk level that triggers quarantine |

### Start the MCP server

**Stdio transport** (used by Bob via `.bob/mcp.json`):

```bash
python -m sieve.mcp.server
# or: make run-mcp
```

**Streamable HTTP transport** (required by the dashboard backend):

```bash
python mcp_server.py --http
# Serves on http://127.0.0.1:8081/mcp by default
# Set PORT env var to override
```

### Start the dashboard

In a separate terminal (with the HTTP MCP server already running):

```bash
make run-dashboard
# or: uvicorn sieve.dashboard.dashboard_backend:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/dashboard` in a browser.

### Register with Bob

The MCP server is pre-configured in [`.bob/mcp.json`](.bob/mcp.json) for stdio transport. Bob will discover and connect to it automatically when the workspace is opened.

To use the **Security Guardian** custom mode, open Bob's mode selector and choose "Security Guardian". The mode definition is in [`.bob/custom_modes.yaml`](.bob/custom_modes.yaml).

### Run tests

```bash
make test
# or: pytest tests/ -v
```

### Demo reset

```bash
make reset-demo
# Truncates sieve_incidents.jsonl and sieve_audit.log to empty
```

---

## Project Structure

```
sieve/
├── core/          # Config, types, logger
├── detectors/     # L1 heuristics, L2 composite
├── quarantine/    # Wrapper (pipeline orchestrator), audit log
├── approval/      # Approval gate, privileged-action registry
├── hooks/         # GitHub, web_fetch, README guard hooks
├── mcp/           # MCP server (guardian.py = FastMCP server, server.py = dispatcher)
└── dashboard/     # Dashboard backend (SSE + REST), static HTML
tests/
├── fixtures/      # Labeled injection corpus + calibration set
└── ...            # Unit and integration tests
.bob/
├── mcp.json           # MCP server registration for Bob
├── custom_modes.yaml  # Security Guardian mode definition
└── rules-security-guardian/
    └── 01-policy.md   # Mode policy rules
```
