"""FastAPI dashboard backend for Sieve.

Provides REST endpoints for:

- Listing incident logs (GET /api/incidents)
- Listing pending approval requests (GET /api/approvals)
- Approving an action (POST /api/approvals/{id}/approve)
- Denying an action (POST /api/approvals/{id}/deny)
- Health check (GET /health)

Run with::

    uvicorn sieve.dashboard.api:app --host 127.0.0.1 --port 8000 --reload
    # or via Makefile:
    make run-dashboard
"""

from __future__ import annotations

from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from sieve.approval.approval_gate import install_approval_gate
from sieve.approval.gate import ApprovalDeniedError, ApprovalPendingError, gate
from sieve.core.config import settings
from sieve.core.logger import configure_logging, get_logger
from sieve.core.types import ApprovalRequest, IncidentLog

configure_logging(level=settings.log_level, fmt=settings.log_format)
log = get_logger(__name__)

app = FastAPI(
    title="Sieve — Injection Tripwire Dashboard",
    version="0.1.0",
    description="Security dashboard for monitoring and managing AI prompt-injection incidents.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
install_approval_gate(app)

# ---------------------------------------------------------------------------
# In-memory incident store (TODO: replace with persistent storage)
# ---------------------------------------------------------------------------
_incident_store: list[IncidentLog] = []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["ops"])
def health() -> dict:
    """Simple liveness probe."""
    return {"status": "ok", "service": "sieve"}


@app.get("/api/incidents", response_model=list[IncidentLog], tags=["incidents"])
def list_incidents(limit: int = 100, offset: int = 0) -> list[IncidentLog]:
    """Return recent incident logs, newest first.

    Args:
        limit:  Maximum number of incidents to return (default 100).
        offset: Pagination offset.
    """
    sorted_incidents = sorted(_incident_store, key=lambda i: i.timestamp, reverse=True)
    return sorted_incidents[offset : offset + limit]


@app.post("/api/incidents", response_model=IncidentLog, tags=["incidents"], status_code=201)
def record_incident(incident: IncidentLog) -> IncidentLog:
    """Record a new incident log entry.

    Called internally by the Sieve pipeline (or the MCP server) after a scan.
    """
    _incident_store.append(incident)
    log.info("Incident recorded.", extra={"incident_id": str(incident.id), "risk_level": incident.risk_level})
    return incident


@app.get("/api/approvals", response_model=list[ApprovalRequest], tags=["approvals"])
def list_approvals(pending_only: bool = True) -> list[ApprovalRequest]:
    """Return approval requests.

    Args:
        pending_only: When True (default) return only unresolved requests.
    """
    return gate.list_pending() if pending_only else gate.list_all()


@app.post("/api/approvals/{request_id}/approve", response_model=ApprovalRequest, tags=["approvals"])
def approve_action(request_id: UUID, resolved_by: str = "operator") -> ApprovalRequest:
    """Approve a pending privileged-action request."""
    try:
        return gate.approve(request_id, resolved_by=resolved_by)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Approval request {request_id} not found.")


@app.post("/api/approvals/{request_id}/deny", response_model=ApprovalRequest, tags=["approvals"])
def deny_action(request_id: UUID, resolved_by: str = "operator") -> ApprovalRequest:
    """Deny a pending privileged-action request."""
    try:
        gate.deny(request_id, resolved_by=resolved_by)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Approval request {request_id} not found.")
    except ApprovalDeniedError as exc:
        return exc.request
    raise HTTPException(status_code=500, detail="Unexpected error resolving denial.")


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "sieve.dashboard.api:app",
        host=settings.dashboard_host,
        port=settings.dashboard_port,
        reload=settings.dashboard_debug,
    )
