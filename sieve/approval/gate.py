"""Approval gate — blocks privileged actions until a human approves.

When the quarantine pipeline marks an action as :attr:`ActionTaken.PENDING_APPROVAL`,
the agent must call :meth:`ApprovalGate.request` before proceeding.  The gate
stores the request in an in-process registry (swappable for a DB-backed store)
and raises :exc:`ApprovalPendingError` until the request is explicitly
resolved.

In production, pair this with the Dashboard ``/api/approvals`` endpoints so
that a security operator can approve or reject requests via the UI or API.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from uuid import UUID

from sieve.core.config import settings
from sieve.core.logger import get_logger
from sieve.core.types import ApprovalRequest, IncidentLog

log = get_logger(__name__)


class ApprovalPendingError(Exception):
    """Raised when an action requires approval that has not yet been granted."""

    def __init__(self, request: ApprovalRequest) -> None:
        self.request = request
        super().__init__(
            f"Action '{request.action_description}' is pending approval "
            f"(request id: {request.id})."
        )


class ApprovalDeniedError(Exception):
    """Raised when an approval request has been explicitly denied."""

    def __init__(self, request: ApprovalRequest) -> None:
        self.request = request
        super().__init__(
            f"Action '{request.action_description}' was denied "
            f"(request id: {request.id})."
        )


class ApprovalGate:
    """Manage approval requests for privileged agent actions.

    This is a thread-safe, in-memory implementation suitable for single-process
    deployments.  Swap :attr:`_store` for a Redis/DB-backed mapping in
    production multi-process environments.
    """

    def __init__(self) -> None:
        self._store: dict[UUID, ApprovalRequest] = {}
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def request(
        self,
        incident: IncidentLog,
        action_description: str,
        *,
        context_summary: str = "",
    ) -> ApprovalRequest:
        """Create a new approval request and raise :exc:`ApprovalPendingError`.

        The caller must catch this exception and surface it to the operator.
        Re-call :meth:`check` once the operator has resolved the request.

        Args:
            incident:           The :class:`~sieve.core.types.IncidentLog` that
                                triggered the gate.
            action_description: Short description of the privileged action.
            context_summary:    Optional extra context for the reviewer.

        Raises:
            ApprovalPendingError: Always (the request is pending on creation).
        """
        req = ApprovalRequest(
            incident_id=incident.id,
            action_description=action_description,
            context_summary=context_summary,
        )
        with self._lock:
            self._store[req.id] = req
        log.warning(
            "Approval requested.",
            extra={
                "request_id": str(req.id),
                "incident_id": str(req.incident_id),
                "action": action_description,
            },
        )
        raise ApprovalPendingError(req)

    def check(self, request_id: UUID) -> ApprovalRequest:
        """Check the status of an existing approval request.

        Args:
            request_id: The UUID of the :class:`~sieve.core.types.ApprovalRequest`.

        Returns:
            The approved :class:`~sieve.core.types.ApprovalRequest`.

        Raises:
            KeyError:             If *request_id* is unknown.
            ApprovalPendingError: If the request has not yet been resolved.
            ApprovalDeniedError:  If the request was denied.
        """
        with self._lock:
            req = self._store[request_id]

        if req.approved is None:
            raise ApprovalPendingError(req)
        if req.approved is False:
            raise ApprovalDeniedError(req)
        return req

    def approve(self, request_id: UUID, *, resolved_by: str = "operator") -> ApprovalRequest:
        """Approve a pending request.

        Args:
            request_id:  UUID of the pending :class:`~sieve.core.types.ApprovalRequest`.
            resolved_by: Identity of the approver (e.g. username).

        Returns:
            The updated (approved) :class:`~sieve.core.types.ApprovalRequest`.
        """
        return self._resolve(request_id, approved=True, resolved_by=resolved_by)

    def deny(self, request_id: UUID, *, resolved_by: str = "operator") -> ApprovalRequest:
        """Deny a pending request.

        Args:
            request_id:  UUID of the pending :class:`~sieve.core.types.ApprovalRequest`.
            resolved_by: Identity of the denier (e.g. username).

        Returns:
            The updated (denied) :class:`~sieve.core.types.ApprovalRequest`.

        Raises:
            ApprovalDeniedError: After recording the denial.
        """
        req = self._resolve(request_id, approved=False, resolved_by=resolved_by)
        raise ApprovalDeniedError(req)

    def list_pending(self) -> list[ApprovalRequest]:
        """Return all requests that have not yet been resolved."""
        with self._lock:
            return [r for r in self._store.values() if r.approved is None]

    def list_all(self) -> list[ApprovalRequest]:
        """Return all requests (pending and resolved)."""
        with self._lock:
            return list(self._store.values())

    # ── Internals ─────────────────────────────────────────────────────────────

    def _resolve(
        self,
        request_id: UUID,
        *,
        approved: bool,
        resolved_by: str,
    ) -> ApprovalRequest:
        with self._lock:
            req = self._store[request_id]
            updated = req.model_copy(
                update={
                    "approved": approved,
                    "resolved_at": datetime.now(tz=timezone.utc),
                    "resolved_by": resolved_by,
                }
            )
            self._store[request_id] = updated
        log.info(
            "Approval request resolved.",
            extra={
                "request_id": str(request_id),
                "approved": approved,
                "resolved_by": resolved_by,
            },
        )
        return updated


# Module-level singleton used by the MCP server and dashboard.
gate = ApprovalGate()
