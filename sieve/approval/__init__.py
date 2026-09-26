"""Sieve approval — human-in-the-loop gate for privileged actions."""

from sieve.approval.approval_gate import (
    ApprovalGate,
    ApprovalNotFoundError,
    Origin,
    Provenance,
    approval_gate,
    untrusted_origin,
)

__all__ = [
    "ApprovalGate",
    "ApprovalNotFoundError",
    "Origin",
    "Provenance",
    "approval_gate",
    "untrusted_origin",
]
