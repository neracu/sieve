"""Shared Pydantic data models for Sieve."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────


class ContentSource(str, Enum):
    """Origin of the untrusted content being scanned."""

    GITHUB_ISSUE = "GITHUB_ISSUE"
    GITHUB_PR = "GITHUB_PR"
    WEB_FETCH = "WEB_FETCH"
    README = "README"


class RiskLevel(str, Enum):
    """Assessed risk level returned by a detector."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ActionTaken(str, Enum):
    """What Sieve did after detection."""

    ALLOWED = "ALLOWED"
    QUARANTINED = "QUARANTINED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"


class HookExecutionStatus(str, Enum):
    """High-level outcome returned by a guard hook to the caller.

    Maps from the lower-level :class:`ActionTaken` / :class:`RiskLevel` pair
    onto a simpler three-way signal that gate logic can act on directly:

    - ``CLEAN``       — content is safe; pass it to the agent unchanged.
    - ``QUARANTINED`` — injection patterns found; content is wrapped with a
                        warning header but the agent may still read it.
    - ``BLOCKED``     — content is so dangerous that the agent must NOT read
                        it; the pipeline should raise or abort the tool call.
    """

    CLEAN = "CLEAN"
    QUARANTINED = "QUARANTINED"
    BLOCKED = "BLOCKED"


# ── Core domain models ────────────────────────────────────────────────────────


class UntrustedContent(BaseModel):
    """Represents a piece of external content to be scanned."""

    id: UUID = Field(default_factory=uuid4)
    source: ContentSource
    raw_text: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    model_config = {"frozen": False}


class DetectionResult(BaseModel):
    """Output produced by a single detector pass."""

    content_id: UUID
    is_flagged: bool
    risk_level: RiskLevel
    detected_patterns: list[str] = Field(default_factory=list)
    raw_score: float = Field(ge=0.0, le=1.0, default=0.0)
    explanation: str = ""
    detector_name: str = ""

    model_config = {"frozen": True}


class IncidentLog(BaseModel):
    """Immutable record of a detected (or cleared) injection attempt."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    source: ContentSource
    risk_level: RiskLevel
    action_taken: ActionTaken
    detected_patterns: list[str] = Field(default_factory=list)
    raw_score: float = Field(ge=0.0, le=1.0, default=0.0)
    explanation: str = ""
    # Truncated raw content stored for forensics (length capped by config).
    raw_text_excerpt: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}


class ApprovalRequest(BaseModel):
    """Emitted by the approval gate when a privileged action needs sign-off."""

    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    action_description: str
    context_summary: str = ""
    approved: bool | None = None  # None = pending
    resolved_at: datetime | None = None
    resolved_by: str | None = None

    model_config = {"frozen": False}


class HookExecutionResult(BaseModel):
    """Structured result returned by every guard hook.

    Callers (MCP server, approval gate, dashboard) consume this rather than
    working with the lower-level :class:`~sieve.quarantine.wrapper.ScanResult`
    directly.
    """

    status: HookExecutionStatus
    source: ContentSource
    # The raw dict received from the upstream API (GitHub, etc.).
    original_payload: dict[str, Any]
    # Text that is safe to hand to the agent (may be quarantine-wrapped).
    processed_content: str
    # Aggregated detection result (highest-risk detector wins).
    detection_result: DetectionResult
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}
