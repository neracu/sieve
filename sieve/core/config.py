"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    # ── IBM watsonx.ai ────────────────────────────────────────────────────────
    watsonx_api_key: str = ""
    watsonx_project_id: str = ""
    watsonx_url: str = "https://us-south.ml.cloud.ibm.com"
    watsonx_model_id: str = "ibm/granite-13b-instruct-v2"
    # Alias expected by the task spec (GRANITE_MODEL_ID env var maps here too)
    granite_model_id: str = "ibm/granite-13b-instruct-v2"
    # When True, skip the live API and use a deterministic local mock classifier
    use_mock_watsonx: bool = True

    # ── GitHub ────────────────────────────────────────────────────────────────
    github_token: str = ""

    # ── Sieve behaviour ───────────────────────────────────────────────────────
    # Minimum risk level that triggers quarantine ("SUSPICIOUS" or "MALICIOUS")
    quarantine_threshold: str = "SUSPICIOUS"
    # L2 composite score threshold (0.0–1.0).  Scores at or above this value
    # are treated as MALICIOUS regardless of the risk-level enum produced by
    # L2CompositeDetector's own thresholds.  Set to 1.1 to disable.
    l2_score_threshold: float = 0.50
    # Enable the human-approval gate for privileged actions
    approval_gate_enabled: bool = True
    # Seconds a paused action waits before it is denied. Timeout denies.
    approval_timeout_seconds: float = 300.0
    # When False, a direct user instruction may run a privileged action.
    approval_pause_on_trusted: bool = False
    # Risk tiers that pause when the triggering content is untrusted.
    approval_tiers: str = "low,medium,high"
    # Maximum characters of raw text stored per incident log entry
    incident_log_max_raw_chars: int = 2000
    # Path to the append-only audit log for blocked/quarantined events.
    # SIEVE_AUDIT_LOG_PATH is preferred. AUDIT_LOG_PATH is the older name.
    # Set to "" to disable file-based audit logging.
    audit_log_path: str = Field(
        default="sieve_audit.log",
        validation_alias=AliasChoices("SIEVE_AUDIT_LOG_PATH", "AUDIT_LOG_PATH"),
    )

    # ── Dashboard / API ───────────────────────────────────────────────────────
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8000
    dashboard_debug: bool = False

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    # "json" for structured machine-readable output, "text" for human-readable
    log_format: str = "text"


settings = Settings()
