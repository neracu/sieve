"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
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
    # Enable the human-approval gate for privileged actions
    approval_gate_enabled: bool = True
    # Maximum characters of raw text stored per incident log entry
    incident_log_max_raw_chars: int = 2000

    # ── Dashboard / API ───────────────────────────────────────────────────────
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8000
    dashboard_debug: bool = False

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    # "json" for structured machine-readable output, "text" for human-readable
    log_format: str = "text"


settings = Settings()
