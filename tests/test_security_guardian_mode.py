"""The Security Guardian prompt keeps the rules Bob has to follow."""

from pathlib import Path

_ROOT = Path(__file__).parents[1]
_POLICY = _ROOT / ".bob" / "rules-security-guardian" / "01-policy.md"
_MODE = _ROOT / ".bob" / "custom_modes.yaml"
_MCP = _ROOT / ".bob" / "mcp.json"

_REQUIRED = (
    "quarantine_check",
    "request_approval",
    "check_approval_status",
    "approve_action",
    "ignore previous instructions",
    "approval already granted",
    "SYSTEM:",
    "Do not retry",
    "operator's own",
    "Do not fabricate approval",
)


def test_mode_files_keep_the_security_rules():
    policy = _POLICY.read_text(encoding="utf-8")
    mode = _MODE.read_text(encoding="utf-8")
    assert "slug: security-guardian" in mode
    assert "mcp" in mode
    for phrase in _REQUIRED:
        assert phrase in policy
        assert phrase in mode


def test_project_mcp_registration_uses_stdio():
    text = _MCP.read_text(encoding="utf-8")
    assert "sieve-security-guardian" in text
    assert "sieve.mcp.server" in text
