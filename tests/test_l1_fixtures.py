"""Parameterized fixture-driven tests for L1Detector.

Loads every entry from ``tests/fixtures/injections.json`` and asserts that
``L1Detector.scan()`` flags each payload as injection (is_flagged=True,
risk_level in SUSPICIOUS|MALICIOUS).

Any fixture miss produces a detailed failure message listing the fixture id,
type, payload excerpt, raw score, and which patterns *were* matched so the
gap can be diagnosed and a new regex rule added immediately.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from sieve.core.types import RiskLevel
from sieve.detectors.l1_heuristics import L1Detector

# ---------------------------------------------------------------------------
# Load fixtures at collection time
# ---------------------------------------------------------------------------

_FIXTURES_PATH = Path(__file__).parent / "fixtures" / "injections.json"

_RAW_FIXTURES: list[dict] = json.loads(_FIXTURES_PATH.read_text(encoding="utf-8"))

# Build pytest parameter list: each item is (id, type, payload)
_PARAMS = [
    pytest.param(
        item["id"],
        item.get("type", "unknown"),
        item["payload"],
        id=item["id"],
    )
    for item in _RAW_FIXTURES
]

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Parameterized detection test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_id,fixture_type,payload", _PARAMS)
def test_l1_detects_injection_fixture(fixture_id: str, fixture_type: str, payload: str) -> None:
    """Every fixture in injections.json must be flagged by L1Detector.

    Failure message includes enough context to pinpoint the missing regex rule.
    """
    detector = L1Detector()
    result = run(detector.scan(payload, source=f"fixture:{fixture_id}"))

    # Build a rich diagnostic if the assertion fails
    excerpt = payload[:120].replace("\n", " ")
    diagnostic = (
        f"\n"
        f"  Fixture  : {fixture_id} ({fixture_type})\n"
        f"  Payload  : {excerpt!r}{'…' if len(payload) > 120 else ''}\n"
        f"  Score    : {result.raw_score:.4f}\n"
        f"  RiskLevel: {result.risk_level}\n"
        f"  Patterns : {result.detected_patterns or '(none)'}\n"
        f"\n"
        f"  ACTION REQUIRED: add a regex rule to l1_heuristics.py to cover this vector."
    )

    assert result.is_flagged, f"[MISS] L1 failed to flag {fixture_id} ({fixture_type}){diagnostic}"
    assert result.risk_level in (
        RiskLevel.SUSPICIOUS,
        RiskLevel.MALICIOUS,
    ), f"Expected SUSPICIOUS or MALICIOUS for {fixture_id}, got {result.risk_level}{diagnostic}"


# ---------------------------------------------------------------------------
# Aggregate detection-rate test (convenience — fails fast if < 100 %)
# ---------------------------------------------------------------------------


def test_l1_fixture_detection_rate_100_percent() -> None:
    """Sanity check: ALL fixtures must be detected (100 % rate)."""
    detector = L1Detector()
    total = len(_RAW_FIXTURES)
    misses: list[str] = []

    for item in _RAW_FIXTURES:
        result = run(detector.scan(item["payload"]))
        if not result.is_flagged:
            misses.append(f"  - {item['id']} ({item.get('type', 'unknown')}): score={result.raw_score:.4f}")

    if misses:
        miss_list = "\n".join(misses)
        pytest.fail(
            f"L1 missed {len(misses)}/{total} fixtures:\n{miss_list}\n\n"
            "Add regex rules to sieve/detectors/l1_heuristics.py to cover these vectors."
        )


# ---------------------------------------------------------------------------
# Per-type group tests (explicit assertions for each fixture category)
# ---------------------------------------------------------------------------


class TestFixtureByType:
    """Each method tests a specific vector category from the fixture set.

    These complement the parameterized tests above with targeted checks on
    risk level expectations per category.
    """

    def _get_payload(self, fixture_id: str) -> str:
        for item in _RAW_FIXTURES:
            if item["id"] == fixture_id:
                return item["payload"]
        raise KeyError(f"Fixture {fixture_id!r} not found")

    def _scan(self, fixture_id: str):
        det = L1Detector()
        return run(det.scan(self._get_payload(fixture_id), source=fixture_id))

    def test_inj_01_direct_override_malicious(self):
        """[SYSTEM NOTE: ...] bracket prefix is MALICIOUS."""
        result = self._scan("inj_01")
        assert result.is_flagged
        assert result.risk_level == RiskLevel.MALICIOUS

    def test_inj_02_exfiltration_shell_malicious(self):
        """curl -X POST + process.env is MALICIOUS."""
        result = self._scan("inj_02")
        assert result.is_flagged
        assert result.risk_level == RiskLevel.MALICIOUS

    def test_inj_03_hidden_html_comment_flagged(self):
        """HTML comment carrying system override is flagged."""
        result = self._scan("inj_03")
        assert result.is_flagged
        assert "HIDDEN_HTML_COMMENT" in result.detected_patterns or result.risk_level == RiskLevel.MALICIOUS

    def test_inj_04_base64_obfuscation_malicious(self):
        """Base64-encoded instruction override is decoded and flagged."""
        result = self._scan("inj_04")
        assert result.is_flagged
        assert "ENCODED_PAYLOAD_BASE64" in result.detected_patterns

    def test_inj_05_zero_width_unicode_malicious(self):
        """Zero-width unicode sequence (≥4 chars) is MALICIOUS."""
        result = self._scan("inj_05")
        assert result.is_flagged
        assert result.risk_level == RiskLevel.MALICIOUS

    def test_inj_06_fake_system_error_malicious(self):
        """Fake system error with bypass claim and rm -rf is MALICIOUS."""
        result = self._scan("inj_06")
        assert result.is_flagged
        assert result.risk_level == RiskLevel.MALICIOUS
        # Expect multiple patterns matched
        assert len(result.detected_patterns) >= 2

    def test_inj_07_markdown_image_payload_malicious(self):
        """Image tooltip injection is MALICIOUS (text contains patterns)."""
        result = self._scan("inj_07")
        assert result.is_flagged
        assert result.risk_level == RiskLevel.MALICIOUS

    def test_inj_08_malicious_readme_script_malicious(self):
        """README with web_fetch call and hidden md comment is MALICIOUS."""
        result = self._scan("inj_08")
        assert result.is_flagged
        assert result.risk_level == RiskLevel.MALICIOUS

    def test_inj_09_jailbreak_debug_mode_malicious(self):
        """DAN/developer mode jailbreak is MALICIOUS."""
        result = self._scan("inj_09")
        assert result.is_flagged
        assert result.risk_level == RiskLevel.MALICIOUS
