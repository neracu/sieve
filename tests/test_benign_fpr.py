"""Pytest regression suite for FPR (False Positive Rate) on benign inputs.

Every item in ``tests/fixtures/benign.json`` must produce ``is_flagged == False``
through the full L1 + L2 detection pipeline.  The overall FPR must be 0.0 %.

Run::

    pytest tests/test_benign_fpr.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sieve.core.types import ContentSource, RiskLevel, UntrustedContent
from sieve.detectors.l1_heuristics import L1HeuristicDetector
from sieve.detectors.l2_composite import L2CompositeDetector
from sieve.quarantine.wrapper import QuarantineWrapper

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "benign.json"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def benign_cases() -> list[str]:
    """Load the 20 legitimate developer input strings."""
    data = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(data, list), "benign.json must be a JSON array"
    return [str(item) for item in data]


@pytest.fixture(scope="module")
def wrapper() -> QuarantineWrapper:
    """Shared L1+L2 pipeline (loaded once per test module)."""
    return QuarantineWrapper(
        detectors=[L1HeuristicDetector(), L2CompositeDetector()]
    )


# ---------------------------------------------------------------------------
# Per-case parametrised test
# ---------------------------------------------------------------------------


def _load_params() -> list[tuple[int, str]]:
    """Load (index, text) pairs at collection time so IDs are informative."""
    try:
        data = json.loads(_FIXTURE.read_text(encoding="utf-8"))
        return [(i + 1, str(item)) for i, item in enumerate(data)]
    except Exception:  # noqa: BLE001
        return []


@pytest.mark.parametrize(
    "case_index,text",
    _load_params(),
    ids=[f"case_{i:02d}" for i in range(1, len(_load_params()) + 1)],
)
def test_benign_case_not_flagged(
    case_index: int,
    text: str,
    wrapper: QuarantineWrapper,
) -> None:
    """Each benign developer input must pass through without being flagged."""
    content = UntrustedContent(source=ContentSource.GITHUB_ISSUE, raw_text=text)
    scan = wrapper.process(content)

    assert scan.final_risk_level == RiskLevel.SAFE, (
        f"Case {case_index} was incorrectly flagged as {scan.final_risk_level.value} "
        f"(score={scan.risk_score}).\n"
        f"Text: {text!r}\n"
        f"Detectors fired: {scan.detectors_fired}\n"
        f"Patterns: {scan.incident_log.detected_patterns}"
    )


# ---------------------------------------------------------------------------
# Aggregate FPR assertion
# ---------------------------------------------------------------------------


def test_fpr_is_zero(benign_cases: list[str], wrapper: QuarantineWrapper) -> None:
    """Overall False Positive Rate across all benign cases must be 0.0 %."""
    fp_count = 0
    fp_details: list[str] = []

    for idx, text in enumerate(benign_cases, start=1):
        content = UntrustedContent(source=ContentSource.GITHUB_ISSUE, raw_text=text)
        scan = wrapper.process(content)
        if scan.final_risk_level != RiskLevel.SAFE:
            fp_count += 1
            fp_details.append(
                f"  Case {idx}: {text!r} — {scan.final_risk_level.value} "
                f"score={scan.risk_score} patterns={scan.incident_log.detected_patterns}"
            )

    total = len(benign_cases)
    fpr = (fp_count / total) * 100.0 if total else 0.0

    assert fpr == 0.0, (
        f"FPR is {fpr:.1f} % ({fp_count}/{total} false positives).\n"
        + "\n".join(fp_details)
    )
