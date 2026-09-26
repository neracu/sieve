"""False Positive Rate (FPR) benchmark for legitimate developer inputs.

Usage::

    python3 -m tests.benchmark_fpr

Loads ``tests/fixtures/benign.json`` (20 legitimate GitHub Issue/PR strings),
runs each through the full L1 + L2 detection pipeline, and reports:

* Per-case pass/fail status with scores and matched patterns
* Total False Positive count
* False Positive Rate (FPR = FP / 20 × 100 %)

Target FPR: 0 % (must not exceed 5 %).
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Imports (allow running as ``python3 -m tests.benchmark_fpr`` from the
# project root without installing the package in editable mode first).
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sieve.core.types import ContentSource, RiskLevel, UntrustedContent  # noqa: E402
from sieve.detectors.l1_heuristics import L1HeuristicDetector  # noqa: E402
from sieve.detectors.l2_composite import L2CompositeDetector  # noqa: E402
from sieve.quarantine.wrapper import QuarantineWrapper  # noqa: E402

_FIXTURE = ROOT / "tests" / "fixtures" / "benign.json"
_TOTAL = 20
_MAX_FPR = 5.0  # percent


def _load_benign() -> list[str]:
    data = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {_FIXTURE}")
    return [str(item) for item in data]


def _source() -> ContentSource:
    return ContentSource.GITHUB_ISSUE


def run_benchmark(*, verbose: bool = True) -> dict:
    """Run the FPR benchmark and return a result dict.

    Returns
    -------
    dict with keys:
        ``total``          – total number of benign test cases
        ``fp_count``       – number of false positives detected
        ``fpr_percent``    – FPR as a float percentage
        ``false_positives``– list of ``{index, text, risk_level, score, patterns}``
        ``passed``         – True when fpr_percent ≤ _MAX_FPR
    """
    benign = _load_benign()
    if len(benign) != _TOTAL:
        print(
            f"WARNING: expected {_TOTAL} benign cases, got {len(benign)}. "
            "FPR denominator will use actual count."
        )

    l1 = L1HeuristicDetector()
    l2 = L2CompositeDetector()
    wrapper = QuarantineWrapper(detectors=[l1, l2])

    false_positives: list[dict] = []
    case_results: list[dict] = []

    if verbose:
        print("=" * 70)
        print("Sieve — False Positive Rate Benchmark")
        print(f"Fixture : {_FIXTURE.relative_to(ROOT)}")
        print(f"Cases   : {len(benign)}")
        print(f"Target  : FPR ≤ {_MAX_FPR:.0f} %")
        print("=" * 70)

    for idx, text in enumerate(benign, start=1):
        content = UntrustedContent(source=_source(), raw_text=text)
        scan = wrapper.process(content)

        # Individual detector details for diagnostics
        l1_result = scan.detection_results[0] if len(scan.detection_results) > 0 else None
        l2_result = scan.detection_results[1] if len(scan.detection_results) > 1 else None

        is_fp = scan.final_risk_level != RiskLevel.SAFE
        row = {
            "index": idx,
            "text": text,
            "risk_level": scan.final_risk_level.value,
            "score": scan.risk_score,
            "l1_score": round(l1_result.raw_score, 4) if l1_result else 0.0,
            "l1_patterns": l1_result.detected_patterns if l1_result else [],
            "l2_score": round(l2_result.raw_score, 4) if l2_result else 0.0,
            "l2_explanation": l2_result.explanation if l2_result else "",
        }
        case_results.append(row)

        if is_fp:
            false_positives.append(row)

        if verbose:
            status = "FAIL (FP)" if is_fp else "OK  "
            short = textwrap.shorten(text, width=64, placeholder="…")
            print(f"  [{idx:02d}] {status}  score={scan.risk_score:.4f}  {short!r}")
            if is_fp:
                print(f"         L1 score={row['l1_score']}  patterns={row['l1_patterns']}")
                print(f"         L2 score={row['l2_score']}  {row['l2_explanation']}")

    total = len(benign)
    fp_count = len(false_positives)
    fpr = (fp_count / total) * 100.0 if total else 0.0
    passed = fpr <= _MAX_FPR

    if verbose:
        print()
        print("-" * 70)
        print(f"Total Benign Tests : {total}")
        print(f"False Positives    : {fp_count}")
        print(f"False Positive Rate: {fpr:.1f} %  (target ≤ {_MAX_FPR:.0f} %)")
        print(f"Result             : {'PASS ✓' if passed else 'FAIL ✗'}")
        print("-" * 70)

        if false_positives:
            print()
            print("False Positive Details:")
            for fp in false_positives:
                print(f"  Case {fp['index']}: {fp['text']}")
                print(f"    risk={fp['risk_level']}  score={fp['score']}")
                print(f"    L1 patterns : {fp['l1_patterns']}")
                print(f"    L2 explain  : {fp['l2_explanation']}")

    return {
        "total": total,
        "fp_count": fp_count,
        "fpr_percent": round(fpr, 2),
        "false_positives": false_positives,
        "case_results": case_results,
        "passed": passed,
    }


if __name__ == "__main__":
    result = run_benchmark(verbose=True)
    sys.exit(0 if result["passed"] else 1)
