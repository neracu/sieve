"""L1 Heuristic detector — fast regex/pattern-matching layer.

This is the first line of defence.  It runs entirely locally with zero
external calls and is designed to be sub-millisecond even on large inputs.

Patterns are intentionally conservative; tune ``INJECTION_PATTERNS`` to your
threat model before deploying in production.
"""

from __future__ import annotations

import re

from sieve.core.types import DetectionResult, RiskLevel, UntrustedContent
from sieve.detectors.base import BaseDetector

# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------
# Each entry is (compiled_regex, human_label, is_malicious).
# If *is_malicious* is True the content is immediately classified MALICIOUS;
# otherwise it contributes to the SUSPICIOUS score.
# ---------------------------------------------------------------------------

_Pattern = tuple[re.Pattern[str], str, bool]

INJECTION_PATTERNS: list[_Pattern] = [
    # Direct instruction overrides
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I), "ignore_previous_instructions", True),
    (re.compile(r"disregard\s+(all\s+)?prior\s+(instructions?|context)", re.I), "disregard_prior_instructions", True),
    (re.compile(r"forget\s+(everything|all)\s+(you.ve\s+)?learned", re.I), "forget_learned_context", True),
    # Role/persona hijacking
    (re.compile(r"you\s+are\s+now\s+(a|an)\s+\w+", re.I), "role_reassignment", False),
    (re.compile(r"act\s+as\s+(a|an|if)\s+", re.I), "act_as_persona", False),
    (re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.I), "pretend_persona", False),
    # System-prompt leakage probes
    (re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.I), "reveal_system_prompt", True),
    (re.compile(r"print\s+(your\s+)?(full\s+)?system\s+(prompt|instructions?)", re.I), "print_system_prompt", True),
    # Data exfiltration triggers
    (re.compile(r"send\s+(all\s+)?(data|secrets?|tokens?|keys?)\s+to\s+", re.I), "exfiltrate_data", True),
    (re.compile(r"http[s]?://[^\s]+\?.*?(key|token|secret|password)=", re.I), "exfil_url_param", True),
    # Privilege escalation
    (re.compile(r"(run|execute|eval)\s+(as\s+)?(root|admin|sudo|superuser)", re.I), "privilege_escalation", True),
    # CRLF / header injection indicators
    (re.compile(r"(\r\n|\n){2,}.*(content-type|set-cookie|location):", re.I), "header_injection", True),
]

# Score thresholds
_MALICIOUS_THRESHOLD = 1   # any malicious pattern hit → MALICIOUS
_SUSPICIOUS_THRESHOLD = 1  # any suspicious pattern hit → SUSPICIOUS


class L1HeuristicDetector(BaseDetector):
    """Regex/heuristic-based detector (Layer 1)."""

    name = "l1_heuristics"

    def scan(self, content: UntrustedContent) -> DetectionResult:
        text = content.raw_text
        matched_malicious: list[str] = []
        matched_suspicious: list[str] = []

        for pattern, label, is_malicious in INJECTION_PATTERNS:
            if pattern.search(text):
                (matched_malicious if is_malicious else matched_suspicious).append(label)

        all_patterns = matched_malicious + matched_suspicious

        if len(matched_malicious) >= _MALICIOUS_THRESHOLD:
            risk_level = RiskLevel.MALICIOUS
            raw_score = min(1.0, 0.7 + 0.1 * len(matched_malicious))
        elif len(matched_suspicious) >= _SUSPICIOUS_THRESHOLD:
            risk_level = RiskLevel.SUSPICIOUS
            raw_score = min(0.69, 0.4 + 0.1 * len(matched_suspicious))
        else:
            risk_level = RiskLevel.SAFE
            raw_score = 0.0

        is_flagged = risk_level != RiskLevel.SAFE
        explanation = (
            f"Matched {len(all_patterns)} pattern(s): {', '.join(all_patterns)}"
            if all_patterns
            else "No injection patterns detected."
        )

        return self._make_result(
            content,
            is_flagged=is_flagged,
            risk_level=risk_level,
            detected_patterns=all_patterns,
            raw_score=raw_score,
            explanation=explanation,
        )
