"""Abstract base class for all Sieve detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from sieve.core.types import DetectionResult, UntrustedContent


class BaseDetector(ABC):
    """Every detector must implement :meth:`scan`.

    Detectors are stateless by design — each call to :meth:`scan` is
    independent and must not rely on instance-level mutable state.
    """

    #: Human-readable name referenced in ``DetectionResult.detector_name``.
    name: str = "base"

    @abstractmethod
    def scan(self, content: UntrustedContent) -> DetectionResult:
        """Analyse *content* and return a :class:`~sieve.core.types.DetectionResult`.

        Args:
            content: The untrusted content item to analyse.

        Returns:
            A fully populated :class:`~sieve.core.types.DetectionResult`.
        """
        ...

    # ── Convenience helpers ───────────────────────────────────────────────────

    def _make_result(
        self,
        content: UntrustedContent,
        *,
        is_flagged: bool,
        risk_level: "RiskLevel",  # noqa: F821 — imported by subclasses
        detected_patterns: list[str] | None = None,
        raw_score: float = 0.0,
        explanation: str = "",
    ) -> DetectionResult:
        from sieve.core.types import RiskLevel  # local import avoids circular

        return DetectionResult(
            content_id=content.id,
            is_flagged=is_flagged,
            risk_level=risk_level,
            detected_patterns=detected_patterns or [],
            raw_score=raw_score,
            explanation=explanation,
            detector_name=self.name,
        )
