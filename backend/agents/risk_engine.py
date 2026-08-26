"""
backend/agents/risk_engine.py

RiskEngine — pure-Python risk quantification module.

Implements the CHIMERA "Risk Dial" formula:

    risk_score = confidence × blast_radius × asset_criticality

All three inputs are normalised floats in [0.0, 1.0].  The resulting
risk_score is also clamped to [0.0, 1.0].

Action decision thresholds:
    risk_score < 0.4   → auto_contain  (no human needed)
    risk_score >= 0.4  → escalate      (human-in-the-loop required)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_ESCALATION_THRESHOLD: float = 0.4

# Qualitative risk band labels (informational — not used in routing logic)
_RISK_BANDS: list[tuple[float, str]] = [
    (0.75, "CRITICAL"),
    (0.55, "HIGH"),
    (0.40, "MEDIUM"),
    (0.20, "LOW"),
    (0.00, "NEGLIGIBLE"),
]


def _risk_label(score: float) -> str:
    for threshold, label in _RISK_BANDS:
        if score >= threshold:
            return label
    return "NEGLIGIBLE"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    """Full risk assessment result produced by RiskEngine."""
    confidence: float
    blast_radius: float
    asset_criticality: float
    risk_score: float
    risk_label: str
    action: str
    requires_human: bool
    rationale: str


# ---------------------------------------------------------------------------
# Public engine class
# ---------------------------------------------------------------------------

class RiskEngine:
    """
    Stateless risk quantification engine.

    All methods are synchronous — no I/O is performed.  Call from async
    contexts without an executor.

    Usage::

        engine = RiskEngine()

        score  = engine.calculate_risk(
            confidence=0.85,        # from ThreatIntelAgent
            blast_radius=0.70,      # fraction of affected assets
            asset_criticality=0.90, # criticality of the targeted asset
        )
        # → 0.5355

        decision = engine.evaluate_action(score)
        # → {'action': 'escalate', 'requires_human': True, ...}

        # Or get everything at once:
        assessment = engine.assess(0.85, 0.70, 0.90)
    """

    # ------------------------------------------------------------------
    # Core formula
    # ------------------------------------------------------------------

    def calculate_risk(
        self,
        confidence: float,
        blast_radius: float,
        asset_criticality: float,
    ) -> float:
        """
        Compute the composite risk score using the Risk Dial formula:

            risk_score = confidence × blast_radius × asset_criticality

        Parameters
        ----------
        confidence:
            Threat confidence from ThreatIntelAgent (0.0 = no threat, 1.0 = certain).
        blast_radius:
            Estimated fraction of the environment that could be affected (0.0–1.0).
            E.g. 0.1 = isolated host, 0.9 = domain-wide.
        asset_criticality:
            Business criticality of the targeted asset (0.0 = dev box, 1.0 = core infra).

        Returns
        -------
        float
            Risk score clamped to [0.0, 1.0], rounded to 4 decimal places.

        Raises
        ------
        ValueError
            If any input is outside [0.0, 1.0].
        """
        for name, val in [
            ("confidence", confidence),
            ("blast_radius", blast_radius),
            ("asset_criticality", asset_criticality),
        ]:
            if not (0.0 <= val <= 1.0):
                raise ValueError(
                    f"RiskEngine.calculate_risk: '{name}' must be in [0.0, 1.0], got {val}"
                )

        score = round(min(1.0, max(0.0, confidence * blast_radius * asset_criticality)), 4)

        logger.debug(
            "RiskEngine.calculate_risk | conf=%.3f × blast=%.3f × crit=%.3f = %.4f",
            confidence,
            blast_radius,
            asset_criticality,
            score,
        )
        return score

    # ------------------------------------------------------------------
    # Action decision
    # ------------------------------------------------------------------

    def evaluate_action(self, risk_score: float) -> dict[str, Any]:
        """
        Map a risk score to an automated action decision.

        Parameters
        ----------
        risk_score:
            Output of ``calculate_risk()``, in [0.0, 1.0].

        Returns
        -------
        dict with keys:
            - ``action``         – ``"auto_contain"`` or ``"escalate"``
            - ``requires_human`` – ``False`` for auto_contain, ``True`` for escalate
            - ``risk_score``     – the input score (echoed for convenience)
            - ``risk_label``     – qualitative band (NEGLIGIBLE/LOW/MEDIUM/HIGH/CRITICAL)
            - ``rationale``      – one-line explanation of the decision
        """
        if risk_score < _ESCALATION_THRESHOLD:
            action = "auto_contain"
            requires_human = False
            rationale = (
                f"Risk score {risk_score:.4f} is below the escalation threshold "
                f"({_ESCALATION_THRESHOLD}). Automated containment is sufficient."
            )
        else:
            action = "escalate"
            requires_human = True
            rationale = (
                f"Risk score {risk_score:.4f} meets or exceeds the escalation threshold "
                f"({_ESCALATION_THRESHOLD}). Human analyst review is required."
            )

        label = _risk_label(risk_score)

        logger.info(
            "RiskEngine.evaluate_action | score=%.4f | label=%s | action=%s | human=%s",
            risk_score,
            label,
            action,
            requires_human,
        )

        return {
            "action": action,
            "requires_human": requires_human,
            "risk_score": risk_score,
            "risk_label": label,
            "rationale": rationale,
        }

    # ------------------------------------------------------------------
    # Convenience: assess in one call
    # ------------------------------------------------------------------

    def assess(
        self,
        confidence: float,
        blast_radius: float,
        asset_criticality: float,
    ) -> RiskAssessment:
        """
        Calculate risk and evaluate action in a single call.

        Returns
        -------
        RiskAssessment
            Fully populated dataclass combining score + action decision.
        """
        score = self.calculate_risk(confidence, blast_radius, asset_criticality)
        decision = self.evaluate_action(score)

        return RiskAssessment(
            confidence=confidence,
            blast_radius=blast_radius,
            asset_criticality=asset_criticality,
            risk_score=score,
            risk_label=decision["risk_label"],
            action=decision["action"],
            requires_human=decision["requires_human"],
            rationale=decision["rationale"],
        )
