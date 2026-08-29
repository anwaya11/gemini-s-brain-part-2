"""
backend/agents/triage_agent.py

TriageAgent — classifies incoming alerts with an LLM.

Given a raw log payload and the XGBoost anomaly score produced by
EdgeFilter, it returns a structured JSON triage verdict containing:

    {
        "severity":        "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "mitre_tactic":    str,   # e.g. "Initial Access"
        "mitre_technique": str,   # e.g. "T1190 – Exploit Public-Facing Application"
        "reasoning":       str    # one-sentence rationale (bonus field)
    }

LLM provider: Groq (llama-3.3-70b-versatile) — the groq package is already
in requirements.txt.  The `_call_llm` helper can be swapped for any provider
(Lyzr, Gemini, OpenAI) by changing only that function.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
try:
    from groq import AsyncGroq
except ImportError:
    AsyncGroq = None

from backend.config import settings
from backend.fixtures.loader import is_demo_mode, get_demo_fixture, simulate_agent_latency

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------

_GROQ_MODEL = "llama-3.3-70b-versatile"

_SYSTEM_PROMPT = """\
You are CHIMERA Triage — a senior SOC analyst AI embedded in an autonomous
Security Operations Centre.  Your sole job is to classify security alerts.

When given a raw log and an XGBoost anomaly score (0.0 = benign, 1.0 = critical
threat), you MUST respond with ONLY valid JSON — no markdown fences, no prose.

Required JSON schema:
{
  "severity":        "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "mitre_tactic":    "<MITRE ATT&CK tactic name>",
  "mitre_technique": "<Txxxx – Technique Name>",
  "reasoning":       "<one concise sentence explaining the classification>"
}

Severity mapping guidance (use the anomaly_score as the primary signal):
  0.00 – 0.29  → LOW
  0.30 – 0.59  → MEDIUM
  0.60 – 0.84  → HIGH
  0.85 – 1.00  → CRITICAL

Always pick the single most relevant MITRE ATT&CK tactic and technique.
If the log is ambiguous, default to the tactic suggested by the anomaly score.
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_user_message(raw_log: dict[str, Any], anomaly_score: float) -> str:
    """Serialise the log + score into a compact prompt string."""
    log_str = json.dumps(raw_log, separators=(",", ":"), default=str)
    return (
        f"anomaly_score: {anomaly_score:.4f}\n"
        f"raw_log: {log_str}"
    )


def _extract_json(text: str) -> dict[str, Any]:
    """
    Parse the LLM response into a dict.

    Handles responses that accidentally include markdown fences or
    surrounding prose by extracting the first JSON object found.
    """
    # Strip common markdown code fences
    text = re.sub(r"```(?:json)?", "", text).strip()

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Fall back to extracting the first {...} block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse JSON from LLM response: {text!r}")


def _severity_from_score(score: float) -> str:
    """Hard-coded fallback severity derived from anomaly score alone."""
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.30:
        return "MEDIUM"
    return "LOW"


async def _call_llm(system: str, user: str) -> str:
    """
    Call the Groq LLM asynchronously and return the assistant message content.
    """
    if AsyncGroq is None:
        raise RuntimeError("Groq SDK is not installed in the environment.")
    groq_client = AsyncGroq(api_key=None)
    chat = await groq_client.chat.completions.create(
        model=_GROQ_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.1,          # low temperature for deterministic classification
        max_tokens=512,
        response_format={"type": "json_object"},
    )
    return chat.choices[0].message.content or ""


# ---------------------------------------------------------------------------
# Public agent class
# ---------------------------------------------------------------------------

class TriageAgent:
    """
    Classifies a security alert using an LLM backed by the XGBoost anomaly
    score from EdgeFilter.
    In DEMO_MODE, returns deterministic high-fidelity classification with simulated latency.
    """

    async def classify(
        self,
        raw_log: dict[str, Any],
        anomaly_score: float,
    ) -> dict[str, Any]:
        """
        Run LLM-based triage classification.
        """
        logger.info(
            "TriageAgent.classify | anomaly_score=%.4f | log_keys=%s",
            anomaly_score,
            list(raw_log.keys()),
        )

        source_ip = raw_log.get("source_ip") or raw_log.get("source") or ""
        endpoint = raw_log.get("endpoint") or raw_log.get("path") or ""

        # ── 1. DEMO_MODE Fast Deterministic Return ─────────────────────────
        if is_demo_mode():
            await simulate_agent_latency(200, 380)
            fixture = get_demo_fixture(source_ip) or get_demo_fixture(endpoint)
            if fixture:
                sev = fixture.get("severity") or _severity_from_score(anomaly_score)
                tactic = fixture.get("mitre_tactic", "Initial Access")
                technique = fixture.get("mitre_technique", "T1190 – Exploit Public-Facing Application")
                reasoning = fixture.get("reasoning", f"Classified as {sev} based on anomaly score {anomaly_score:.2f}")
                return {
                    "severity": sev,
                    "mitre_tactic": tactic,
                    "mitre_technique": technique,
                    "reasoning": reasoning,
                }

        user_msg = _build_user_message(raw_log, anomaly_score)

        try:
            raw_response = await _call_llm(_SYSTEM_PROMPT, user_msg)
            result = _extract_json(raw_response)

            # Normalise and validate required keys
            severity = str(result.get("severity", "")).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                severity = _severity_from_score(anomaly_score)

            return {
                "severity": severity,
                "mitre_tactic": result.get("mitre_tactic", "Unknown"),
                "mitre_technique": result.get("mitre_technique", "Unknown"),
                "reasoning": result.get("reasoning", ""),
            }

        except Exception as exc:
            logger.error("TriageAgent LLM call failed: %s — using fallback", exc)
            fixture = get_demo_fixture(source_ip) or get_demo_fixture(endpoint)
            if fixture:
                return {
                    "severity": fixture.get("severity", _severity_from_score(anomaly_score)),
                    "mitre_tactic": fixture.get("mitre_tactic", "Initial Access"),
                    "mitre_technique": fixture.get("mitre_technique", "T1190 – Exploit Public-Facing Application"),
                    "reasoning": fixture.get("reasoning", f"Fallback classification for {source_ip}."),
                }
            return {
                "severity": _severity_from_score(anomaly_score),
                "mitre_tactic": "Unknown",
                "mitre_technique": "Unknown",
                "reasoning": f"LLM unavailable ({exc}); severity derived from anomaly score.",
            }
