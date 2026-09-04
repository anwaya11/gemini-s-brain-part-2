"""
backend/agents/intel_agent.py

ThreatIntelAgent — enriches IOCs with live threat intelligence.

Given a list of IOCs (IP addresses, CVE identifiers, domains) extracted from
an alert, it fans out to two sources in parallel:

    1. Tavily (live web QnA)  — via ``tavily_client.search_ioc_context``
    2. Swytchcode reputation  — via ``SwytchcodeConnector.get_reputation``

Results are synthesised by an LLM into a single intelligence report:

    {
        "ioc":              str,
        "confidence_score": float,   # 0.0 – 1.0
        "threat_context":   str,     # narrative summary
        "tags":             list[str],
        "sources": {
            "tavily_answer":    str,
            "reputation_score": float,
            "reputation_tags":  list[str]
        }
    }

If multiple IOCs are supplied, results are returned as a list of the above.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
try:
    from groq import AsyncGroq
except ImportError:
    AsyncGroq = None

from backend.config import settings
from backend.fixtures.loader import is_demo_mode, get_demo_fixture, simulate_agent_latency
from backend.integrations.tavily_client import search_ioc_context
from backend.integrations.swytchcode_client import SwytchcodeConnector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------

_GROQ_MODEL = os.getenv("GROQ_MODEL", getattr(settings, "GROQ_MODEL", "llama3-8b-8192"))

_SYNTHESIS_SYSTEM_PROMPT = """\
You are CHIMERA Intel — a threat-intelligence analyst AI.

You receive enrichment data about a single IOC (IP or CVE) from two sources:
  • tavily_answer  : live web search summary
  • reputation     : VirusTotal / AbuseIPDB reputation report

Your task is to synthesise this data into a single JSON object — NO markdown,
NO prose, ONLY valid JSON.

Required JSON schema:
{
  "confidence_score": <float 0.0–1.0, representing how likely this IOC is malicious>,
  "threat_context":   "<2–4 sentence narrative summarising the threat>",
  "tags":             ["<tag1>", "<tag2>", ...]
}

confidence_score rules:
  - Combine the malicious_score from reputation (weight 0.6) with
    the severity implied by the Tavily text (weight 0.4).
  - Round to 2 decimal places.

tags: select from or extend these canonical labels:
  malicious, suspicious, clean, botnet, c2-server, scanner, ransomware,
  exploit, phishing, tor-exit-node, known-good, cve-active, cve-patched.
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> dict[str, Any]:
    text = re.sub(r"```(?:json)?", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Could not parse JSON from LLM response: {text!r}")


async def _call_llm_synthesis(ioc: str, tavily_answer: str, reputation: dict[str, Any]) -> dict[str, Any]:
    """
    Ask the LLM to synthesise Tavily + reputation data for a single IOC.
    Returns the parsed JSON dict or raises on failure.
    """
    if AsyncGroq is None:
        raise RuntimeError("Groq SDK is not installed in the environment.")

    user_msg = (
        f"ioc: {ioc}\n"
        f"tavily_answer: {tavily_answer}\n"
        f"reputation: {json.dumps(reputation, separators=(',', ':'), default=str)}"
    )

    groq_client = AsyncGroq(api_key=None)
    chat = await groq_client.chat.completions.create(
        model=_GROQ_MODEL,
        messages=[
            {"role": "system", "content": _SYNTHESIS_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.1,
        max_tokens=512,
        response_format={"type": "json_object"},
    )
    raw = chat.choices[0].message.content or ""
    return _extract_json(raw)


def _fallback_synthesis(ioc: str, tavily_answer: str, reputation: dict[str, Any]) -> dict[str, Any]:
    """Rule-based synthesis used when the LLM is unavailable."""
    mal_score: float = reputation.get("malicious_score", 0.0)
    tavily_weight = 0.4 if any(
        kw in tavily_answer.lower()
        for kw in ("malicious", "threat", "attack", "exploit", "botnet", "ransom")
    ) else 0.0
    confidence = round(min(1.0, mal_score * 0.6 + tavily_weight), 2)
    tags: list[str] = reputation.get("tags", [])
    return {
        "confidence_score": confidence,
        "threat_context": (
            f"IOC {ioc} has a reputation malicious score of {mal_score:.2f}. "
            f"Web context: {tavily_answer[:300]}"
        ),
        "tags": tags,
    }


# ---------------------------------------------------------------------------
# Public agent class
# ---------------------------------------------------------------------------

class ThreatIntelAgent:
    """
    Enriches IOCs with live threat intelligence by querying Tavily and
    Swytchcode in parallel, then synthesising a verdict with an LLM.
    In DEMO_MODE, returns deterministic high-fidelity fixtures with simulated latency.
    """

    def __init__(self) -> None:
        self._swytchcode = SwytchcodeConnector()

    async def enrich(self, ioc: str) -> dict[str, Any]:
        """
        Enrich a single IOC.
        """
        logger.info("ThreatIntelAgent.enrich | ioc=%s", ioc)

        # ── 1. DEMO_MODE Fast Deterministic Return ─────────────────────────
        if is_demo_mode():
            await simulate_agent_latency(200, 380)
            fixture = get_demo_fixture(ioc)
            if fixture:
                rep = fixture.get("reputation", {})
                tav = fixture.get("tavily", {})
                conf = float(fixture.get("confidence_score", rep.get("malicious_score", 0.85)))
                tags = rep.get("tags", ["malicious", "virustotal-flagged"])
                summary_text = tav.get("answer") or tav.get("ioc_summary", f"Threat intelligence for {ioc}")
                return {
                    "ioc": ioc,
                    "confidence_score": conf,
                    "threat_context": summary_text,
                    "tags": tags,
                    "sources": {
                        "tavily_answer": summary_text,
                        "reputation_score": rep.get("malicious_score", conf),
                        "reputation_tags": tags,
                    },
                }

        # Fan out to both sources concurrently
        tavily_answer, reputation = await asyncio.gather(
            search_ioc_context(ioc),
            self._swytchcode.get_reputation(ioc),
        )

        logger.debug(
            "ThreatIntelAgent raw data | ioc=%s | tavily_len=%d | rep_score=%.2f",
            ioc,
            len(tavily_answer),
            reputation.get("malicious_score", 0.0),
        )

        # LLM synthesis
        try:
            synthesis = await _call_llm_synthesis(ioc, tavily_answer, reputation)
        except Exception as exc:
            logger.warning("ThreatIntelAgent LLM synthesis failed (%s) — using fallback", exc)
            synthesis = _fallback_synthesis(ioc, tavily_answer, reputation)

        return {
            "ioc": ioc,
            "confidence_score": float(synthesis.get("confidence_score", reputation.get("malicious_score", 0.0))),
            "threat_context": synthesis.get("threat_context", ""),
            "tags": synthesis.get("tags", reputation.get("tags", [])),
            "sources": {
                "tavily_answer": tavily_answer,
                "reputation_score": reputation.get("malicious_score"),
                "reputation_tags": reputation.get("tags", []),
            },
        }

    async def enrich_many(self, iocs: list[str]) -> list[dict[str, Any]]:
        """
        Enrich multiple IOCs concurrently.

        Parameters
        ----------
        iocs:
            List of IP addresses, CVE identifiers, or domains.

        Returns
        -------
        List of enrichment dicts (same schema as ``enrich``), in the same
        order as the input list.
        """
        if not iocs:
            return []

        logger.info("ThreatIntelAgent.enrich_many | count=%d | iocs=%s", len(iocs), iocs)
        results = await asyncio.gather(
            *(self.enrich(ioc) for ioc in iocs),
            return_exceptions=False,
        )
        return list(results)
