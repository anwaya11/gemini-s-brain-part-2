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
import re
from typing import Any

from groq import AsyncGroq

from backend.config import settings
from backend.integrations.tavily_client import search_ioc_context
from backend.integrations.swytchcode_client import SwytchcodeConnector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------

_GROQ_MODEL = "llama-3.3-70b-versatile"

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

    Usage::

        agent = ThreatIntelAgent()

        # Single IOC
        report = await agent.enrich("198.51.100.42")

        # Multiple IOCs
        reports = await agent.enrich_many(["198.51.100.42", "CVE-2024-12345"])
    """

    def __init__(self) -> None:
        self._swytchcode = SwytchcodeConnector()

    async def enrich(self, ioc: str) -> dict[str, Any]:
        """
        Enrich a single IOC.

        Parameters
        ----------
        ioc:
            An IP address, CVE identifier, or domain.

        Returns
        -------
        dict with keys:
            - ``ioc``              – the queried indicator
            - ``confidence_score`` – float 0.0–1.0 (likelihood of maliciousness)
            - ``threat_context``   – narrative summary string
            - ``tags``             – list of descriptive labels
            - ``sources``          – raw data from Tavily and Swytchcode
        """
        logger.info("ThreatIntelAgent.enrich | ioc=%s", ioc)

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
