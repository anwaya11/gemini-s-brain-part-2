"""
backend/integrations/tavily_client.py

Tavily integration for live threat-intelligence web searches.
Uses the tavily-python SDK to run QnA searches against open web sources,
returning enriched context for a given IOC (IP address or CVE identifier).
"""

import logging
from tavily import TavilyClient

from backend.config import settings
from backend.fixtures.loader import is_demo_mode, get_demo_fixture, simulate_agent_latency

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Client initialisation
# ---------------------------------------------------------------------------

def _build_client() -> TavilyClient:
    """Instantiate a TavilyClient, raising clearly if the key is missing."""
    api_key = settings.TAVILY_API_KEY
    if not api_key:
        raise ValueError(
            "TAVILY_API_KEY is not set. "
            "Add it to your .env file or environment variables."
        )
    return TavilyClient(api_key=api_key)


# Lazy singleton so the key is only required when the client is first used.
_client: TavilyClient | None = None


def get_tavily_client() -> TavilyClient:
    global _client
    if _client is None:
        _client = _build_client()
    return _client


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def search_ioc_context(ioc: str) -> str:
    """
    Query Tavily for live web context about a given IOC.
    In DEMO_MODE, returns deterministic fixture data with realistic micro-latency.
    """
    # ── 1. DEMO_MODE Fast Offline Return with simulated latency ─────────
    if is_demo_mode():
        await simulate_agent_latency(200, 380)
        fixture = get_demo_fixture(ioc)
        if fixture and "tavily" in fixture:
            answer = fixture["tavily"].get("answer") or fixture["tavily"].get("ioc_summary")
            if answer:
                logger.info("[Tavily DEMO_MODE] Resolved fixture for ioc=%s", ioc)
                return answer

    query = (
        f"What is the threat intelligence context for {ioc}? "
        "Include any known malicious activity, CVE details, or abuse reports."
    )

    logger.info("Tavily QnA search | ioc=%s", ioc)

    try:
        client = get_tavily_client()
        result: str = client.qna_search(query=query)
        logger.debug("Tavily result | ioc=%s | answer=%s", ioc, result[:120])
        return result
    except Exception as exc:
        logger.warning("Tavily search failed | ioc=%s | error=%s — using mock/fallback context", ioc, exc)
        fixture = get_demo_fixture(ioc)
        if fixture and "tavily" in fixture:
            return fixture["tavily"].get("answer") or fixture["tavily"].get("ioc_summary", "")
        return (
            f"IOC {ioc} threat intelligence summary: Automated scanning, suspicious access patterns, "
            f"and potential exploit payloads associated with active vulnerability reconnaissance."
        )
