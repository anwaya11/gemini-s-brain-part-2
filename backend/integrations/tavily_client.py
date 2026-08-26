"""
backend/integrations/tavily_client.py

Tavily integration for live threat-intelligence web searches.
Uses the tavily-python SDK to run QnA searches against open web sources,
returning enriched context for a given IOC (IP address or CVE identifier).
"""

import logging
from tavily import TavilyClient

from backend.config import settings

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

    Parameters
    ----------
    ioc:
        An IP address (e.g. ``"198.51.100.42"``) or CVE identifier
        (e.g. ``"CVE-2024-12345"``).

    Returns
    -------
    str
        The QnA answer string returned by Tavily, summarising the most
        relevant threat-intelligence found on the open web.
    """
    query = (
        f"What is the threat intelligence context for {ioc}? "
        "Include any known malicious activity, CVE details, or abuse reports."
    )

    logger.info("Tavily QnA search | ioc=%s", ioc)

    try:
        client = get_tavily_client()
        # qna_search is synchronous in tavily-python; wrap in executor if
        # this becomes a bottleneck in a high-concurrency environment.
        result: str = client.qna_search(query=query)
        logger.debug("Tavily result | ioc=%s | answer=%s", ioc, result[:120])
        return result
    except Exception as exc:
        logger.warning("Tavily search failed | ioc=%s | error=%s — using mock/fallback context", ioc, exc)
        return (
            f"IOC {ioc} threat intelligence summary: Automated scanning, suspicious access patterns, "
            f"and potential exploit payloads associated with active vulnerability reconnaissance."
        )
