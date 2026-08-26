"""
backend/integrations/swytchcode_client.py

Mock Swytchcode connector that simulates fetching VirusTotal / AbuseIPDB
reputation data for a given IOC.

In a production deployment, replace the simulated logic inside
``_fetch_virustotal`` and ``_fetch_abuseipdb`` with real API calls using
the ``VIRUSTOTAL_API_KEY`` and ``ABUSEIPDB_API_KEY`` from config.py.
"""

import asyncio
import hashlib
import logging
import re
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def _ioc_type(ioc: str) -> str:
    if _IP_RE.match(ioc):
        return "ip"
    if _CVE_RE.match(ioc):
        return "cve"
    return "domain"


def _deterministic_score(ioc: str) -> float:
    """
    Derive a stable pseudo-random malicious score in [0.0, 1.0] from the
    IOC string so that repeated calls for the same IOC return the same score.
    """
    digest = int(hashlib.md5(ioc.encode()).hexdigest(), 16)
    return round((digest % 100) / 100, 2)


def _derive_tags(ioc: str, score: float, ioc_type: str) -> list[str]:
    tags: list[str] = [ioc_type]
    if score >= 0.75:
        tags += ["malicious", "high-risk"]
    elif score >= 0.40:
        tags += ["suspicious"]
    else:
        tags += ["clean"]

    # Add source-specific tags based on a simple hash bucket
    digest = int(hashlib.md5(ioc.encode()).hexdigest(), 16)
    source_tags = [
        ["virustotal-flagged", "abuseipdb-reported"],
        ["botnet", "scanner"],
        ["c2-server", "tor-exit-node"],
        ["known-good", "cdn"],
    ]
    tags += source_tags[digest % len(source_tags)]
    return tags


# ---------------------------------------------------------------------------
# Simulated sub-fetchers
# ---------------------------------------------------------------------------

async def _fetch_virustotal(ioc: str) -> dict[str, Any]:
    """Simulate a VirusTotal lookup (replace with real HTTP call in prod)."""
    await asyncio.sleep(0.05)  # simulate network latency
    score = _deterministic_score(ioc + "vt")
    return {"engine": "virustotal", "positives": int(score * 72), "total": 72}


async def _fetch_abuseipdb(ioc: str) -> dict[str, Any]:
    """Simulate an AbuseIPDB lookup (replace with real HTTP call in prod)."""
    await asyncio.sleep(0.05)
    score = _deterministic_score(ioc + "abuse")
    return {
        "engine": "abuseipdb",
        "abuse_confidence_score": int(score * 100),
        "total_reports": int(score * 500),
    }


# ---------------------------------------------------------------------------
# Public connector class
# ---------------------------------------------------------------------------

class SwytchcodeConnector:
    """
    Mock Swytchcode reputation connector.

    Aggregates simulated VirusTotal and AbuseIPDB data into a unified
    reputation report for a given IOC.

    Attributes
    ----------
    api_key : str | None
        The Swytchcode API key read from settings (unused in mock mode).
    """

    def __init__(self) -> None:
        self.api_key: str | None = settings.SWYTCHCODE_API_KEY
        if not self.api_key:
            logger.warning(
                "SWYTCHCODE_API_KEY is not set — running in mock/simulation mode."
            )

    async def get_reputation(self, ioc: str) -> dict[str, Any]:
        """
        Return a reputation report for the given IOC.

        Parameters
        ----------
        ioc:
            IP address, CVE identifier, or domain string.

        Returns
        -------
        dict with keys:
            - ``ioc``             – the queried indicator
            - ``ioc_type``        – ``"ip"``, ``"cve"``, or ``"domain"``
            - ``malicious_score`` – float in [0.0, 1.0]
            - ``tags``            – list of descriptive tag strings
            - ``sources``         – raw per-source data
        """
        logger.info("SwytchcodeConnector.get_reputation | ioc=%s", ioc)

        ioc_kind = _ioc_type(ioc)

        # Run both sub-fetchers concurrently
        vt_data, abuse_data = await asyncio.gather(
            _fetch_virustotal(ioc),
            _fetch_abuseipdb(ioc),
        )

        # Aggregate into a single composite score
        vt_score = vt_data["positives"] / max(vt_data["total"], 1)
        abuse_score = abuse_data["abuse_confidence_score"] / 100
        composite = round((vt_score * 0.6) + (abuse_score * 0.4), 2)

        tags = _derive_tags(ioc, composite, ioc_kind)

        report: dict[str, Any] = {
            "ioc": ioc,
            "ioc_type": ioc_kind,
            "malicious_score": composite,
            "tags": tags,
            "sources": {
                "virustotal": vt_data,
                "abuseipdb": abuse_data,
            },
        }

        logger.debug(
            "Reputation report | ioc=%s | score=%s | tags=%s",
            ioc,
            composite,
            tags,
        )
        return report
