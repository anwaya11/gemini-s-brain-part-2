"""
backend/fixtures/loader.py

Deterministic Offline Demo & Fallback Loader for Project CHIMERA.
Provides zero-latency, offline-safe mock responses with realistic async micro-delays (200-400ms).
"""

import asyncio
import json
import logging
import random
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("chimera.fixtures")

FIXTURE_PATH = Path(__file__).resolve().parent / "demo_sequence.json"

_CACHED_FIXTURES: Optional[Dict[str, Any]] = None
_RUNTIME_DEMO_MODE: Optional[bool] = None


def load_fixtures() -> Dict[str, Any]:
    global _CACHED_FIXTURES
    if _CACHED_FIXTURES is not None:
        return _CACHED_FIXTURES

    if FIXTURE_PATH.exists():
        try:
            with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
                _CACHED_FIXTURES = json.load(f)
                return _CACHED_FIXTURES
        except Exception as e:
            logger.error(f"[Fixtures] Failed to load fixture file: {e}")

    _CACHED_FIXTURES = {"incidents": {}}
    return _CACHED_FIXTURES


def is_demo_mode() -> bool:
    """
    Returns True if DEMO_MODE is currently enabled.
    Falls back to True if no external API keys (Groq, Tavily, Lyzr) are configured.
    """
    global _RUNTIME_DEMO_MODE
    if _RUNTIME_DEMO_MODE is not None:
        return _RUNTIME_DEMO_MODE

    from backend.config import settings

    if settings.DEMO_MODE is not None:
        _RUNTIME_DEMO_MODE = settings.DEMO_MODE
        return _RUNTIME_DEMO_MODE

    # Default to True if major live API keys are absent
    has_live_keys = bool(settings.TAVILY_API_KEY and (settings.LYZR_API_KEY or settings.GEMINI_API_KEY))
    _RUNTIME_DEMO_MODE = not has_live_keys
    return _RUNTIME_DEMO_MODE


def set_demo_mode(enabled: bool) -> bool:
    """Set the runtime demo mode state dynamically."""
    global _RUNTIME_DEMO_MODE
    _RUNTIME_DEMO_MODE = bool(enabled)
    logger.info(f"[DEMO_MODE] Runtime state switched to: {_RUNTIME_DEMO_MODE}")
    return _RUNTIME_DEMO_MODE


async def simulate_agent_latency(min_ms: int = 200, max_ms: int = 400) -> None:
    """
    Introduce an asynchronous 200–400ms micro-delay to simulate realistic agent reasoning latency.
    """
    delay_sec = random.uniform(min_ms / 1000.0, max_ms / 1000.0)
    await asyncio.sleep(delay_sec)


def get_demo_fixture(key: str) -> Optional[Dict[str, Any]]:
    """
    Look up matching incident fixture by IP address, endpoint, or pattern.
    """
    fixtures = load_fixtures()
    incidents = fixtures.get("incidents", {})

    clean_key = str(key).strip()

    # Direct key lookup
    if clean_key in incidents:
        return incidents[clean_key]

    # Search by IP in incident objects
    for ip, data in incidents.items():
        if ip in clean_key or clean_key in ip:
            return data
        if data.get("endpoint") and data["endpoint"] in clean_key:
            return data

    # Default to first fixture if not found
    if incidents:
        first_key = next(iter(incidents))
        return incidents[first_key]

    return None
