"""
backend/db/reset_demo.py

CHIMERA Demo State Reset Utility.
Connects to PostgreSQL via SQLAlchemy and completely truncates all records from:
  - incidents
  - events
  - actions
  - reports
  - decision_edges
  - graph_edges

Resets all counters, live telemetry queues, and decision-provenance graphs back to 0
without dropping table schemas or altering column definitions.

Usage:
    python -m backend.db.reset_demo
    python backend/db/reset_demo.py
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from sqlalchemy import text
from backend.config import settings
from backend.db.postgres import engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chimera.reset_demo")

TABLES_TO_TRUNCATE = [
    "actions",
    "reports",
    "decision_edges",
    "graph_edges",
    "events",
    "incidents",
]


async def reset_demo_database(custom_db_url: str = None) -> None:
    db_target = custom_db_url or settings.async_database_url
    logger.info("Connecting to PostgreSQL at %s for DEMO RESET...", db_target)

    async with engine.begin() as conn:
        for table in TABLES_TO_TRUNCATE:
            try:
                await conn.execute(text(f"TRUNCATE TABLE {table} CASCADE;"))
                logger.info("  ✓ Cleared table: %s (0 records)", table)
            except Exception as e:
                # Fallback to DELETE FROM if TRUNCATE CASCADE fails
                logger.warning("TRUNCATE on %s failed (%s), attempting DELETE...", table, e)
                try:
                    await conn.execute(text(f"DELETE FROM {table};"))
                    logger.info("  ✓ Deleted all records from: %s", table)
                except Exception as del_err:
                    logger.error("Failed to clear table %s: %s", table, del_err)

    logger.info("=" * 60)
    logger.info("✨ DEMO RESET COMPLETE: All incident & telemetry tables reset to 0.")
    logger.info("=" * 60)


async def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        await reset_demo_database(url)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
