"""
scripts/init_db.py

Database Initialization Script for Project-CHIMERA.
Connects to PostgreSQL using settings.DATABASE_URL (or os.getenv("DATABASE_URL") / command-line arg)
and executes Base.metadata.create_all to create all SQL tables:
  - incidents
  - events
  - actions
  - reports
  - decision_edges
  - graph_edges

Usage:
    python scripts/init_db.py
    python scripts/init_db.py postgresql+asyncpg://user:pass@localhost:5432/dbname
    python -m backend.db.init_db
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.config import settings
from backend.db.models import Base
from backend.db.postgres import engine, init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chimera.init_db")


async def main() -> None:
    db_url = sys.argv[1] if len(sys.argv) > 1 else (os.getenv("DATABASE_URL") or settings.async_database_url)
    logger.info("Connecting to PostgreSQL at: %s", db_url)
    try:
        await init_db()
        logger.info("All database tables created successfully [OK]:")
        for table_name in Base.metadata.tables.keys():
            logger.info("  ✓ Table: %s", table_name)
    except Exception as exc:
        logger.error("Database initialization note: %s", exc)
        logger.info(
            "Note: If running in standalone / containerless mode, start PostgreSQL using:\n"
            "  docker compose -f infra/docker-compose.yml up -d\n"
            "or set DATABASE_URL in backend/.env."
        )
        sys.exit(1)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
