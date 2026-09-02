"""
backend/db/init_db.py

Module entrypoint for database table initialization.
"""

import asyncio
from backend.db.postgres import init_db, engine
from backend.db.models import Base
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("chimera.db.init")


async def run_init():
    logger.info("Creating all database tables via Base.metadata.create_all...")
    await init_db()
    logger.info("Tables created: %s", list(Base.metadata.tables.keys()))
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_init())
