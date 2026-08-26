from typing import Any, AsyncGenerator, Dict, List, Optional
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text
from backend.config import settings

# Initialize Async Engine
engine: AsyncEngine = create_async_engine(
    settings.async_database_url,
    echo=(settings.ENVIRONMENT == "development"),
    future=True,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Create Async Session Maker
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides an asynchronous database session.
    Automatically commits on success or rolls back on exception.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def execute_query(query: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """
    Execute a raw SQL command (INSERT, UPDATE, DELETE, CREATE, etc.) asynchronously.
    """
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(text(query), params or {})
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise


async def fetch_all(query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Execute a raw SQL SELECT query and return all matching rows as a list of dictionaries.
    """
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(text(query), params or {})
            mappings = result.mappings().all()
            return [dict(row) for row in mappings]
        except Exception:
            await session.rollback()
            raise


async def fetch_one(query: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Execute a raw SQL SELECT query and return a single row as a dictionary, or None.
    """
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(text(query), params or {})
            mapping = result.mappings().first()
            return dict(mapping) if mapping is not None else None
        except Exception:
            await session.rollback()
            raise
