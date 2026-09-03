"""
backend/db/postgres.py

PostgreSQL database configuration, async session management, schema initialization,
and CRUD persistence helpers for Project-CHIMERA using SQLAlchemy 2.0.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional
import uuid

from sqlalchemy import select, update, delete, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.config import settings
from backend.db.models import (
    Base,
    Incident,
    Event,
    Action,
    Report,
    DecisionEdge,
    GraphEdge,
)

logger = logging.getLogger("chimera.db")

# Resolve Database URL (support postgres://, postgresql://, and asyncpg dialect prefix)
DATABASE_URL: str = os.getenv("DATABASE_URL") or settings.DATABASE_URL
if DATABASE_URL.startswith("postgres://"):
    ASYNC_DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql+asyncpg://"):
    ASYNC_DATABASE_URL = DATABASE_URL
else:
    ASYNC_DATABASE_URL = settings.async_database_url

# Detect cloud or managed database connections requiring SSL & pooler resilience
is_cloud_db = (
    any(domain in ASYNC_DATABASE_URL for domain in ("neon.tech", "supabase", "amazonaws.com", "render.com", "railway.app", "pooler."))
    or "sslmode" in ASYNC_DATABASE_URL
    or os.getenv("DB_SSL_REQUIRE", "").lower() in ("true", "1")
    or ("localhost" not in ASYNC_DATABASE_URL and "127.0.0.1" not in ASYNC_DATABASE_URL)
)

connect_args: Dict[str, Any] = {}
if is_cloud_db:
    connect_args["ssl"] = True
    connect_args["prepared_statement_cache_size"] = 0
    # Strip sslmode parameter from URL to prevent asyncpg unexpected keyword error
    if "sslmode=" in ASYNC_DATABASE_URL:
        ASYNC_DATABASE_URL = re.sub(r"[?&]sslmode=[^&]+", "", ASYNC_DATABASE_URL)
        if "?" not in ASYNC_DATABASE_URL and "&" in ASYNC_DATABASE_URL:
            ASYNC_DATABASE_URL = ASYNC_DATABASE_URL.replace("&", "?", 1)

# ---------------------------------------------------------------------------
# Async Engine & Session Factory
# ---------------------------------------------------------------------------
engine: AsyncEngine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=(settings.ENVIRONMENT == "development"),
    future=True,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args=connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ---------------------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------------------
async def init_db() -> None:
    """
    Initialize database schema by creating all tables registered on Base.metadata.
    """
    logger.info("Initializing PostgreSQL schema for Project-CHIMERA...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized successfully [OK].")


# ---------------------------------------------------------------------------
# FastAPI Dependency
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Raw SQL Execution Helpers (Backward Compatibility)
# ---------------------------------------------------------------------------
async def execute_query(query: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """
    Execute a raw SQL command (INSERT, UPDATE, DELETE, DDL) asynchronously.
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
    Execute a raw SQL SELECT query and return all matching rows as dictionaries.
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


# ---------------------------------------------------------------------------
# Incident ORM Helpers
# ---------------------------------------------------------------------------
async def create_incident(incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Insert or update a security incident in PostgreSQL using SQLAlchemy ORM.
    Returns the persisted incident as a dictionary.
    """
    inc_id = incident_data.get("id") or f"INC-2026-{uuid.uuid4().hex[:4].upper()}"
    now_dt = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as session:
        try:
            # Check if incident already exists
            existing = await session.get(Incident, inc_id)
            if existing:
                existing.title = incident_data.get("title", existing.title)
                existing.description = incident_data.get("description", existing.description)
                existing.status = incident_data.get("status", existing.status)
                existing.severity = incident_data.get("severity", existing.severity)
                existing.risk_score = float(incident_data.get("risk_score", existing.risk_score))
                existing.confidence = float(incident_data.get("confidence", existing.confidence))
                existing.mitre_technique = incident_data.get("mitre_technique", existing.mitre_technique)
                existing.cert_in_category = incident_data.get("cert_in_category", existing.cert_in_category)
                existing.decoy_path = incident_data.get("decoy_path", existing.decoy_path)
                existing.endpoint = incident_data.get("endpoint", existing.endpoint)
                existing.blast_radius = incident_data.get("blast_radius", existing.blast_radius)
                existing.metadata_json = incident_data.get("metadata", existing.metadata_json)
                existing.updated_at = now_dt
                await session.commit()
                await session.refresh(existing)
                return existing.to_dict()

            new_incident = Incident(
                id=inc_id,
                title=incident_data.get("title", "Security Incident"),
                description=incident_data.get("description"),
                source_ip=incident_data.get("source_ip", "127.0.0.1"),
                destination_ip=incident_data.get("destination_ip"),
                endpoint=incident_data.get("endpoint"),
                severity=incident_data.get("severity", "HIGH"),
                status=incident_data.get("status", "PENDING_APPROVAL"),
                risk_score=float(incident_data.get("risk_score", 0.0)),
                confidence=float(incident_data.get("confidence", 0.0)),
                mitre_technique=incident_data.get("mitre_technique"),
                cert_in_category=incident_data.get("cert_in_category"),
                decoy_path=incident_data.get("decoy_path"),
                blast_radius=incident_data.get("blast_radius") or {},
                metadata_json=incident_data.get("metadata") or {},
                created_at=now_dt,
                updated_at=now_dt,
            )
            session.add(new_incident)
            await session.commit()
            await session.refresh(new_incident)
            logger.info("Persisted incident %s to PostgreSQL [OK]", inc_id)
            return new_incident.to_dict()

        except Exception as exc:
            await session.rollback()
            logger.warning("PostgreSQL create_incident error (%s) — returning memory record.", exc)
            return incident_data


async def get_all_incidents() -> List[Dict[str, Any]]:
    """
    Retrieve all incidents from PostgreSQL ordered by creation timestamp descending.
    """
    async with AsyncSessionLocal() as session:
        try:
            stmt = select(Incident).order_by(Incident.created_at.desc())
            result = await session.execute(stmt)
            incidents = result.scalars().all()
            return [inc.to_dict() for inc in incidents]
        except Exception as exc:
            logger.warning("PostgreSQL get_all_incidents error: %s", exc)
            return []


async def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single incident by ID.
    """
    async with AsyncSessionLocal() as session:
        try:
            inc = await session.get(Incident, incident_id)
            return inc.to_dict() if inc else None
        except Exception as exc:
            logger.warning("PostgreSQL get_incident_by_id error: %s", exc)
            return None


async def update_incident_status(incident_id: str, status: str) -> Optional[Dict[str, Any]]:
    """
    Update the status of an incident in PostgreSQL.
    """
    async with AsyncSessionLocal() as session:
        try:
            inc = await session.get(Incident, incident_id)
            if inc:
                inc.status = status
                inc.updated_at = datetime.now(timezone.utc)
                await session.commit()
                await session.refresh(inc)
                logger.info("Updated incident %s status -> %s in PostgreSQL", incident_id, status)
                return inc.to_dict()
            return None
        except Exception as exc:
            await session.rollback()
            logger.warning("PostgreSQL update_incident_status error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Event & Telemetry Helpers
# ---------------------------------------------------------------------------
async def record_event(
    event_id: str,
    source: str,
    event_type: str = "http_log",
    severity: str = "INFO",
    payload: Optional[Dict[str, Any]] = None,
    raw_log: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Persist an incoming raw log or security event in the `events` table.
    """
    now_dt = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        try:
            event = Event(
                id=event_id,
                incident_id=incident_id,
                event_type=event_type,
                source=source,
                severity=severity,
                payload=payload or {},
                raw_log=raw_log or "",
                timestamp=now_dt,
                created_at=now_dt,
            )
            session.add(event)
            await session.commit()
            return event.to_dict()
        except Exception as exc:
            await session.rollback()
            logger.warning("PostgreSQL record_event error: %s", exc)
            return {
                "id": event_id,
                "source": source,
                "event_type": event_type,
                "severity": severity,
                "payload": payload or {},
            }


# ---------------------------------------------------------------------------
# Action & Remediation Helpers
# ---------------------------------------------------------------------------
async def record_agent_action(
    incident_id: Optional[str],
    action_type: str,
    status: str = "SUCCESS",
    playbook_name: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    result: Optional[Dict[str, Any]] = None,
    executed_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Record an automated or manual containment action in the `actions` table.
    """
    action_id = str(uuid.uuid4())
    now_dt = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        try:
            action = Action(
                id=action_id,
                incident_id=incident_id,
                playbook_name=playbook_name,
                action_type=action_type,
                status=status,
                payload=payload or {},
                result=result or {},
                executed_at=executed_at or now_dt,
                created_at=now_dt,
            )
            session.add(action)
            await session.commit()
            logger.info("Recorded agent action %s (%s) for incident %s", action_id, action_type, incident_id)
            return action.to_dict()
        except Exception as exc:
            await session.rollback()
            logger.warning("PostgreSQL record_agent_action error: %s", exc)
            return {
                "id": action_id,
                "incident_id": incident_id,
                "action_type": action_type,
                "status": status,
            }


# ---------------------------------------------------------------------------
# Decision Provenance & Graph Edge Helpers
# ---------------------------------------------------------------------------
async def record_decision_edge(
    source_node: str,
    target_node: str,
    edge_type: str = "decision_flow",
    incident_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    reasoning: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Record a decision provenance edge connecting agent reasoning, telemetry, and actions.
    Also syncs with `graph_edges` table for topology visualizer.
    """
    edge_id = str(uuid.uuid4())
    now_dt = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        try:
            # 1. Record Decision Edge
            edge = DecisionEdge(
                id=edge_id,
                incident_id=incident_id,
                source_node=source_node,
                target_node=target_node,
                edge_type=edge_type,
                agent_name=agent_name,
                reasoning=reasoning,
                metadata_json=metadata or {},
                created_at=now_dt,
            )
            session.add(edge)

            # 2. Record Graph Edge for network topology
            g_edge = GraphEdge(
                id=edge_id,
                incident_id=incident_id,
                source_node=source_node,
                target_node=target_node,
                edge_type=edge_type,
                metadata_json=metadata or {},
                created_at=now_dt,
            )
            session.add(g_edge)

            await session.commit()
            logger.info(
                "Recorded decision provenance edge %s | %s → %s [%s]",
                edge_id,
                source_node,
                target_node,
                agent_name or edge_type,
            )
            return edge.to_dict()
        except Exception as exc:
            await session.rollback()
            logger.warning("PostgreSQL record_decision_edge error: %s", exc)
            return {
                "id": edge_id,
                "source_node": source_node,
                "target_node": target_node,
                "edge_type": edge_type,
            }


# ---------------------------------------------------------------------------
# Forensic Report Helpers
# ---------------------------------------------------------------------------
async def record_report(
    incident_id: str,
    title: str,
    summary: Optional[str] = None,
    content: Optional[Dict[str, Any]] = None,
    generated_by: str = "ReportingAgent",
) -> Dict[str, Any]:
    """
    Persist an incident forensic report in the `reports` table.
    """
    report_id = str(uuid.uuid4())
    now_dt = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        try:
            report = Report(
                id=report_id,
                incident_id=incident_id,
                title=title,
                summary=summary,
                content=content or {},
                generated_by=generated_by,
                created_at=now_dt,
                updated_at=now_dt,
            )
            session.add(report)
            await session.commit()
            logger.info("Persisted forensic report %s for incident %s", report_id, incident_id)
            return report.to_dict()
        except Exception as exc:
            await session.rollback()
            logger.warning("PostgreSQL record_report error: %s", exc)
            return {
                "id": report_id,
                "incident_id": incident_id,
                "title": title,
                "summary": summary,
            }
