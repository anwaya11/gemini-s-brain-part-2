import uuid
import asyncio
import json
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.postgres import get_db, execute_query
from backend.ml.edge_filter import EdgeFilter
from backend.routers.ws import manager, emit_event

router = APIRouter()

# Singleton EdgeFilter instance (loaded once at module import)
edge_filter = EdgeFilter()

# Classification threshold
ESCALATION_THRESHOLD = 0.8


# ---------------------------------------------------------------------------
#  Pydantic Models
# ---------------------------------------------------------------------------

class RawLogPayload(BaseModel):
    """Incoming raw log payload from SIEM, honeypot, or external collector."""
    source_ip: str = Field(..., description="Source IP address of the request")
    destination_ip: str = Field(..., description="Destination IP address")
    endpoint: str = Field(..., description="Target endpoint / URI path")
    method: str = Field(default="GET", description="HTTP method (GET, POST, etc.)")
    headers: Dict[str, Any] = Field(default_factory=dict, description="Request headers")
    body: Optional[str] = Field(default="", description="Request body / payload")
    timestamp: Optional[str] = Field(default=None, description="Event timestamp (ISO 8601)")


class IngestResponse(BaseModel):
    """Response from the ingest pipeline."""
    status: str
    event_id: str
    xgb_score: float
    action: str


# ---------------------------------------------------------------------------
#  Background task: threat processing orchestrator
# ---------------------------------------------------------------------------

async def process_threat(event_id: str, payload: Dict[str, Any], xgb_score: float) -> None:
    """
    Executes the multi-agent SOC orchestrator pipeline for high-confidence threats.
    """
    from backend.agents.orchestrator import run_soc_workflow

    await run_soc_workflow(event_id=event_id, raw_log=payload, xgb_score=xgb_score)


# ---------------------------------------------------------------------------
#  POST /api/ingest — Sub-50ms log ingestion pipeline
# ---------------------------------------------------------------------------

@router.post("/api/ingest", response_model=IngestResponse)
async def ingest_log(
    payload: RawLogPayload,
    background_tasks: BackgroundTasks,
):
    """
    High-throughput log ingestion endpoint.

    Pipeline (target: < 50 ms):
      1. Extract features → compute anomaly score via XGBoost EdgeFilter.
      2. Classify: DROPPED (score < 0.8) or ESCALATED (score >= 0.8).
      3. Persist event to PostgreSQL `events` table (fire-and-forget async).
      4. Broadcast to WebSocket `event_stream` channel.
      5. If ESCALATED, spawn background threat processing task.
    """
    event_id = str(uuid.uuid4())
    now = payload.timestamp or datetime.now(timezone.utc).isoformat()

    # ── 1. Build raw log dict for EdgeFilter ──────────────────────────
    raw_log = {
        "path": payload.endpoint,
        "method": payload.method,
        "body": payload.body or "",
        "headers": payload.headers,
        "user_agent": payload.headers.get("user-agent", payload.headers.get("User-Agent", "")),
        "query_params": "",
        "request_rate_per_sec": 1.0,  # Default; will be enriched by rate limiter in production
        "status_code": 200,
    }

    # ── 2. Score with XGBoost EdgeFilter ──────────────────────────────
    xgb_score = await edge_filter.score_log(raw_log)

    # ── 3. Classify ───────────────────────────────────────────────────
    action = "escalated" if xgb_score >= ESCALATION_THRESHOLD else "dropped"
    severity = "CRITICAL" if xgb_score >= 0.9 else "HIGH" if xgb_score >= ESCALATION_THRESHOLD else "LOW"

    # ── 4. Persist to PostgreSQL (fire-and-forget) ────────────────────
    event_payload = {
        "source_ip": payload.source_ip,
        "destination_ip": payload.destination_ip,
        "endpoint": payload.endpoint,
        "method": payload.method,
        "headers": payload.headers,
        "body": payload.body or "",
        "xgb_score": round(xgb_score, 4),
        "action": action,
    }

    async def _persist():
        try:
            await execute_query(
                """
                INSERT INTO events (id, event_type, source, severity, payload, raw_log, timestamp)
                VALUES (:id, :event_type, :source, :severity, :payload::jsonb, :raw_log, :timestamp)
                """,
                {
                    "id": event_id,
                    "event_type": "http_log",
                    "source": payload.source_ip,
                    "severity": severity,
                    "payload": json.dumps(event_payload),
                    "raw_log": json.dumps(raw_log),
                    "timestamp": now,
                },
            )
        except Exception as e:
            print(f"[Ingest] DB persist error for {event_id}: {e}")

    background_tasks.add_task(asyncio.create_task, _persist())

    # ── 5. Broadcast to WebSocket event_stream ────────────────────────
    background_tasks.add_task(
        emit_event,
        log_id=event_id,
        source=payload.source_ip,
        anomaly_score=xgb_score,
        raw_log=event_payload,
    )

    # ── 6. Escalate threats to agent orchestrator ─────────────────────
    if action == "escalated":
        background_tasks.add_task(
            process_threat,
            event_id,
            event_payload,
            xgb_score,
        )

    return IngestResponse(
        status="accepted",
        event_id=event_id,
        xgb_score=round(xgb_score, 4),
        action=action,
    )
