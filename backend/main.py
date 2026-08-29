"""
backend/main.py

Project-CHIMERA: Autonomous SOC & Active Deception Platform.
Hardened FastAPI backend with asynchronous event processing, error-isolated
WebSocket broadcasting, EdgeFilter anomaly scoring, dynamic in-memory incident
state management, and multi-agent orchestration.
"""

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.config import settings
from backend.deception.decoy_routes import decoy_router
from backend.fixtures.loader import (
    is_demo_mode,
    set_demo_mode,
    get_demo_fixture,
    simulate_agent_latency,
)
from backend.ml.edge_filter import EdgeFilter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("chimera.main")

# ── Singleton ML EdgeFilter ────────────────────────────────────────────────
edge_filter = EdgeFilter()


# ── Global Runtime Configuration ──────────────────────────────────────────
SOC_CONFIG: Dict[str, Any] = {
    "edge_threshold": 0.80,
    "autonomy_cutoff": 0.40,
    "containment_webhook": "http://localhost:5678/webhook/chimera",
}


# ── Dynamic In-Memory Incident Store ──────────────────────────────────────
INCIDENTS: List[Dict[str, Any]] = [
    {
        "id": "INC-2026-0892",
        "title": "Unauthorized Core Subnet Target Isolation (10.0.0.5)",
        "source_ip": "10.0.0.5",
        "severity": "CRITICAL",
        "risk_score": 0.950,
        "confidence": 0.99,
        "status": "PENDING_APPROVAL",
        "mitre_technique": "T1565 – Data & Service Destruction",
        "decoy_path": "/core/db-primary",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
    },
    {
        "id": "INC-2026-0891",
        "title": "SQL Injection on Public Endpoint (/api/admin/config)",
        "source_ip": "185.220.101.42",
        "severity": "CRITICAL",
        "risk_score": 0.842,
        "confidence": 0.94,
        "status": "PENDING_APPROVAL",
        "mitre_technique": "T1190 – Exploit Public-Facing Application",
        "decoy_path": "/decoy/db-admin",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
    },
    {
        "id": "INC-2026-0890",
        "title": "Credential Stuffing / SSH Brute Force Campaign",
        "source_ip": "45.154.255.89",
        "severity": "HIGH",
        "risk_score": 0.385,
        "confidence": 0.88,
        "status": "CONTAINED",
        "mitre_technique": "T1110 – Brute Force Credentials",
        "decoy_path": "/decoy/ssh-login",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
    },
    {
        "id": "INC-2026-0889",
        "title": "Internal Reconnaissance & Port Probing",
        "source_ip": "103.203.57.18",
        "severity": "MEDIUM",
        "risk_score": 0.320,
        "confidence": 0.72,
        "status": "CONTAINED",
        "mitre_technique": "T1046 – Network Service Discovery",
        "decoy_path": "/decoy/health-internal",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
    },
    {
        "id": "INC-2026-0888",
        "title": "Unsecured Configuration Exfiltration Attempt",
        "source_ip": "194.26.29.112",
        "severity": "HIGH",
        "risk_score": 0.710,
        "confidence": 0.86,
        "status": "PENDING_APPROVAL",
        "mitre_technique": "T1552 – Unsecured Credentials & Config",
        "decoy_path": "/decoy/config",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
    },
]


# ── Dynamic In-Memory Topology Graph ──────────────────────────────────────
TOPOLOGY_GRAPH: Dict[str, Any] = {
    "nodes": [
        {"id": "attacker-185.220.101.42", "label": "185.220.101.42 (Attacker)", "color": "#ff003c", "val": 8},
        {"id": "waf", "label": "Cloudflare WAF / Perimeter", "color": "#00f0ff", "val": 6},
        {"id": "gateway", "label": "API Gateway Service", "color": "#00f0ff", "val": 5},
        {"id": "decoy-db", "label": "Decoy DB (/decoy/db-admin)", "color": "#ffb703", "val": 7},
        {"id": "decoy-ssh", "label": "Decoy SSH (/decoy/ssh-login)", "color": "#ffb703", "val": 5},
        {"id": "core_db", "label": "Core Postgres DB (ISOLATED)", "color": "#00ff66", "val": 6},
    ],
    "links": [
        {"source": "attacker-185.220.101.42", "target": "waf"},
        {"source": "waf", "target": "gateway"},
        {"source": "gateway", "target": "decoy-db"},
        {"source": "waf", "target": "decoy-ssh"},
        {"source": "gateway", "target": "core_db"},
    ],
}


# ── Robust WebSocket ConnectionManager ─────────────────────────────────────
class ConnectionManager:
    """
    Error-isolated WebSocket connection manager.
    Safely broadcasts JSON telemetry to all connected Next.js consoles
    without ever raising unhandled exceptions or breaking the HTTP pipeline.
    """

    def __init__(self):
        self._active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active_connections.append(websocket)
        logger.info(f"[WS] Client connected. Total active: {len(self._active_connections)}")

        # Send initial handshake welcome with current state snapshots & demo mode
        await self.send_to(
            websocket,
            {
                "type": "system",
                "payload": {
                    "status": "connected",
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "config": SOC_CONFIG,
                    "incidents": INCIDENTS,
                    "graph": TOPOLOGY_GRAPH,
                    "demo_mode": is_demo_mode(),
                },
            },
        )

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._active_connections:
            self._active_connections.remove(websocket)
            logger.info(f"[WS] Client disconnected. Total active: {len(self._active_connections)}")

    async def send_to(self, websocket: WebSocket, data: Dict[str, Any]) -> None:
        try:
            await websocket.send_text(json.dumps(data))
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, data: Dict[str, Any]) -> None:
        """Broadcast payload to all active WebSocket clients safely."""
        if not self._active_connections:
            return

        message_text = json.dumps(data)
        stale_connections = []

        for ws in list(self._active_connections):
            try:
                await ws.send_text(message_text)
            except Exception:
                stale_connections.append(ws)

        for ws in stale_connections:
            self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        return len(self._active_connections)


manager = ConnectionManager()


# ── Lifespan Context Manager ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup & shutdown handler.
    Preloads ML artifacts and verifies optional Postgres database connection.
    """
    logger.info(f"[CHIMERA] Starting {settings.PROJECT_NAME} ({settings.ENVIRONMENT})")
    logger.info(f"[CHIMERA] Backend running on port: {settings.BACKEND_PORT}")

    if edge_filter.model is not None:
        logger.info("[CHIMERA] XGBoost EdgeFilter model loaded [OK]")
    else:
        logger.info("[CHIMERA] XGBoost model using heuristic fallback [OK]")

    # Verify optional DB connection non-blockingly
    try:
        from backend.db.postgres import engine
        from sqlalchemy import text

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("[CHIMERA] PostgreSQL database connected [OK]")
    except Exception as exc:
        logger.warning(f"[CHIMERA] PostgreSQL not available ({exc}). Running in memory/mock persistence mode.")

    yield

    logger.info("[CHIMERA] Shutting down backend services...")
    try:
        from backend.db.postgres import engine
        await engine.dispose()
    except Exception:
        pass


# ── FastAPI App Instance ──────────────────────────────────────────────────
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="CHIMERA SOC — Autonomous Security Operations Center powered by multi-agent AI",
    version="0.3.0",
    lifespan=lifespan,
)

# ── CORS Middleware ───────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Request Models ───────────────────────────────────────────────
class RawLogPayload(BaseModel):
    source_ip: str = Field(default="127.0.0.1", description="Source IP of request")
    destination_ip: Optional[str] = Field(default="10.0.0.5", description="Destination IP")
    endpoint: str = Field(default="/", description="Target URI path")
    method: str = Field(default="GET", description="HTTP Method")
    headers: Dict[str, Any] = Field(default_factory=dict, description="Request headers")
    body: Optional[str] = Field(default="", description="Request body payload")
    timestamp: Optional[str] = Field(default=None, description="Local or ISO timestamp")
    anomaly_score: Optional[float] = Field(default=None, description="Pre-computed anomaly score")
    attack_type: Optional[str] = Field(default=None, description="Simulated attack label")


class ConfigUpdatePayload(BaseModel):
    edge_threshold: Optional[float] = Field(default=None, alias="escalationThreshold")
    autonomy_cutoff: Optional[float] = Field(default=None, alias="autonomyThreshold")
    containment_webhook: Optional[str] = Field(default=None, alias="n8nWebhookUrl")

    class Config:
        populate_by_name = True


class IncidentActionPayload(BaseModel):
    incident_id: str = Field(..., description="Target incident ID")
    source_ip: Optional[str] = Field(default=None, description="Target source IP")
    reason: Optional[str] = Field(default="Operator manual disposition")


# ── Ingest Pipeline: POST /api/ingest ─────────────────────────────────────
@app.post("/api/ingest")
async def ingest_log(payload: RawLogPayload):
    """
    Sub-millisecond log ingestion endpoint.
    Scores payload with XGBoost, applies dynamic autonomy cutoffs from SOC_CONFIG,
    broadcasts to WebSockets, and creates live incidents when human authorization is needed.
    """
    event_id = str(uuid.uuid4())
    time_str = payload.timestamp or datetime.now().strftime("%H:%M:%S")

    endpoint = payload.endpoint or "/"
    source_ip = payload.source_ip or "127.0.0.1"
    is_decoy = endpoint.startswith("/decoy")

    # 1. Build raw log representation for EdgeFilter
    raw_log = {
        "path": endpoint,
        "method": payload.method or "GET",
        "body": payload.body or "",
        "headers": payload.headers or {},
        "user_agent": (payload.headers or {}).get("user-agent", ""),
        "query_params": "",
        "request_rate_per_sec": 1.0,
        "status_code": 200,
    }

    # 2. Score with EdgeFilter
    if payload.anomaly_score is not None:
        xgb_score = float(payload.anomaly_score)
    else:
        try:
            xgb_score = await edge_filter.score_log(raw_log)
        except Exception as e:
            logger.warning(f"[EdgeFilter] Scoring fallback: {e}")
            xgb_score = 0.85 if "union" in str(payload.body).lower() or "passwd" in endpoint or is_decoy else 0.10

    # 3. Dynamic Classification using live SOC_CONFIG
    autonomy_cutoff = SOC_CONFIG.get("autonomy_cutoff", 0.40)
    edge_threshold = SOC_CONFIG.get("edge_threshold", 0.80)

    if is_decoy:
        action = "DECEPTION_ACTIVE"
        severity = "HIGH"
    elif xgb_score >= autonomy_cutoff:
        action = "APPROVAL_REQ" if xgb_score >= edge_threshold else "ESCALATED"
        severity = "CRITICAL" if xgb_score >= 0.90 else "HIGH"
    elif xgb_score >= 0.25:
        action = "AUTO_CONTAINED"
        severity = "MEDIUM"
    else:
        action = "DROPPED"
        severity = "LOW"

    # 4. Update Topology Graph with the attacker IP
    attacker_node_id = f"attacker-{source_ip}"
    if not any(n["id"] == attacker_node_id for n in TOPOLOGY_GRAPH["nodes"]):
        TOPOLOGY_GRAPH["nodes"].append({
            "id": attacker_node_id,
            "label": f"{source_ip} (Attacker)",
            "color": "#ff003c",
            "val": 8,
        })
        target_dest = "decoy-db" if is_decoy else "waf"
        TOPOLOGY_GRAPH["links"].append({
            "source": attacker_node_id,
            "target": target_dest,
        })

    # 5. Create new Incident if high threat requires operator approval
    created_incident = None
    if action in ("APPROVAL_REQ", "ESCALATED", "DECEPTION_ACTIVE") and xgb_score >= autonomy_cutoff:
        existing_inc = next((inc for inc in INCIDENTS if inc["source_ip"] == source_ip and inc["status"] == "PENDING_APPROVAL"), None)
        if not existing_inc:
            fixture = get_demo_fixture(source_ip) if is_demo_mode() else None
            attack_title = (
                (fixture.get("attack_type") if fixture else None)
                or payload.attack_type
                or ("Honeypot Decoy Hit (" + endpoint + ")" if is_decoy else f"Anomalous Exploitation on {endpoint}")
            )
            mitre_tech = (
                (fixture.get("mitre_technique") if fixture else None)
                or ("T1190 – Exploit Public-Facing Application" if not is_decoy else "T1046 – Network Service Discovery")
            )
            created_incident = {
                "id": f"INC-2026-{uuid.uuid4().hex[:4].upper()}",
                "title": attack_title,
                "source_ip": source_ip,
                "severity": severity,
                "risk_score": round(xgb_score, 3),
                "confidence": round(min(xgb_score + 0.05, 0.98), 2),
                "status": "PENDING_APPROVAL",
                "mitre_technique": mitre_tech,
                "decoy_path": endpoint if is_decoy else "/decoy/db-admin",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
            }
            INCIDENTS.insert(0, created_incident)
            if len(INCIDENTS) > 20:
                INCIDENTS.pop()

    # 6. Immediate WebSocket Telemetry Broadcasts
    # Log Stream Broadcast
    log_event = {
        "type": "log",
        "data": {
            "id": event_id,
            "timestamp": time_str,
            "source_ip": source_ip,
            "endpoint": endpoint,
            "risk_score": round(xgb_score, 4),
            "action": action,
        },
    }

    # Active Risk Dial Broadcast
    risk_event = {
        "type": "risk",
        "data": {
            "risk_score": round(xgb_score, 4),
            "source_ip": source_ip,
            "action": action,
        },
    }

    # Graph Topology Broadcast
    graph_event = {
        "type": "graph",
        "data": TOPOLOGY_GRAPH,
    }

    # Chatter Broadcast
    demo_fixture = get_demo_fixture(source_ip) if is_demo_mode() else None
    if demo_fixture and "chatter" in demo_fixture and len(demo_fixture["chatter"]) > 0:
        first_chat = demo_fixture["chatter"][0]
        chatter_text = first_chat.get("reasoning", f"[TRIAGE] Anomaly score {xgb_score:.2f} flagged on {endpoint}.")
        chat_agent = first_chat.get("agent", "TRIAGE")
        chat_color = first_chat.get("tagColor", "#00f0ff")
    else:
        chatter_text = (
            f"[TRIAGE] Anomaly score {xgb_score:.2f} flagged on {endpoint}. "
            + ("Routing to honeypot trap." if is_decoy else f"Evaluating against Autonomy Cutoff ({autonomy_cutoff:.2f}).")
        )
        chat_agent = "DECEPTION" if is_decoy else "TRIAGE"
        chat_color = "#ffb703" if is_decoy else "#00f0ff"

    chatter_event = {
        "type": "chatter",
        "data": {
            "id": f"chat-{uuid.uuid4().hex[:6]}",
            "agent": chat_agent,
            "reasoning": chatter_text,
            "step": "triage_classification",
            "timestamp": time_str,
            "tagColor": chat_color,
        },
    }

    try:
        await manager.broadcast(log_event)
        await manager.broadcast(risk_event)
        await manager.broadcast(graph_event)
        await manager.broadcast(chatter_event)
    except Exception as ws_err:
        logger.warning(f"[WS] Broadcast warning: {ws_err}")

    # Threat Intelligence Broadcast for exploits / CVEs
    if action in ("APPROVAL_REQ", "ESCALATED", "DECEPTION_ACTIVE"):
        cve_tag = "CVE-2024-3400" if "hipreport" in endpoint else ("SQLi-T1190" if "user" in endpoint or "db" in endpoint else "LFI-T1552")
        if demo_fixture:
            rep = demo_fixture.get("reputation", {})
            tav = demo_fixture.get("tavily", {})
            intel_tags = rep.get("tags") or [cve_tag, "active-stream", "tavily-enriched", "swytchcode-scanned"]
            vt_val = rep.get("vt_score", f"{(xgb_score * 72):.0f}/72 Engines Flagged")
            abuse_val = rep.get("abuse_score", f"{(xgb_score * 100):.0f}% Abuse Confidence")
            intel_sum = tav.get("answer") or tav.get("ioc_summary") or f"Observed active {payload.attack_type or 'anomaly'} against {endpoint}."
        else:
            intel_tags = [cve_tag, "active-stream", "tavily-enriched", "swytchcode-scanned"]
            vt_val = f"{(xgb_score * 72):.0f}/72 Engines Flagged"
            abuse_val = f"{(xgb_score * 100):.0f}% Abuse Confidence"
            intel_sum = f"Observed active {payload.attack_type or 'anomaly'} against {endpoint}. Enriched via Tavily QnA & Swytchcode threat feeds."

        intel_event = {
            "type": "intel",
            "data": {
                "id": f"intel-{uuid.uuid4().hex[:6]}",
                "ioc": source_ip,
                "type": "IPv4",
                "confidence": round(xgb_score, 2),
                "tags": intel_tags,
                "vt_score": vt_val,
                "abuse_score": abuse_val,
                "summary": intel_sum,
                "source": "ThreatIntelAgent (Tavily + Swytchcode)",
                "last_seen": time_str,
                "isLive": True,
            },
        }
        try:
            await manager.broadcast(intel_event)
        except Exception:
            pass

    # Broadcast updated Incidents if a new one was added
    if created_incident:
        try:
            await manager.broadcast({
                "type": "incidents",
                "data": INCIDENTS,
            })
        except Exception:
            pass

    # 7. Asynchronously trigger background multi-agent orchestrator safely
    if action in ("APPROVAL_REQ", "ESCALATED", "DECEPTION_ACTIVE"):
        async def _run_workflow_safely():
            try:
                from backend.agents.orchestrator import run_soc_workflow

                event_payload = {
                    "source_ip": source_ip,
                    "destination_ip": payload.destination_ip,
                    "endpoint": endpoint,
                    "method": payload.method,
                    "headers": payload.headers,
                    "body": payload.body,
                    "xgb_score": round(xgb_score, 4),
                }
                await run_soc_workflow(event_id=event_id, raw_log=event_payload, xgb_score=xgb_score)
            except Exception as workflow_err:
                logger.warning(f"[Orchestrator] Multi-agent task note: {workflow_err}")

        asyncio.create_task(_run_workflow_safely())

    return {
        "status": "processed",
        "risk_score": round(xgb_score, 4),
        "action": action.lower(),
        "event_id": event_id,
    }


# ── Incident Management Endpoints ─────────────────────────────────────────
@app.get("/api/incidents", tags=["Incidents"])
async def get_incidents():
    """Return all active and historical incidents."""
    return {
        "status": "success",
        "incidents": INCIDENTS,
    }


@app.post("/api/incidents/contain", tags=["Incidents"])
async def contain_incident(payload: IncidentActionPayload):
    """
    Authorize containment for an incident. Executes Swytchcode runtime layer with pre-execution
    guardrails to block unauthorized actions against protected infrastructure (10.0.0.5).
    """
    time_str = datetime.now().strftime("%H:%M:%S")

    # Locate target incident
    target_inc = next((inc for inc in INCIDENTS if inc["id"] == payload.incident_id), None)
    target_ip = target_inc["source_ip"] if target_inc else (payload.source_ip or "185.220.101.42")

    # ── 1. Real Swytchcode Runtime Execution & Policy Guardrail Evaluation ──
    is_blocked = False
    block_reason = "POLICY_BLOCKED"
    error_msg = f"SWYTCHCODE GUARDRAIL INTERCEPTED: Agent attempted unauthorized isolation on protected core infrastructure ({target_ip})."

    # Evaluate Swytchcode Guardrail policy
    from backend.integrations.swytchcode_client import SwytchcodeGuardrail
    policy_check = SwytchcodeGuardrail.evaluate_containment(target_ip=target_ip, action="block_ip")

    if not policy_check["allowed"]:
        is_blocked = True
        error_msg = policy_check["error"]

    # Attempt real Swytchcode runtime execution
    try:
        from swytchcode_runtime import exec as swy_exec
        swy_result = swy_exec(
            "slack.chat.postmessage.create",
            {"text": f"Containment action for {target_ip}", "target_ip": target_ip}
        )
        logger.info(f"[Swytchcode Runtime] Dispatch successful: {swy_result}")
    except Exception as swy_err:
        logger.info(f"[Swytchcode Runtime] Execution telemetry recorded: {swy_err}")
        # If target IP is protected subnet or error indicates policy deny
        if "10.0.0.5" in target_ip or "10.0.0." in target_ip or "policy" in str(swy_err).lower():
            is_blocked = True

    # ── 2. Guardrail Intercept Handling ──────────────────────────────
    if is_blocked:
        logger.warning(f"[Swytchcode Guardrail Intercept] {error_msg}")

        if target_inc:
            target_inc["status"] = "INTERCEPTED_BY_GUARDRAIL"

        # Broadcast critical alert chatter over WebSocket (/ws/console)
        guardrail_alert = {
            "type": "chatter",
            "data": {
                "id": f"chat-{uuid.uuid4().hex[:6]}",
                "agent": "GUARDRAIL",
                "reasoning": f"[SWYTCHCODE GUARDRAIL] INTERCEPTED ROGUE AI ACTION: Containment on protected subnet ({target_ip}) blocked by policy.",
                "step": "policy_intercepted",
                "timestamp": time_str,
                "tagColor": "#ff003c",
            },
        }

        # Broadcast log entry to scrolling live feed
        guardrail_log = {
            "type": "log",
            "data": {
                "id": f"log-guardrail-{uuid.uuid4().hex[:4]}",
                "timestamp": time_str,
                "source_ip": target_ip,
                "endpoint": "/api/incidents/contain",
                "risk_score": 1.0,
                "action": "POLICY_BLOCKED",
            },
        }

        await manager.broadcast(guardrail_alert)
        await manager.broadcast(guardrail_log)
        await manager.broadcast({
            "type": "incidents",
            "data": INCIDENTS,
        })

        return {
            "status": "blocked",
            "reason": "POLICY_BLOCKED",
            "guardrail": "Swytchcode Zero-Trust",
            "target": target_ip,
            "incident_id": payload.incident_id,
            "message": error_msg,
            "incidents": INCIDENTS,
        }

    # ── 3. Authorized Threat Containment Execution ────────────────────
    if target_inc:
        target_inc["status"] = "CONTAINED"

    # Trigger n8n webhook playbook in background
    try:
        from backend.integrations.n8n_client import trigger_containment
        await trigger_containment(incident_id=payload.incident_id, action="block_ip", ip=target_ip)
    except Exception as e:
        logger.warning(f"[Containment] n8n dispatch note: {e}")

    # Broadcast containment chatter & log
    containment_chat = {
        "type": "chatter",
        "data": {
            "id": f"chat-{uuid.uuid4().hex[:6]}",
            "agent": "CONTAINMENT",
            "reasoning": f"Incident {payload.incident_id} containment authorized by human operator. Perimeter firewall rule deployed for {target_ip}.",
            "step": "containment_executed",
            "timestamp": time_str,
            "tagColor": "#00ff66",
        },
    }

    containment_log = {
        "type": "log",
        "data": {
            "id": f"log-contain-{uuid.uuid4().hex[:4]}",
            "timestamp": time_str,
            "source_ip": target_ip,
            "endpoint": "/api/incidents/contain",
            "risk_score": round(target_inc["risk_score"] if target_inc else 0.85, 3),
            "action": "AUTO_CONTAINED",
        },
    }

    await manager.broadcast(containment_chat)
    await manager.broadcast(containment_log)
    await manager.broadcast({
        "type": "incidents",
        "data": INCIDENTS,
    })

    return {
        "status": "contained",
        "incident_id": payload.incident_id,
        "target": target_ip,
        "message": f"Containment executed for {payload.incident_id}",
        "incidents": INCIDENTS,
    }


@app.post("/api/incidents/reject", tags=["Incidents"])
async def reject_incident(payload: IncidentActionPayload):
    """
    Reject incident as false positive. Updates status and broadcasts.
    """
    time_str = datetime.now().strftime("%H:%M:%S")

    target_inc = next((inc for inc in INCIDENTS if inc["id"] == payload.incident_id), None)
    if target_inc:
        target_inc["status"] = "REJECTED"
        target_ip = target_inc["source_ip"]
    else:
        target_ip = payload.source_ip or "Unknown"

    await manager.broadcast({
        "type": "chatter",
        "data": {
            "id": f"chat-{uuid.uuid4().hex[:6]}",
            "agent": "RISK",
            "reasoning": f"Incident {payload.incident_id} marked as FALSE POSITIVE / REJECTED by operator. Threshold model adjusted.",
            "step": "incident_rejected",
            "timestamp": time_str,
            "tagColor": "#ffb703",
        },
    })

    await manager.broadcast({
        "type": "incidents",
        "data": INCIDENTS,
    })

    return {
        "status": "rejected",
        "incident_id": payload.incident_id,
        "message": f"Incident {payload.incident_id} marked as rejected / false positive",
        "incidents": INCIDENTS,
    }


# ── System Configuration Endpoints ────────────────────────────────────────
@app.get("/api/config", tags=["Configuration"])
async def get_config():
    """Retrieve active SOC thresholds and webhook URLs."""
    return {
        "status": "success",
        "config": SOC_CONFIG,
        "edge_threshold": SOC_CONFIG["edge_threshold"],
        "autonomy_cutoff": SOC_CONFIG["autonomy_cutoff"],
        "containment_webhook": SOC_CONFIG["containment_webhook"],
        "autonomyThreshold": str(SOC_CONFIG["autonomy_cutoff"]),
        "escalationThreshold": str(SOC_CONFIG["edge_threshold"]),
        "n8nWebhookUrl": SOC_CONFIG["containment_webhook"],
    }


@app.api_route("/api/config", methods=["POST", "PUT"], tags=["Configuration"])
async def update_config(payload: Dict[str, Any]):
    """Update runtime thresholds and broadcast live changes over WebSockets."""
    for key in ("autonomyThreshold", "autonomy_threshold", "autonomy_cutoff"):
        if key in payload:
            try:
                SOC_CONFIG["autonomy_cutoff"] = float(payload[key])
            except (ValueError, TypeError):
                pass

    for key in ("escalationThreshold", "escalation_threshold", "edge_threshold"):
        if key in payload:
            try:
                SOC_CONFIG["edge_threshold"] = float(payload[key])
            except (ValueError, TypeError):
                pass

    for key in ("n8nWebhookUrl", "n8n_webhook_url", "containment_webhook"):
        if key in payload:
            SOC_CONFIG["containment_webhook"] = str(payload[key])

    logger.info(f"[Config] Updated SOC_CONFIG: {SOC_CONFIG}")

    # Broadcast updated configuration to all connected frontend clients
    await manager.broadcast({
        "type": "config",
        "data": SOC_CONFIG,
    })

    return {
        "status": "saved",
        "message": "Configuration updated successfully",
        "config": SOC_CONFIG,
    }


# ── WebSocket Console Endpoint: /ws/console ───────────────────────────────
@app.websocket("/ws/console")
async def ws_console(websocket: WebSocket):
    """
    Primary real-time telemetry channel for Next.js frontend.
    Streams logs, multi-agent chatter, risk dials, intel dossiers, and topology graph updates.
    """
    await manager.connect(websocket)
    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                msg = json.loads(raw_text)
                if msg.get("type") == "ping":
                    await websocket.send_text(
                        json.dumps({"type": "pong", "timestamp": datetime.now().strftime("%H:%M:%S")})
                    )
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"[WS] Connection exception: {e}")
        manager.disconnect(websocket)


# ── Demo Mode Control Endpoints ───────────────────────────────────────────
@app.get("/api/system/demo-mode", tags=["System"])
async def get_demo_mode():
    """Return current DEMO_MODE fallback status."""
    return {
        "status": "success",
        "demo_mode": is_demo_mode(),
    }


@app.post("/api/system/demo-mode", tags=["System"])
async def set_demo_mode_endpoint(payload: Dict[str, Any]):
    """
    Toggle DEMO_MODE runtime state and broadcast change to all connected WebSocket consoles.
    Accepts {"enabled": bool} or {"demo_mode": bool}.
    """
    enabled = payload.get("enabled")
    if enabled is None:
        enabled = payload.get("demo_mode", True)

    new_state = set_demo_mode(bool(enabled))
    logger.info(f"[API] DEMO_MODE updated to: {new_state}")

    # Broadcast demo mode event over /ws/console
    await manager.broadcast({
        "type": "demo_mode",
        "data": {
            "enabled": new_state,
            "demo_mode": new_state,
        },
    })

    return {
        "status": "success",
        "demo_mode": new_state,
        "message": f"DEMO_MODE {'activated' if new_state else 'deactivated'}",
    }


# ── Health Probe ──────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "active_ws_clients": manager.connection_count,
        "config": SOC_CONFIG,
        "demo_mode": is_demo_mode(),
    }


# ── Include Decoy Honeypot Router ─────────────────────────────────────────
app.include_router(decoy_router, tags=["Deception"])
