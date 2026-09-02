import json
import asyncio
import uuid
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime, timezone

router = APIRouter()

# Valid streaming channels
CHANNELS = {
    "event_stream",     # Ingested raw logs with XGBoost DROPPED/ANALYZING tags
    "agent_chatter",    # Live reasoning traces from multi-agent crew
    "incident_stream",  # Staged/contained incidents with risk scores
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_tag_color(agent_name: str) -> str:
    norm = agent_name.upper().replace("AGENT", "").strip()
    if norm in ("INTEL", "TAVILY", "THREATINTEL"):
        return "#00f0ff"
    elif norm in ("ACTION", "SWYTCHCODE", "CONTAINMENT"):
        return "#ff3344"
    elif norm in ("RISK", "RISKENGINE"):
        return "#ffb703"
    elif norm in ("DECEPTION",):
        return "#00ff66"
    elif norm in ("REPORTING",):
        return "#a855f7"
    elif norm in ("ORCHESTRATOR", "LYZR", "LYZR_CORE", "LYZRCORE"):
        return "#38bdf8"
    elif norm in ("TRIAGE",):
        return "#00f0ff"
    return "#00f0ff"


class ConnectionManager:
    """
    Manages active WebSocket connections with per-channel and broadcast support.
    Error-isolated: safe against client dropouts or concurrent async disconnections.
    """

    def __init__(self):
        self._active: List[WebSocket] = []
        self._channel_subs: Dict[str, List[WebSocket]] = {ch: [] for ch in CHANNELS}

    async def connect(self, websocket: WebSocket, channels: List[str] = None) -> None:
        """Accept and register an incoming WebSocket connection."""
        await websocket.accept()
        if websocket not in self._active:
            self._active.append(websocket)

        subscribed = channels if channels else list(CHANNELS)
        for ch in subscribed:
            if ch in self._channel_subs and websocket not in self._channel_subs[ch]:
                self._channel_subs[ch].append(websocket)

        await self._send_to(websocket, {
            "type": "system",
            "channel": "system",
            "payload": {
                "status": "connected",
                "subscriptions": subscribed,
                "timestamp": _utcnow(),
            },
        })

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from all registries."""
        if websocket in self._active:
            self._active.remove(websocket)
        for ch in self._channel_subs:
            if websocket in self._channel_subs[ch]:
                self._channel_subs[ch].remove(websocket)

    async def broadcast(self, channel_or_data: Any, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Broadcast payload to all active WebSocket connections.
        Supports both signatures:
          - manager.broadcast({"type": "chatter", "data": ...})
          - manager.broadcast("agent_chatter", {...})
        """
        if isinstance(channel_or_data, str) and data is not None:
            channel = channel_or_data
            envelope = {
                "type": channel,
                "channel": channel,
                "payload": data,
                "timestamp": _utcnow(),
            }
            raw_text = json.dumps(envelope)
            targets = list(self._channel_subs.get(channel, self._active))
        else:
            raw_text = json.dumps(channel_or_data)
            targets = list(self._active)

        if not targets:
            targets = list(self._active)

        dead: List[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(raw_text)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

    async def send_to_all(self, data: Dict[str, Any]) -> None:
        """Broadcast a message to every connected client."""
        await self.broadcast(data)

    async def send_to(self, websocket: WebSocket, data: Dict[str, Any]) -> None:
        await self._send_to(websocket, data)

    async def _send_to(self, websocket: WebSocket, data: Dict[str, Any]) -> None:
        """Send a message to a single WebSocket connection."""
        try:
            await websocket.send_text(json.dumps(data))
        except Exception:
            self.disconnect(websocket)

    @property
    def connection_count(self) -> int:
        return len(self._active)


# Singleton manager shared across the application
manager = ConnectionManager()


# ---------------------------------------------------------------------------
#  Convenience helpers for emitting to each stream channel
# ---------------------------------------------------------------------------

async def emit_event(log_id: str, source: str, anomaly_score: float, raw_log: dict) -> None:
    """Emit a classified log event to event_stream channel and catch-all feed."""
    THRESHOLD = 0.45
    tag = "ANALYZING" if anomaly_score >= THRESHOLD else "DROPPED"
    payload = {
        "log_id": log_id,
        "source": source,
        "tag": tag,
        "anomaly_score": round(anomaly_score, 4),
        "raw_log": raw_log,
        "timestamp": _utcnow(),
    }
    await manager.broadcast({
        "type": "event_stream",
        "data": payload,
        "payload": payload,
    })


async def emit_agent_chatter(
    agent_name: str,
    reasoning: str,
    step: str = None,
    metadata: dict = None,
    tag_color: str = None,
) -> None:
    """
    Emit a reasoning trace from a CHIMERA agent to the agent_chatter channel and chatter feed.
    """
    color = tag_color or _get_tag_color(agent_name)
    chat_id = f"chat-{uuid.uuid4().hex[:6]}"
    chat_data = {
        "id": chat_id,
        "agent": agent_name,
        "reasoning": reasoning,
        "step": step or "reasoning",
        "metadata": metadata or {},
        "timestamp": _utcnow(),
        "tagColor": color,
    }
    # Broadcast unified payload recognizable by both messageType==='chatter' and messageType==='agent_chatter'
    await manager.broadcast({
        "type": "chatter",
        "data": chat_data,
        "payload": chat_data,
        "channel": "agent_chatter",
    })


async def emit_incident(
    incident_id: str,
    title: str,
    status: str,
    risk_score: float,
    confidence: float,
    blast_radius: dict,
    severity: str = "HIGH",
    metadata: dict = None,
) -> None:
    """
    Emit a staged or contained incident update to the incident_stream channel.
    """
    inc_data = {
        "incident_id": incident_id,
        "id": incident_id,
        "title": title,
        "status": status,
        "severity": severity,
        "risk_score": round(risk_score, 4),
        "confidence": round(confidence, 4),
        "blast_radius": blast_radius,
        "metadata": metadata or {},
        "timestamp": _utcnow(),
    }
    await manager.broadcast({
        "type": "incident_stream",
        "data": inc_data,
        "payload": inc_data,
        "channel": "incident_stream",
    })
