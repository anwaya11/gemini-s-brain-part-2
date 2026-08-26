import json
import asyncio
from typing import Dict, List, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime, timezone

router = APIRouter()

# Valid streaming channels
CHANNELS = {
    "event_stream",     # Ingested raw logs with XGBoost DROPPED/ANALYZING tags
    "agent_chatter",    # Live reasoning traces from multi-agent crew
    "incident_stream",  # Staged/contained incidents with risk scores
}


class ConnectionManager:
    """
    Manages active WebSocket connections with per-channel subscription support.
    Supports targeted channel broadcasting and full-console catch-all connections.
    """

    def __init__(self):
        # All active connections (receive all channels)
        self._active: List[WebSocket] = []
        # Per-channel subscribers (for targeted subscriptions)
        self._channel_subs: Dict[str, List[WebSocket]] = {ch: [] for ch in CHANNELS}

    async def connect(self, websocket: WebSocket, channels: List[str] = None) -> None:
        """
        Accept and register an incoming WebSocket connection.
        Optionally subscribe to specific channels; defaults to all channels.
        """
        await websocket.accept()
        self._active.append(websocket)

        subscribed = channels if channels else list(CHANNELS)
        for ch in subscribed:
            if ch in self._channel_subs:
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
        """
        Remove a WebSocket from all active and channel-specific registries.
        """
        if websocket in self._active:
            self._active.remove(websocket)
        for ch in self._channel_subs:
            if websocket in self._channel_subs[ch]:
                self._channel_subs[ch].remove(websocket)

    async def broadcast(self, channel: str, data: Dict[str, Any]) -> None:
        """
        Broadcast a structured message to all subscribers of a given channel.
        Automatically disconnects stale/closed connections.
        """
        if channel not in CHANNELS:
            return

        envelope = {
            "type": channel,
            "channel": channel,
            "payload": data,
            "timestamp": _utcnow(),
        }

        dead: List[WebSocket] = []
        for ws in list(self._channel_subs.get(channel, [])):
            try:
                await ws.send_text(json.dumps(envelope))
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

    async def send_to_all(self, data: Dict[str, Any]) -> None:
        """Broadcast a system message to every connected client."""
        dead: List[WebSocket] = []
        for ws in list(self._active):
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        return len(self._active)

    async def _send_to(self, websocket: WebSocket, data: Dict[str, Any]) -> None:
        """Send a message to a single WebSocket connection."""
        try:
            await websocket.send_text(json.dumps(data))
        except Exception:
            self.disconnect(websocket)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# Singleton manager shared across the application
manager = ConnectionManager()


# ---------------------------------------------------------------------------
#  WebSocket Endpoint: /ws/console
# ---------------------------------------------------------------------------
@router.websocket("/ws/console")
async def ws_console(websocket: WebSocket):
    """
    Primary WebSocket console endpoint consumed by the Next.js frontend.

    Streams three live data channels to registered clients:

      - event_stream    : Ingested logs tagged DROPPED or ANALYZING by XGBoost EdgeFilter.
      - agent_chatter   : Real-time reasoning traces from the multi-agent CHIMERA crew.
      - incident_stream : Staged or contained incidents with full risk metadata.

    Clients may optionally send a JSON subscription message on connect:
        { "subscribe": ["event_stream", "incident_stream"] }
    to limit which channels they receive. Defaults to all channels.
    """
    # Read optional subscription preferences before accepting
    channels = None
    try:
        # Accept first, then optionally wait briefly for a subscription payload
        await websocket.accept()
        # We manually accepted — re-use our internal method without double-accept
        manager._active.append(websocket)

        subscribed = list(CHANNELS)
        for ch in subscribed:
            if ch in manager._channel_subs:
                manager._channel_subs[ch].append(websocket)

        await manager._send_to(websocket, {
            "type": "system",
            "channel": "system",
            "payload": {
                "status": "connected",
                "subscriptions": subscribed,
                "client_count": manager.connection_count,
                "timestamp": _utcnow(),
            },
        })

        # Listen for incoming control messages from the client
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
                msg = json.loads(raw)

                # Handle channel subscription changes
                if "subscribe" in msg and isinstance(msg["subscribe"], list):
                    # Remove old subs
                    for ch in manager._channel_subs:
                        if websocket in manager._channel_subs[ch]:
                            manager._channel_subs[ch].remove(websocket)
                    # Apply new subs
                    new_subs = [ch for ch in msg["subscribe"] if ch in CHANNELS]
                    for ch in new_subs:
                        manager._channel_subs[ch].append(websocket)
                    await manager._send_to(websocket, {
                        "type": "system",
                        "channel": "system",
                        "payload": {
                            "status": "resubscribed",
                            "subscriptions": new_subs,
                            "timestamp": _utcnow(),
                        },
                    })

                # Handle client ping
                elif msg.get("type") == "ping":
                    await manager._send_to(websocket, {
                        "type": "pong",
                        "channel": "system",
                        "payload": {"timestamp": _utcnow()},
                    })

            except asyncio.TimeoutError:
                # Send keepalive heartbeat to detect dead connections
                await manager._send_to(websocket, {
                    "type": "heartbeat",
                    "channel": "system",
                    "payload": {
                        "status": "alive",
                        "client_count": manager.connection_count,
                        "timestamp": _utcnow(),
                    },
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
#  Convenience helpers for emitting to each stream channel
# ---------------------------------------------------------------------------

async def emit_event(log_id: str, source: str, anomaly_score: float, raw_log: dict) -> None:
    """
    Emit a classified log event to the event_stream channel.
    Tags the event as DROPPED (below threshold) or ANALYZING (above threshold).
    """
    THRESHOLD = 0.45
    tag = "ANALYZING" if anomaly_score >= THRESHOLD else "DROPPED"
    await manager.broadcast("event_stream", {
        "log_id": log_id,
        "source": source,
        "tag": tag,
        "anomaly_score": round(anomaly_score, 4),
        "raw_log": raw_log,
        "timestamp": _utcnow(),
    })


async def emit_agent_chatter(agent_name: str, reasoning: str, step: str = None, metadata: dict = None) -> None:
    """
    Emit a reasoning trace from a CHIMERA agent to the agent_chatter channel.
    """
    await manager.broadcast("agent_chatter", {
        "agent": agent_name,
        "step": step or "reasoning",
        "reasoning": reasoning,
        "metadata": metadata or {},
        "timestamp": _utcnow(),
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
    await manager.broadcast("incident_stream", {
        "incident_id": incident_id,
        "title": title,
        "status": status,
        "severity": severity,
        "risk_score": round(risk_score, 4),
        "confidence": round(confidence, 4),
        "blast_radius": blast_radius,
        "metadata": metadata or {},
        "timestamp": _utcnow(),
    })
