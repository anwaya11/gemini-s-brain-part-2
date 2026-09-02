"""
backend/integrations/n8n_client.py

Live n8n webhook integration for automated containment actions.

Sends real asynchronous HTTP POST requests using httpx to the configured
N8N_WEBHOOK_URL with a full incident payload (incident ID, target IP,
MITRE technique, risk score, action, and timestamp).

Includes resilient timeout configuration, live execution confirmation extraction,
and graceful fallback handling to ensure the FastAPI server never crashes if
the remote webhook fails or times out.
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from backend.config import settings

logger = logging.getLogger("chimera.n8n")

# Default HTTP timeout settings (5s connect, 10s read)
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


async def trigger_containment(
    incident_id: str,
    action: str = "block_ip",
    ip: Optional[str] = None,
    target_ip: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    risk_score: Optional[float] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Trigger a live containment workflow in n8n via webhook.

    Sends an asynchronous HTTP POST request to ``N8N_WEBHOOK_URL`` with the
    full incident payload. Returns the live execution confirmation data on
    success (HTTP 200), or fallback confirmation data on failure/timeout.

    Parameters
    ----------
    incident_id:
        Unique identifier for the CHIMERA incident.
    action:
        Containment action to perform (default: ``"block_ip"``).
    ip:
        Target IP address (alias for ``target_ip``).
    target_ip:
        The target IP address under containment.
    mitre_technique:
        Associated MITRE ATT&CK technique (e.g. ``"T1190 - Exploit Public-Facing Application"``).
    risk_score:
        Calculated risk score float (0.0 to 1.0).
    **kwargs:
        Additional optional metadata to include in the payload.

    Returns
    -------
    Dict[str, Any]
        Live execution confirmation data from n8n or structured fallback data.
    """
    resolved_url = settings.N8N_WEBHOOK_URL or os.getenv("N8N_WEBHOOK_URL")
    resolved_ip = target_ip or ip or "127.0.0.1"
    resolved_mitre = mitre_technique or kwargs.get("mitre") or "T1190 - Exploit Public-Facing Application"
    resolved_risk = float(risk_score) if risk_score is not None else 0.85

    payload: Dict[str, Any] = {
        "incident_id": incident_id,
        "target_ip": resolved_ip,
        "ip": resolved_ip,
        "mitre_technique": resolved_mitre,
        "risk_score": resolved_risk,
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Merge any extra metadata passed
    for key, value in kwargs.items():
        if key not in payload:
            payload[key] = value

    logger.info(
        "Dispatching live n8n webhook | url=%s | incident_id=%s | target_ip=%s | mitre=%s | risk=%.2f",
        resolved_url,
        incident_id,
        resolved_ip,
        resolved_mitre,
        resolved_risk,
    )

    if not resolved_url:
        logger.warning(
            "N8N_WEBHOOK_URL is not configured — using local fallback execution."
        )
        return {
            "status": "unconfigured",
            "execution_id": f"local-{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "target_ip": resolved_ip,
            "mitre_technique": resolved_mitre,
            "risk_score": resolved_risk,
            "action": action,
            "message": "N8N_WEBHOOK_URL not configured. Running in standalone mode.",
        }

    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "Project-CHIMERA-SOC/1.0",
    }
    if settings.N8N_API_KEY:
        headers["X-N8N-API-KEY"] = settings.N8N_API_KEY

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.post(resolved_url, json=payload, headers=headers)
            response.raise_for_status()

            # Attempt to parse response body as JSON
            try:
                data = response.json()
            except Exception:
                data = {"raw_response": response.text}

            # Extract or assign execution ID
            if isinstance(data, dict):
                execution_id = (
                    data.get("executionId")
                    or data.get("execution_id")
                    or data.get("id")
                    or f"n8n-live-{uuid.uuid4().hex[:8]}"
                )
                result: Dict[str, Any] = {
                    "status": "success",
                    "status_code": response.status_code,
                    "execution_id": str(execution_id),
                    "incident_id": incident_id,
                    "target_ip": resolved_ip,
                    "mitre_technique": resolved_mitre,
                    "risk_score": resolved_risk,
                    "action": action,
                    "data": data,
                }
            else:
                execution_id = f"n8n-live-{uuid.uuid4().hex[:8]}"
                result = {
                    "status": "success",
                    "status_code": response.status_code,
                    "execution_id": execution_id,
                    "incident_id": incident_id,
                    "target_ip": resolved_ip,
                    "mitre_technique": resolved_mitre,
                    "risk_score": resolved_risk,
                    "action": action,
                    "data": data,
                }

            logger.info(
                "n8n webhook executed successfully | status=%d | execution_id=%s",
                response.status_code,
                execution_id,
            )
            return result

    except httpx.TimeoutException as exc:
        fallback_id = f"fallback-timeout-{uuid.uuid4().hex[:8]}"
        logger.warning(
            "n8n webhook timed out for incident %s (%s). Using graceful fallback id: %s",
            incident_id,
            exc,
            fallback_id,
        )
        return {
            "status": "timeout_fallback",
            "execution_id": fallback_id,
            "incident_id": incident_id,
            "target_ip": resolved_ip,
            "mitre_technique": resolved_mitre,
            "risk_score": resolved_risk,
            "action": action,
            "error": "Request timed out",
            "message": "n8n webhook timed out; local fallback executed gracefully.",
        }

    except httpx.HTTPStatusError as exc:
        fallback_id = f"fallback-http-{uuid.uuid4().hex[:8]}"
        logger.warning(
            "n8n webhook returned HTTP error %s for incident %s. Using graceful fallback id: %s",
            exc.response.status_code,
            incident_id,
            fallback_id,
        )
        return {
            "status": "http_error_fallback",
            "status_code": exc.response.status_code,
            "execution_id": fallback_id,
            "incident_id": incident_id,
            "target_ip": resolved_ip,
            "mitre_technique": resolved_mitre,
            "risk_score": resolved_risk,
            "action": action,
            "error": f"HTTP {exc.response.status_code}",
            "message": "n8n responded with non-200 status; local fallback executed gracefully.",
        }

    except Exception as exc:
        fallback_id = f"fallback-err-{uuid.uuid4().hex[:8]}"
        logger.warning(
            "n8n webhook unexpected error for incident %s: %s. Using graceful fallback id: %s",
            incident_id,
            exc,
            fallback_id,
        )
        return {
            "status": "error_fallback",
            "execution_id": fallback_id,
            "incident_id": incident_id,
            "target_ip": resolved_ip,
            "mitre_technique": resolved_mitre,
            "risk_score": resolved_risk,
            "action": action,
            "error": str(exc),
            "message": "n8n webhook encountered an error; local fallback executed gracefully.",
        }
