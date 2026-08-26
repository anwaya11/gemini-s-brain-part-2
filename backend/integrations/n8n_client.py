"""
backend/integrations/n8n_client.py

n8n webhook integration for automated containment actions.

Sends structured POST requests to the configured N8N_WEBHOOK_URL and
returns the execution ID reported by n8n (or a mock ID when the webhook
is unavailable / not configured).
"""

import logging
import uuid
from typing import Any

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def trigger_containment(
    incident_id: str,
    action: str,
    ip: str,
) -> str:
    """
    Trigger a containment workflow in n8n via webhook.

    Sends a POST request to ``N8N_WEBHOOK_URL`` with a JSON payload
    describing the incident and the requested action.  Returns the
    ``n8n_execution_id`` string from the response, or a locally-generated
    mock ID if the webhook is unreachable or not configured.

    Parameters
    ----------
    incident_id:
        Unique identifier for the CHIMERA incident (e.g. a UUID or slug).
    action:
        The containment action to perform, e.g. ``"block_ip"``,
        ``"isolate_host"``, or ``"rate_limit"``.
    ip:
        The IP address that is the subject of the containment action.

    Returns
    -------
    str
        The ``n8n_execution_id`` returned by the webhook, or a
        ``mock-<uuid>`` string when running without a live n8n instance.

    Raises
    ------
    httpx.HTTPStatusError
        If n8n responds with a 4xx or 5xx status code.
    """
    webhook_url = settings.N8N_WEBHOOK_URL
    payload: dict[str, Any] = {
        "incident_id": incident_id,
        "action": action,
        "ip": ip,
    }

    logger.info(
        "n8n trigger_containment | incident_id=%s | action=%s | ip=%s | url=%s",
        incident_id,
        action,
        ip,
        webhook_url,
    )

    if not webhook_url:
        mock_id = f"mock-{uuid.uuid4()}"
        logger.warning(
            "N8N_WEBHOOK_URL is not configured — returning mock execution id: %s",
            mock_id,
        )
        return mock_id

    async with httpx.AsyncClient(timeout=10.0) as client:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if settings.N8N_API_KEY:
            headers["X-N8N-API-KEY"] = settings.N8N_API_KEY

        try:
            response = await client.post(webhook_url, json=payload, headers=headers)
            response.raise_for_status()
        except httpx.ConnectError:
            # n8n may not be running in dev — fall back to a mock ID
            mock_id = f"mock-{uuid.uuid4()}"
            logger.warning(
                "Could not connect to n8n webhook — returning mock execution id: %s",
                mock_id,
            )
            return mock_id

        data = response.json()
        execution_id: str = data.get("executionId") or data.get("n8n_execution_id") or f"mock-{uuid.uuid4()}"

        logger.info(
            "n8n webhook responded | execution_id=%s | status=%s",
            execution_id,
            response.status_code,
        )
        return execution_id
