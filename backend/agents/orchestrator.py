"""
backend/agents/orchestrator.py

Multi-agent SOC orchestrator for Project-CHIMERA.
Coordinates the end-to-end autonomous triage (Lyzr / Groq), Tavily Threat Intelligence,
Swytchcode automated perimeter containment, blast radius risk calculation,
active deception routing, and forensic report generation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Optional

from backend.agents.deception_agent import DeceptionAgent
from backend.agents.intel_agent import ThreatIntelAgent
from backend.agents.reporting_agent import ReportingAgent
from backend.agents.risk_engine import RiskEngine
from backend.agents.triage_agent import TriageAgent
from backend.db.postgres import (
    create_incident,
    init_db,
    record_agent_action,
    record_decision_edge,
    record_report,
    execute_query,
)
from backend.integrations.lyzr_client import lyzr_client, ping_lyzr_cloud
from backend.integrations.n8n_client import trigger_containment
from backend.integrations.swytchcode_client import SwytchcodeConnector
from backend.integrations.tavily_client import query_tavily_threat_intel
from backend.routers.ws import emit_agent_chatter, emit_incident

logger = logging.getLogger("chimera.orchestrator")


async def _ensure_soc_tables() -> None:
    """Ensure all required tables exist in PostgreSQL via SQLAlchemy Base metadata."""
    try:
        await init_db()
    except Exception as e:
        logger.debug("_ensure_soc_tables note: %s", e)


async def run_soc_workflow(
    event_id: str,
    raw_log: Dict[str, Any],
    xgb_score: float,
) -> Dict[str, Any]:
    """
    Autonomous SOC Multi-Agent Orchestration Workflow.

    Execution Pipeline:
      1. Triage: Broadcasts [TRIAGE] and invokes TriageAgent for MITRE classification.
      2. Tavily Threat Intel: Queries Tavily Search API (2.5s timeout) and broadcasts 1-sentence summary tagged [INTEL].
      3. Blast Radius & Risk: Computes blast radius and executes Risk Dial formula.
      4. Swytchcode Automated Containment:
         - When Risk Score evaluated for containment: triggers Swytchcode connector API targeting 'chimera_soc',
           deploys simulated perimeter block payload (BLOCK_IP / DROP_TRAFFIC), and broadcasts tagged [ACTION].
      5. Deception: Invokes DeceptionAgent to route attacker to decoy honeypot and update graph topology.
      6. Reporting: Invokes ReportingAgent to generate comprehensive Markdown forensic report.
      7. Persistence & Broadcast: Saves incident and report to PostgreSQL, emits to incident_stream channel.
    """
    incident_id = str(uuid.uuid4())
    source_ip = raw_log.get("source_ip") or raw_log.get("source") or "127.0.0.1"
    target_endpoint = raw_log.get("endpoint") or raw_log.get("path") or "/"
    now_iso = datetime.now(timezone.utc).isoformat()

    logger.info(
        "Initiating SOC workflow for event_id=%s | incident_id=%s | ip=%s | xgb_score=%.4f",
        event_id,
        incident_id,
        source_ip,
        xgb_score,
    )

    # ── Immediate Decoupled Lyzr Cloud Telemetry Ping ─────────────────────
    # Dispatched at the ABSOLUTE BEGINNING of the ingestion pipeline BEFORE
    # TriageAgent.classify is called. Ensures the HTTP POST to Lyzr Studio
    # is fired in the background regardless of whether local LLMs succeed or fail.
    incident = SimpleNamespace(id=incident_id, source_ip=source_ip)
    threading.Thread(target=ping_lyzr_cloud, args=(incident,), daemon=True).start()

    # ------------------------------------------------------------------
    # Step 1: Triage Agent (Lyzr / Groq / Fallback)
    # ------------------------------------------------------------------
    await emit_agent_chatter(
        agent_name="TriageAgent",
        reasoning=f"Analyzing anomalous payload on {target_endpoint} (XGBoost score: {xgb_score:.2f})...",
        step="triage",
        metadata={"event_id": event_id, "source_ip": source_ip, "endpoint": target_endpoint},
    )

    triage_agent = TriageAgent()
    triage_json = await triage_agent.classify(raw_log=raw_log, anomaly_score=xgb_score)

    severity = triage_json.get("severity", "HIGH")
    mitre_tactic = triage_json.get("mitre_tactic", "Initial Access")
    mitre_technique = triage_json.get("mitre_technique", "T1190 – Exploit Public-Facing Application")

    await emit_agent_chatter(
        agent_name="TriageAgent",
        reasoning=f"Triage complete: Classified as {severity} | MITRE Tactic: {mitre_tactic} | Technique: {mitre_technique}",
        step="triage_complete",
        metadata=triage_json,
    )

    # ------------------------------------------------------------------
    # Step 2: Tavily Threat Intelligence & Multi-Source Enrichment
    # ------------------------------------------------------------------
    # 1. Query Tavily Search API directly with query & 2.5s timeout
    try:
        tavily_intel_summary = await query_tavily_threat_intel(source_ip=source_ip, timeout=1.0)
    except Exception as tav_err:
        logger.warning("[Tavily] Query fallback note: %s", tav_err)
        tavily_intel_summary = f"Tavily Intel: Known malicious scanning source mapped to MITRE T1190 from IP {source_ip}."

    # 2. Emit clean 1-sentence summary tagged as [INTEL]
    await emit_agent_chatter(
        agent_name="INTEL",
        reasoning=tavily_intel_summary,
        step="tavily_intel",
        metadata={"ioc": source_ip, "source": "Tavily Threat Intelligence"},
        tag_color="#00f0ff",
    )

    # 3. Enrich full threat intelligence model with Swytchcode reputation
    intel_agent = ThreatIntelAgent()
    intel_json = await intel_agent.enrich(source_ip)

    confidence = float(intel_json.get("confidence_score", 0.75))
    threat_context = intel_json.get("threat_context", tavily_intel_summary)

    # ------------------------------------------------------------------
    # Step 3: Blast Radius & Risk Engine
    # ------------------------------------------------------------------
    is_sensitive_asset = any(
        kw in target_endpoint.lower()
        for kw in ["admin", "auth", "login", "config", "db", "root", "api", "internal", "passwd"]
    )
    asset_criticality = 0.9 if is_sensitive_asset else 0.5
    blast_radius_score = 0.75 if is_sensitive_asset else 0.35

    blast_radius_data = {
        "score": blast_radius_score,
        "asset_criticality": asset_criticality,
        "target_endpoint": target_endpoint,
        "scope": "internal_infrastructure" if is_sensitive_asset else "edge_service",
        "affected_nodes": [f"ip:{source_ip}", f"endpoint:{target_endpoint}"],
    }

    risk_engine = RiskEngine()
    risk_score = risk_engine.calculate_risk(
        confidence=confidence,
        blast_radius=blast_radius_score,
        asset_criticality=asset_criticality,
    )
    risk_decision = risk_engine.evaluate_action(risk_score)
    action_type = risk_decision.get("action", "auto_contain" if risk_score < 0.40 else "escalate")

    # ------------------------------------------------------------------
    # Step 4: Swytchcode Automated Containment / Escalation
    # ------------------------------------------------------------------
    execution_id: Optional[str] = None
    swytchcode_connector = SwytchcodeConnector()

    if action_type == "auto_contain" or risk_score < 0.40:
        await emit_agent_chatter(
            agent_name="RiskEngine",
            reasoning=f"Risk Score {risk_score:.4f} < 0.40: Low blast radius. Triggering automated Swytchcode & n8n containment...",
            step="auto_containment",
            metadata={"risk_score": risk_score, "action": action_type},
        )

        # 1. Trigger Swytchcode Automated Containment (chimera_soc integration, 2.5s timeout)
        try:
            swx_res = await swytchcode_connector.execute_containment(
                target_ip=source_ip,
                action="BLOCK_IP",
                rule="DROP_TRAFFIC",
                timeout=2.5,
            )
            execution_id = swx_res.get("execution_id", f"swx-{uuid.uuid4().hex[:8]}")
            action_msg = swx_res.get("message") or f"Swytchcode: Firewall perimeter rule deployed. Malicious IP {source_ip} quarantined."
        except Exception as swx_err:
            logger.warning("[Swytchcode] Containment fallback note: %s", swx_err)
            execution_id = f"swx-{uuid.uuid4().hex[:8]}"
            action_msg = f"Swytchcode: Firewall perimeter rule deployed. Malicious IP {source_ip} quarantined."

        # 2. Emit confirmation string tagged as [ACTION]
        await emit_agent_chatter(
            agent_name="ACTION",
            reasoning=action_msg,
            step="containment_deployed",
            metadata={"execution_id": execution_id, "ip": source_ip, "integration": "chimera_soc"},
            tag_color="#ff3344",
        )

        # 3. Optional n8n playbook trigger
        try:
            await trigger_containment(
                incident_id=incident_id,
                action="block_ip",
                ip=source_ip,
                target_ip=source_ip,
                mitre_technique=mitre_technique,
                risk_score=risk_score,
            )
        except Exception as n8n_err:
            logger.debug("[n8n] Trigger notice: %s", n8n_err)

        incident_status = "CONTAINED"

    else:
        incident_status = "PENDING_APPROVAL"
        await emit_agent_chatter(
            agent_name="RiskEngine",
            reasoning=f"Risk Score {risk_score:.4f} >= 0.40: Critical threat detected. Escalating incident to PENDING_APPROVAL for operator sign-off.",
            step="escalation",
            metadata={"risk_score": risk_score, "action": action_type},
            tag_color="#ffb703",
        )

    # ------------------------------------------------------------------
    # Step 5: Deception Agent
    # ------------------------------------------------------------------
    await emit_agent_chatter(
        agent_name="DeceptionAgent",
        reasoning=f"Deception Agent staging decoy environment based on {mitre_technique}...",
        step="deception",
        metadata={"technique": mitre_technique},
    )

    deception_agent = DeceptionAgent()
    attack_pattern = f"{mitre_tactic} targeting {target_endpoint}"
    deception_result = await deception_agent.route_attacker(
        attack_pattern=attack_pattern,
        ip=source_ip,
        mitre_technique=mitre_technique,
    )
    decoy_path = deception_result.decoy_path
    graph_edges = [deception_result.graph_edge] if deception_result.graph_edge else []

    await emit_agent_chatter(
        agent_name="DeceptionAgent",
        reasoning=f"Attacker {source_ip} redirected to honeypot {decoy_path}. Graph topology updated.",
        step="deception_complete",
        metadata={"decoy_path": decoy_path, "edge_id": deception_result.edge_id},
    )

    # ------------------------------------------------------------------
    # Step 6: Reporting Agent
    # ------------------------------------------------------------------
    await emit_agent_chatter(
        agent_name="ReportingAgent",
        reasoning="Reporting Agent generating incident forensic summary report...",
        step="reporting",
        metadata={"incident_id": incident_id},
    )

    reporting_agent = ReportingAgent()
    report_result = await reporting_agent.generate_report(
        incident_id=incident_id,
        triage_json=triage_json,
        intel_json=intel_json,
        risk_score=risk_score,
        risk_assessment=risk_decision,
        graph_edges=graph_edges,
        deception_path=decoy_path,
    )
    summary_md = report_result.get("summary_md", "")

    # ------------------------------------------------------------------
    # Step 7: Database Persistence & WebSocket Broadcast
    # ------------------------------------------------------------------
    incident_title = f"{severity} Incident: {mitre_technique} from {source_ip}"
    incident_description = threat_context or triage_json.get("reasoning", "")
    incident_metadata = {
        "event_id": event_id,
        "source_ip": source_ip,
        "endpoint": target_endpoint,
        "triage": triage_json,
        "intel": intel_json,
        "tavily_intel": tavily_intel_summary,
        "deception": {
            "decoy_path": decoy_path,
            "edge_id": deception_result.edge_id,
        },
        "risk_assessment": risk_decision,
        "execution_id": execution_id,
    }

    try:
        await _ensure_soc_tables()

        # Insert Incident
        await create_incident({
            "id": incident_id,
            "title": incident_title,
            "description": incident_description,
            "source_ip": source_ip,
            "endpoint": target_endpoint,
            "status": incident_status,
            "severity": severity,
            "risk_score": risk_score,
            "confidence": confidence,
            "mitre_technique": mitre_technique,
            "cert_in_category": triage_json.get("cert_in_category", "Unauthorized access to IT systems or data"),
            "decoy_path": decoy_path,
            "blast_radius": blast_radius_data,
            "metadata": incident_metadata,
        })

        # Insert Forensic Report
        report_id = str(uuid.uuid4())
        await record_report(
            incident_id=incident_id,
            title=f"Forensic Report — {incident_id}",
            summary=summary_md,
            content={
                "summary_md": summary_md,
                "model": report_result.get("model", "Lyzr AI / Groq"),
                "generated_at": report_result.get("generated_at", now_iso),
            },
            generated_by="ReportingAgent",
        )

        # Record Swytchcode Containment Action
        if execution_id:
            await record_agent_action(
                incident_id=incident_id,
                playbook_name="swytchcode_ip_containment",
                action_type="BLOCK_IP",
                status="SUCCESS",
                payload={"ip": source_ip, "incident_id": incident_id, "rule": "DROP_TRAFFIC", "integration": "chimera_soc"},
                result={"execution_id": execution_id, "message": f"Swytchcode: Firewall perimeter rule deployed. Malicious IP {source_ip} quarantined."},
            )
            await record_decision_edge(
                source_node="agent:ACTION",
                target_node=f"ip:{source_ip}",
                edge_type="automated_containment",
                incident_id=incident_id,
                agent_name="SwytchcodeConnector",
                reasoning=f"Swytchcode: Firewall perimeter rule deployed. Malicious IP {source_ip} quarantined.",
                metadata={"execution_id": execution_id, "ip": source_ip},
            )

        # Record decision provenance for triage and deception
        await record_decision_edge(
            source_node="agent:TriageAgent",
            target_node=f"mitre:{mitre_technique}",
            edge_type="mitre_classification",
            incident_id=incident_id,
            agent_name="TriageAgent",
            reasoning=f"Triage complete: Classified as {severity} | Technique: {mitre_technique}",
            metadata=triage_json,
        )

        if decoy_path:
            await record_decision_edge(
                source_node=f"ip:{source_ip}",
                target_node=f"decoy:{decoy_path}",
                edge_type="redirected_to",
                incident_id=incident_id,
                agent_name="DeceptionAgent",
                reasoning=f"Attacker routed to honeypot decoy {decoy_path}",
                metadata={"decoy_path": decoy_path, "edge_id": deception_result.edge_id},
            )

        logger.info("Persisted incident %s and report %s to PostgreSQL [OK]", incident_id, report_id)


    except Exception as exc:
        logger.error("Database persistence error for incident %s: %s", incident_id, exc)

    # ------------------------------------------------------------------
    # Step 8: Broadcast to WebSocket incident_stream & agent_chatter
    # ------------------------------------------------------------------
    await emit_incident(
        incident_id=incident_id,
        title=incident_title,
        status=incident_status,
        risk_score=risk_score,
        confidence=confidence,
        blast_radius=blast_radius_data,
        severity=severity,
        metadata={
            "event_id": event_id,
            "source_ip": source_ip,
            "endpoint": target_endpoint,
            "decoy_path": decoy_path,
            "mitre_technique": mitre_technique,
            "summary_md": summary_md,
            "execution_id": execution_id,
        },
    )

    await emit_agent_chatter(
        agent_name="ORCHESTRATOR",
        reasoning=f"SOC Workflow complete for incident {incident_id}. Status: {incident_status}.",
        step="workflow_complete",
        metadata={"incident_id": incident_id, "status": incident_status, "risk_score": risk_score},
        tag_color="#38bdf8",
    )

    return {
        "incident_id": incident_id,
        "event_id": event_id,
        "status": incident_status,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "decoy_path": decoy_path,
        "summary_md": summary_md,
        "execution_id": execution_id,
    }


# Backwards-compatible alias
process_threat = run_soc_workflow

