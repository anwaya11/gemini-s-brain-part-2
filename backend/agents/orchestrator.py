"""
backend/agents/orchestrator.py

Multi-agent SOC orchestrator for Project-CHIMERA.
Coordinates the end-to-end autonomous triage, threat intelligence enrichment,
blast radius risk calculation, autonomous containment / human escalation,
deception routing, and forensic report generation.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.agents.deception_agent import DeceptionAgent
from backend.agents.intel_agent import ThreatIntelAgent
from backend.agents.reporting_agent import ReportingAgent
from backend.agents.risk_engine import RiskEngine
from backend.agents.triage_agent import TriageAgent
from backend.db.postgres import execute_query
from backend.integrations.n8n_client import trigger_containment
from backend.routers.ws import emit_agent_chatter, emit_incident

logger = logging.getLogger(__name__)


async def _ensure_soc_tables() -> None:
    """Ensure incidents and reports tables exist in PostgreSQL."""
    await execute_query(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            title VARCHAR(255) NOT NULL,
            description TEXT,
            status VARCHAR(50) NOT NULL DEFAULT 'OPEN',
            severity VARCHAR(50) NOT NULL DEFAULT 'MEDIUM',
            risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            blast_radius JSONB NOT NULL DEFAULT '{}'::jsonb,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
            title VARCHAR(255) NOT NULL,
            summary TEXT,
            content JSONB NOT NULL DEFAULT '{}'::jsonb,
            generated_by VARCHAR(100) DEFAULT 'SYSTEM',
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS actions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
            playbook_name VARCHAR(255),
            action_type VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            result JSONB NOT NULL DEFAULT '{}'::jsonb,
            executed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


async def run_soc_workflow(
    event_id: str,
    raw_log: Dict[str, Any],
    xgb_score: float,
) -> Dict[str, Any]:
    """
    Autonomous SOC Multi-Agent Orchestration Workflow.

    Execution Pipeline:
      1. Triage: Broadcasts to agent_chatter and invokes TriageAgent for MITRE tactic/technique classification.
      2. Threat Intel: Broadcasts and invokes ThreatIntelAgent to query Tavily & Swytchcode (VirusTotal/AbuseIPDB).
      3. Blast Radius & Risk: Computes blast radius, executes RiskEngine Risk Dial formula.
      4. Containment / Escalation:
         - If auto_contain (risk_score < 0.4): automatically triggers n8n containment playbook.
         - If escalate (risk_score >= 0.4): sets status to PENDING_APPROVAL for human-in-the-loop review.
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

    # ------------------------------------------------------------------
    # Step 1: Triage Agent
    # ------------------------------------------------------------------
    await emit_agent_chatter(
        agent_name="TriageAgent",
        reasoning="Triage Agent analyzing event...",
        step="triage",
        metadata={"event_id": event_id, "source_ip": source_ip, "endpoint": target_endpoint},
    )

    triage_agent = TriageAgent()
    triage_json = await triage_agent.classify(raw_log=raw_log, anomaly_score=xgb_score)

    severity = triage_json.get("severity", "HIGH")
    mitre_tactic = triage_json.get("mitre_tactic", "Unknown")
    mitre_technique = triage_json.get("mitre_technique", "Unknown")

    await emit_agent_chatter(
        agent_name="TriageAgent",
        reasoning=f"Triage complete: Classified as {severity} | MITRE Tactic: {mitre_tactic} | Technique: {mitre_technique}",
        step="triage_complete",
        metadata=triage_json,
    )

    # ------------------------------------------------------------------
    # Step 2: Threat Intel Agent
    # ------------------------------------------------------------------
    await emit_agent_chatter(
        agent_name="ThreatIntelAgent",
        reasoning="Threat Intel Agent querying Tavily & VirusTotal via Swytchcode...",
        step="threat_intel",
        metadata={"ioc": source_ip},
    )

    intel_agent = ThreatIntelAgent()
    intel_json = await intel_agent.enrich(source_ip)

    confidence = float(intel_json.get("confidence_score", 0.7))
    threat_context = intel_json.get("threat_context", "")

    await emit_agent_chatter(
        agent_name="ThreatIntelAgent",
        reasoning=f"Threat Intel enriched: Confidence {confidence:.2f} | Context: {threat_context[:120]}...",
        step="intel_complete",
        metadata={"confidence_score": confidence, "tags": intel_json.get("tags", [])},
    )

    # ------------------------------------------------------------------
    # Step 3: Blast Radius & Risk Engine
    # ------------------------------------------------------------------
    # Blast radius assessment based on target sensitivity and network footprint
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
    action_type = risk_decision.get("action", "escalate")  # "auto_contain" or "escalate"

    # ------------------------------------------------------------------
    # Step 4: Evaluate Risk & Containment / Escalation
    # ------------------------------------------------------------------
    execution_id: Optional[str] = None
    if action_type == "auto_contain":
        await emit_agent_chatter(
            agent_name="RiskEngine",
            reasoning=f"Risk Score {risk_score:.4f} < 0.40: Low blast radius. Executing automated containment playbook via n8n...",
            step="auto_containment",
            metadata={"risk_score": risk_score, "action": action_type},
        )
        try:
            execution_id = await trigger_containment(
                incident_id=incident_id,
                action="block_ip",
                ip=source_ip,
            )
            incident_status = "CONTAINED"
            await emit_agent_chatter(
                agent_name="ContainmentAgent",
                reasoning=f"Automated containment executed successfully via n8n (execution_id: {execution_id}). Blocked IP: {source_ip}.",
                step="containment_executed",
                metadata={"execution_id": execution_id, "ip": source_ip},
            )
        except Exception as exc:
            logger.error("Automated containment failed: %s", exc)
            incident_status = "CONTAINMENT_FAILED"
    else:
        incident_status = "PENDING_APPROVAL"
        await emit_agent_chatter(
            agent_name="RiskEngine",
            reasoning=f"Risk Score {risk_score:.4f} >= 0.40: High criticality threat. Escalating incident to PENDING_APPROVAL for human authorization.",
            step="escalation",
            metadata={"risk_score": risk_score, "action": action_type},
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
        await execute_query(
            """
            INSERT INTO incidents (
                id, title, description, status, severity, risk_score, confidence,
                blast_radius, metadata, created_at, updated_at
            )
            VALUES (
                :id, :title, :description, :status, :severity, :risk_score, :confidence,
                :blast_radius::jsonb, :metadata::jsonb, :created_at, :updated_at
            )
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                risk_score = EXCLUDED.risk_score,
                updated_at = EXCLUDED.updated_at;
            """,
            {
                "id": incident_id,
                "title": incident_title,
                "description": incident_description,
                "status": incident_status,
                "severity": severity,
                "risk_score": risk_score,
                "confidence": confidence,
                "blast_radius": json.dumps(blast_radius_data),
                "metadata": json.dumps(incident_metadata),
                "created_at": now_iso,
                "updated_at": now_iso,
            },
        )

        # Update event record with incident_id reference
        await execute_query(
            """
            UPDATE events
            SET incident_id = :incident_id
            WHERE id = :event_id;
            """,
            {"incident_id": incident_id, "event_id": event_id},
        )

        # Insert Report
        report_id = str(uuid.uuid4())
        await execute_query(
            """
            INSERT INTO reports (
                id, incident_id, title, summary, content, generated_by, created_at, updated_at
            )
            VALUES (
                :id, :incident_id, :title, :summary, :content::jsonb, :generated_by, :created_at, :updated_at
            );
            """,
            {
                "id": report_id,
                "incident_id": incident_id,
                "title": f"Forensic Report — {incident_id}",
                "summary": summary_md,
                "content": json.dumps({
                    "summary_md": summary_md,
                    "model": report_result.get("model", "unknown"),
                    "generated_at": report_result.get("generated_at", now_iso),
                }),
                "generated_by": "ReportingAgent",
                "created_at": now_iso,
                "updated_at": now_iso,
            },
        )

        # If containment executed, record action
        if execution_id:
            action_id = str(uuid.uuid4())
            await execute_query(
                """
                INSERT INTO actions (
                    id, incident_id, playbook_name, action_type, status, payload, result, executed_at, created_at
                )
                VALUES (
                    :id, :incident_id, :playbook_name, :action_type, :status, :payload::jsonb, :result::jsonb, :executed_at, :created_at
                );
                """,
                {
                    "id": action_id,
                    "incident_id": incident_id,
                    "playbook_name": "n8n_ip_containment",
                    "action_type": "block_ip",
                    "status": "SUCCESS",
                    "payload": json.dumps({"ip": source_ip, "incident_id": incident_id}),
                    "result": json.dumps({"execution_id": execution_id}),
                    "executed_at": now_iso,
                    "created_at": now_iso,
                },
            )

        logger.info("Persisted incident %s and report %s to PostgreSQL", incident_id, report_id)

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
        agent_name="Orchestrator",
        reasoning=f"SOC Workflow complete for incident {incident_id}. Status: {incident_status}.",
        step="workflow_complete",
        metadata={"incident_id": incident_id, "status": incident_status, "risk_score": risk_score},
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
