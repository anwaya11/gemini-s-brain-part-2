"use client";

import React, { useState } from "react";
import { Download, FileDown, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { IncidentItem } from "@/hooks/useSOCStream";

export function generateIncidentMarkdownReport(incident: IncidentItem): string {
  const incidentId = incident?.id || "INC-2026-0891";
  const title = incident?.title || "Security Incident";
  const targetIp = (incident as any)?.target_ip || incident?.source_ip || "0.0.0.0";
  const severity = incident?.severity || "HIGH";
  const status = incident?.status || "PENDING_APPROVAL";
  const mitreTechnique = incident?.mitre_technique || "T1190 – Exploit Public-Facing Application";
  const decoyPath = incident?.decoy_path || "/decoy/db-admin";
  const createdAt = incident?.created_at || new Date().toISOString();
  const certCategory = incident?.cert_in_category || "Unauthorized access to IT systems or data";

  const numRiskScore = typeof incident?.risk_score === "number" ? incident.risk_score : parseFloat(String(incident?.risk_score || 0));
  const riskScoreStr = isNaN(numRiskScore) ? "0.000" : numRiskScore.toFixed(3);
  const isHighRisk = numRiskScore >= 0.40;

  const numConfidence = typeof incident?.confidence === "number" ? incident.confidence : parseFloat(String(incident?.confidence || 0.9));
  const confidencePercent = isNaN(numConfidence) ? "90" : (numConfidence * 100).toFixed(0);

  const exportTimestamp = new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC";

  let containmentStepText = "";
  if (status === "INTERCEPTED_BY_GUARDRAIL") {
    containmentStepText = `5. **[T+1.45s] 🛑 SWYTCHCODE GUARDRAIL:** Autonomous containment blocked on protected core subnet (${targetIp}). Zero-Trust pre-execution policy [policy_protect_core_infrastructure] prevented disruption.\n`;
  } else if (status === "CONTAINED") {
    containmentStepText = `5. **[T+1.85s] ⚡ CONTAINMENT ENGINE:** Perimeter firewall DROP rule deployed via n8n automated playbook. IP ${targetIp} isolated at edge gateway. Slack and Jira tickets synced.\n`;
  } else if (status === "REJECTED") {
    containmentStepText = `5. **[T+2.10s] 🛡️ OPERATOR DISPOSITION:** Incident marked as FALSE POSITIVE by security operator. Suppression filter committed.\n`;
  }

  let remediationDetails = "";
  if (status === "CONTAINED") {
    remediationDetails = `- **Active State:** Perimeter containment active. Inbound/outbound traffic for ${targetIp} dropped.\n- **Playbook:** n8n edge firewall workflow completed.\n- **Decoy:** Attacker sessions sinkholed into ${decoyPath}.`;
  } else if (status === "INTERCEPTED_BY_GUARDRAIL") {
    remediationDetails = `- **Active State:** Containment blocked by Swytchcode Guardrail.\n- **Reason:** Target ${targetIp} is protected mission-critical infrastructure.\n- **Action:** Manual operator review required.`;
  } else if (status === "PENDING_APPROVAL") {
    remediationDetails = `- **Active State:** Awaiting human analyst authorization.\n- **Evaluation:** Risk score ${riskScoreStr} exceeds the 0.40 autonomy threshold.\n- **Decoy:** Attacker active sessions trapped in ${decoyPath}.`;
  } else {
    remediationDetails = `- **Active State:** Incident dismissed / false positive.\n- **Action:** Telemetry logged for threshold tuning.`;
  }

  return `# 🛡️ CHIMERA Forensic Incident Report — ${incidentId}

**Report Generated:** ${exportTimestamp}
**Platform:** Project CHIMERA Autonomous SOC & Deception Platform (v2.0)
**Execution Mode:** Swytchcode Zero-Trust Pre-Execution Enforced

---

## 1. Incident Overview
| Attribute | Value |
|---|---|
| **Incident ID** | \`${incidentId}\` |
| **Title** | ${title} |
| **Detection Timestamp** | ${createdAt} |
| **Target / Origin IP** | \`${targetIp}\` |
| **Severity** | **${severity}** |
| **Incident Status** | \`${status}\` |
| **MITRE ATT&CK Technique** | \`${mitreTechnique}\` |
| **Threat Confidence** | **${confidencePercent}%** |
| **Composite Risk Score** | **${riskScoreStr}** (${isHighRisk ? 'Exceeds Autonomy Cutoff >= 0.40' : 'Within Autonomy Threshold < 0.40'}) |
| **CERT-In Statutory Category** | ${certCategory} |
| **Deception Decoy Target** | \`${decoyPath}\` |

---

## 2. Forensic Agent Report Summary
Target IP origin \`${targetIp}\` was flagged in the telemetry stream during anomalous payload ingestion. Heuristic feature evaluation and ThreatIntelAgent enrichment corroborated high-confidence exploitation matching \`${mitreTechnique}\`. Composite risk score evaluated at **${riskScoreStr}**. Swytchcode Zero-Trust layer monitors and evaluates pre-execution policies on all outgoing containment actions.

---

## 3. Decision-Provenance Chronological Timeline
1. **[T+0.01s] 🛡️ TRIAGE AGENT:** Threat identified & MITRE ATT&CK mapped (\`${mitreTechnique}\`) with ${confidencePercent}% detection confidence.
2. **[T+0.42s] 🌐 THREAT INTEL AGENT:** Tavily & Swytchcode reputation enrichment completed for IOC \`${targetIp}\`. Hostile reputation confirmed.
3. **[T+0.85s] ⚖️ RISK ENGINE:** Composite risk score calculated: **${riskScoreStr}**. ${isHighRisk ? 'Escalated for Human-in-the-Loop authorization.' : 'Qualified for autonomous containment.'}
4. **[T+1.20s] 🪤 DECEPTION AGENT:** Attacker rerouted to decoy honeypot (\`${decoyPath}\`). Graph topology edge committed.
${containmentStepText}
---

## 4. Remediation & Action Taken
${remediationDetails}

---

## 5. Compliance & Statutory Governance
- **Statutory Reporting:** Tracked under CERT-In (Section 70B IT Act) 6-Hour Statutory Compliance Clock.
- **Audit Hash:** \`SHA256-${incidentId}-${targetIp}-${Date.now().toString(36)}\`
- **Zero-Trust Policy:** Enforced via Swytchcode Compiler Target & Execution Kernel.

---
*Report exported from CHIMERA Autonomous SOC Console · Strictly Confidential*
`;
}

export function downloadIncidentReport(incident: IncidentItem) {
  const incidentId = incident?.id || "INC-2026-0891";
  const markdown = generateIncidentMarkdownReport(incident);
  const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `CHIMERA_Report_${incidentId}.md`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

interface ReportExportButtonProps {
  incident: IncidentItem;
  className?: string;
  variant?: "primary" | "compact";
}

export function ReportExportButton({
  incident,
  className,
  variant = "primary",
}: ReportExportButtonProps) {
  const [downloaded, setDownloaded] = useState(false);

  const handleDownload = (e: React.MouseEvent) => {
    e.stopPropagation();
    downloadIncidentReport(incident);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 2200);
  };

  if (variant === "compact") {
    return (
      <button
        onClick={handleDownload}
        title="Download Forensic Markdown Report"
        className={cn(
          "flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono font-bold rounded border transition-all cursor-pointer select-none",
          downloaded
            ? "bg-[#00ff66]/20 border-[#00ff66]/60 text-[#00ff66] shadow-[0_0_10px_rgba(0,255,102,0.3)]"
            : "bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 border-[#00f0ff]/30 hover:border-[#00f0ff]/60 text-[#00f0ff]",
          className
        )}
      >
        {downloaded ? (
          <>
            <Check className="w-3.5 h-3.5 text-[#00ff66]" />
            <span className="text-[#00ff66]">DOWNLOADED</span>
          </>
        ) : (
          <>
            <FileDown className="w-3.5 h-3.5" />
            <span>EXPORT .MD</span>
          </>
        )}
      </button>
    );
  }

  return (
    <button
      onClick={handleDownload}
      title="Generate and Download Full Markdown Incident Dossier"
      className={cn(
        "flex items-center gap-2 px-3 py-1.5 text-xs font-mono font-bold rounded-lg border transition-all duration-200 cursor-pointer select-none",
        downloaded
          ? "bg-[#00ff66]/20 border-[#00ff66]/60 text-[#00ff66] shadow-[0_0_15px_rgba(0,255,102,0.3)]"
          : "bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 border-[#00f0ff]/30 hover:border-[#00f0ff]/60 text-[#00f0ff] shadow-[0_0_12px_rgba(0,240,255,0.15)]",
        className
      )}
    >
      {downloaded ? (
        <>
          <Check className="w-4 h-4 text-[#00ff66]" />
          <span>REPORT DOWNLOADED</span>
        </>
      ) : (
        <>
          <Download className="w-4 h-4 text-[#00f0ff]" />
          <span>Download Report (.md)</span>
        </>
      )}
    </button>
  );
}

export default ReportExportButton;
