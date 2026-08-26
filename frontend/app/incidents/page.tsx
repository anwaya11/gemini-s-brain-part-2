"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  AlertOctagon,
  Clock,
  ExternalLink,
  ChevronRight,
  UserCheck,
  Ban,
  Radio,
  FileText,
} from "lucide-react";
import { cn } from "@/lib/utils";

const MOCK_INCIDENTS = [
  {
    id: "INC-2026-0891",
    title: "SQL Injection on Public Endpoint (/api/admin/config)",
    source_ip: "185.220.101.42",
    severity: "CRITICAL",
    risk_score: 0.842,
    confidence: 0.94,
    status: "PENDING_APPROVAL",
    mitre_technique: "T1190 – Exploit Public-Facing Application",
    decoy_path: "/decoy/db-admin",
    created_at: "2026-08-26 19:46:12 UTC",
  },
  {
    id: "INC-2026-0890",
    title: "Credential Stuffing / SSH Brute Force Campaign",
    source_ip: "45.154.255.89",
    severity: "HIGH",
    risk_score: 0.385,
    confidence: 0.88,
    status: "CONTAINED",
    mitre_technique: "T1110 – Brute Force Credentials",
    decoy_path: "/decoy/ssh-login",
    created_at: "2026-08-26 19:42:05 UTC",
  },
  {
    id: "INC-2026-0889",
    title: "Internal Reconnaissance & Port Probing",
    source_ip: "103.203.57.18",
    severity: "MEDIUM",
    risk_score: 0.320,
    confidence: 0.72,
    status: "CONTAINED",
    mitre_technique: "T1046 – Network Service Discovery",
    decoy_path: "/decoy/health-internal",
    created_at: "2026-08-26 19:35:40 UTC",
  },
  {
    id: "INC-2026-0888",
    title: "Unsecured Configuration Exfiltration Attempt",
    source_ip: "194.26.29.112",
    severity: "HIGH",
    risk_score: 0.710,
    confidence: 0.86,
    status: "PENDING_APPROVAL",
    mitre_technique: "T1552 – Unsecured Credentials & Config",
    decoy_path: "/decoy/config",
    created_at: "2026-08-26 19:10:18 UTC",
  },
];

export default function IncidentsPage() {
  const [selectedIncident, setSelectedIncident] = useState(MOCK_INCIDENTS[0]);
  const [filterStatus, setFilterStatus] = useState<string>("ALL");

  const filtered = MOCK_INCIDENTS.filter((inc) => {
    if (filterStatus === "ALL") return true;
    return inc.status === filterStatus;
  });

  return (
    <div className="flex flex-col h-full space-y-5">
      {/* Header Bar */}
      <div className="flex items-center justify-between px-6 py-4 rounded-xl glass-card hud-corner-border">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#ff003c]/10 border border-[#ff003c]/30 text-[#ff003c]">
            <ShieldAlert className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-wider text-white uppercase font-mono">
              Incident Management & Containment Authorization
            </h1>
            <p className="text-xs text-white/50 font-mono">
              Review and authorize multi-agent containment playbooks or inspect forensic reports
            </p>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-2 font-mono text-xs">
          {["ALL", "PENDING_APPROVAL", "CONTAINED"].map((status) => (
            <button
              key={status}
              onClick={() => setFilterStatus(status)}
              className={cn(
                "px-3 py-1.5 rounded-lg border transition-all uppercase",
                filterStatus === status
                  ? "bg-[#00f0ff]/15 text-[#00f0ff] border-[#00f0ff]/40 font-bold shadow-[0_0_12px_rgba(0,240,255,0.2)]"
                  : "bg-white/[0.02] text-white/50 border-white/10 hover:border-white/20 hover:text-white"
              )}
            >
              {status.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Left Incident List (5 cols), Right Incident Details (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[580px]">
        {/* Incident List */}
        <div className="lg:col-span-5 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex justify-between items-center">
            <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
              Active Incident Queue ({filtered.length})
            </span>
            <span className="text-[10px] font-mono text-white/40">SORT: RISK SCORE</span>
          </div>

          <div className="flex-1 p-3.5 space-y-3 overflow-y-auto">
            {filtered.map((inc) => {
              const isSelected = selectedIncident.id === inc.id;
              const isCritical = inc.severity === "CRITICAL";
              const isPending = inc.status === "PENDING_APPROVAL";

              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={cn(
                    "p-4 rounded-xl border transition-all cursor-pointer",
                    isSelected
                      ? "bg-[#00f0ff]/10 border-[#00f0ff]/50 shadow-[0_0_20px_rgba(0,240,255,0.15)]"
                      : "bg-[#030303]/60 border-white/10 hover:border-white/20"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-[#00f0ff]">
                        {inc.id}
                      </span>
                      <span
                        className={cn(
                          "px-2 py-0.5 text-[9px] font-mono font-bold rounded uppercase",
                          isCritical
                            ? "bg-[#ff003c]/20 text-[#ff003c] border border-[#ff003c]/30"
                            : "bg-[#ffb703]/20 text-[#ffb703] border border-[#ffb703]/30"
                        )}
                      >
                        {inc.severity}
                      </span>
                    </div>

                    <span
                      className={cn(
                        "px-2 py-0.5 text-[9px] font-mono font-bold rounded uppercase",
                        isPending
                          ? "bg-[#ffb703]/15 text-[#ffb703] border border-[#ffb703]/40 animate-pulse"
                          : "bg-[#00ff66]/15 text-[#00ff66] border border-[#00ff66]/40"
                      )}
                    >
                      {inc.status.replace("_", " ")}
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-white mt-2 leading-snug">
                    {inc.title}
                  </h3>

                  <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-white/5 font-mono text-[11px] text-white/50">
                    <div>
                      <span>ATTACKER: </span>
                      <strong className="text-white">{inc.source_ip}</strong>
                    </div>
                    <div>
                      <span>RISK SCORE: </span>
                      <strong className="text-[#ff003c]">{inc.risk_score.toFixed(3)}</strong>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Incident Detail & Authorization Action Panel */}
        <div className="lg:col-span-7 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex justify-between items-center">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#00f0ff]" />
              <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
                Incident Dossier: {selectedIncident.id}
              </span>
            </div>
            <span className="text-xs font-mono text-white/40">
              {selectedIncident.created_at}
            </span>
          </div>

          <div className="flex-1 p-6 space-y-6 overflow-y-auto">
            {/* Header Title & Severity */}
            <div>
              <div className="flex items-center gap-3">
                <span className="px-2.5 py-1 text-xs font-mono font-bold rounded bg-[#ff003c]/20 text-[#ff003c] border border-[#ff003c]/30">
                  {selectedIncident.severity}
                </span>
                <h2 className="text-lg font-bold text-white tracking-wide">
                  {selectedIncident.title}
                </h2>
              </div>
              <p className="text-xs font-mono text-white/50 mt-1.5">
                Observed MITRE Technique: <span className="text-[#00f0ff]">{selectedIncident.mitre_technique}</span>
              </p>
            </div>

            {/* Risk Dial & Metric Cards */}
            <div className="grid grid-cols-3 gap-3 font-mono">
              <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02]">
                <span className="text-[10px] text-white/40 uppercase">THREAT CONFIDENCE</span>
                <p className="text-xl font-bold text-[#00f0ff] mt-1">
                  {(selectedIncident.confidence * 100).toFixed(0)}%
                </p>
              </div>

              <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02]">
                <span className="text-[10px] text-white/40 uppercase">RISK SCORE</span>
                <p className="text-xl font-bold text-[#ff003c] mt-1">
                  {selectedIncident.risk_score.toFixed(3)}
                </p>
              </div>

              <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02]">
                <span className="text-[10px] text-white/40 uppercase">DECEPTION DECOY</span>
                <p className="text-xs font-bold text-[#ffb703] mt-2 truncate">
                  {selectedIncident.decoy_path}
                </p>
              </div>
            </div>

            {/* Forensic Summary Block */}
            <div className="p-4 rounded-xl border border-white/10 bg-[#030303]/80 font-mono text-xs space-y-2">
              <div className="flex items-center gap-2 text-[#00f0ff] font-bold">
                <Radio className="w-3.5 h-3.5 animate-pulse" />
                <span>FORENSIC AGENT REPORT SUMMARY</span>
              </div>
              <p className="text-white/70 leading-relaxed text-[11px]">
                Attacker origin <code className="text-[#00f0ff]">{selectedIncident.source_ip}</code> attempted SQL payload exploitation. Threat Intelligence confirmed high reputation risk. Attacker has been transparently routed to honeypot trap <code className="text-[#ffb703]">{selectedIncident.decoy_path}</code>. Autonomous containment playbook is ready for execution.
              </p>
            </div>

            {/* Human-in-the-loop Action Bar */}
            {selectedIncident.status === "PENDING_APPROVAL" ? (
              <div className="p-5 rounded-xl border border-[#ffb703]/30 bg-[#ffb703]/5 space-y-3">
                <div className="flex items-center gap-2 text-[#ffb703] font-mono text-xs font-bold">
                  <AlertOctagon className="w-4 h-4" />
                  <span>HUMAN AUTHORIZATION REQUIRED (Risk Dial &gt;= 0.40)</span>
                </div>
                <p className="text-xs text-white/60 font-mono">
                  Approve IP perimeter isolation and host containment via n8n automation webhook.
                </p>
                <div className="flex items-center gap-3 pt-2">
                  <button className="flex-1 flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-[#00ff66] text-black font-mono text-xs font-bold hover:bg-[#00ff66]/80 transition-all shadow-[0_0_15px_rgba(0,255,102,0.3)]">
                    <UserCheck className="w-4 h-4" />
                    AUTHORIZE CONTAINMENT
                  </button>
                  <button className="py-2.5 px-4 rounded-lg border border-[#ff003c]/40 text-[#ff003c] font-mono text-xs font-bold hover:bg-[#ff003c]/10 transition-all">
                    <Ban className="w-4 h-4 inline mr-1" />
                    REJECT / FALSE POSITIVE
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl border border-[#00ff66]/30 bg-[#00ff66]/5 flex items-center gap-3 font-mono text-xs text-[#00ff66]">
                <CheckCircle2 className="w-5 h-5" />
                <div>
                  <span className="font-bold">CONTAINMENT ACTIVE: </span>
                  <span>IP {selectedIncident.source_ip} blocked at perimeter firewall via n8n playbook.</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
