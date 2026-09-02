"use client";

import React, { useState, useEffect } from "react";
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
  Lock,
  Loader2,
  XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useSOCStream, IncidentItem, PlaybookExecution, formatLocalTime } from "@/hooks/useSOCStream";
import { PlaybookExecutionPanel } from "@/components/soc/PlaybookExecutionPanel";
import { CertInClock } from "@/components/soc/CertInClock";
import { AskTheSoc } from "@/components/soc/AskTheSoc";
import { DecisionTimeline } from "@/components/soc/DecisionTimeline";
import { ReportExportButton } from "@/components/soc/ReportExportButton";

export default function IncidentsPage() {
  const { incidents: streamIncidents, activePlaybook, isConnected } = useSOCStream("ws://localhost:8000/ws/console");
  const [incidents, setIncidents] = useState<IncidentItem[]>(streamIncidents);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");
  const [filterStatus, setFilterStatus] = useState<string>("ALL");
  const [actionLoading, setActionLoading] = useState<Record<string, "contain" | "reject" | null>>({});
  const [blockedAlert, setBlockedAlert] = useState<{ id: string; target: string; message: string } | null>(null);
  const [playbookExecutions, setPlaybookExecutions] = useState<Record<string, PlaybookExecution>>({});

  // Synchronize with streaming incidents from WebSocket
  useEffect(() => {
    if (streamIncidents && streamIncidents.length > 0) {
      setIncidents((prev) => {
        // Merge without losing locally updated actions
        const map = new Map<string, IncidentItem>();
        streamIncidents.forEach((inc) => map.set(inc.id, inc));
        prev.forEach((inc) => {
          if (inc.status !== "PENDING_APPROVAL" && map.has(inc.id)) {
            map.set(inc.id, { ...map.get(inc.id)!, status: inc.status });
          }
        });
        return Array.from(map.values());
      });
    }
  }, [streamIncidents]);

  // Synchronize with real-time Playbook Execution updates from WebSocket
  useEffect(() => {
    if (activePlaybook && activePlaybook.incident_id) {
      setPlaybookExecutions((prev) => ({
        ...prev,
        [activePlaybook.incident_id]: activePlaybook,
      }));
      if (activePlaybook.status === "COMPLETED") {
        setIncidents((prev) =>
          prev.map((inc) =>
            inc.id === activePlaybook.incident_id ? { ...inc, status: "CONTAINED" } : inc
          )
        );
      }
    }
  }, [activePlaybook]);

  // Initial fetch from backend API
  useEffect(() => {
    async function fetchInitial() {
      try {
        const res = await fetch("http://localhost:8000/api/incidents");
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.incidents)) {
            setIncidents((prev) => {
              const map = new Map<string, IncidentItem>(prev.map((i) => [i.id, i]));
              data.incidents.forEach((inc: IncidentItem) => map.set(inc.id, inc));
              return Array.from(map.values()).sort(
                (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
              );
            });
            if (!selectedIncidentId && data.incidents.length > 0) {
              setSelectedIncidentId(data.incidents[0].id);
            }
          }
        }
      } catch (err) {
        console.warn("[Incidents] Fetch initial fallback:", err);
      }
    }
    fetchInitial();
  }, []);

  const filtered = incidents.filter((inc) => {
    if (filterStatus === "ALL") return true;
    return inc.status === filterStatus;
  });

  const selectedIncident =
    incidents.find((i) => i.id === selectedIncidentId) ||
    filtered[0] ||
    incidents[0];

  // Action Handlers
  const handleContain = async (incidentId: string) => {
    setActionLoading((prev) => ({ ...prev, [incidentId]: "contain" }));
    const targetInc = incidents.find((i) => i.id === incidentId);
    const targetIp = targetInc?.source_ip || "185.220.101.42";

    try {
      const res = await fetch("http://localhost:8000/api/incidents/contain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incident_id: incidentId, source_ip: targetIp }),
      });
      const data = await res.json();

      if (data.status === "blocked" || data.reason === "POLICY_BLOCKED") {
        // Intercepted by Swytchcode Guardrail!
        setBlockedAlert({
          id: incidentId,
          target: data.target || "10.0.0.5",
          message:
            data.message ||
            "Autonomous containment blocked on protected core subnet (10.0.0.5). Zero-Trust Execution Layer Active.",
        });
        setIncidents((prev) =>
          prev.map((inc) => (inc.id === incidentId ? { ...inc, status: "INTERCEPTED_BY_GUARDRAIL" } : inc))
        );
      } else {
        setBlockedAlert(null);
        const execId = data.execution_id || `N8N-RUN-${Math.floor(1000 + Math.random() * 9000)}`;
        const timeNow = new Date().toLocaleTimeString("en-IN", { timeZone: "Asia/Kolkata", hour12: false });
        const initialExec: PlaybookExecution = {
          execution_id: execId,
          incident_id: incidentId,
          target_ip: targetIp,
          status: "QUEUED",
          step_index: 1,
          total_steps: 3,
          step: data.step || "Dispatching webhook to n8n runtime...",
          progress: 33,
          timestamp: timeNow,
          logs: [
            `[${timeNow}] [N8N-INIT] Initializing automated response playbook for target ${targetIp}`,
            `[${timeNow}] [N8N-AUTH] Authorization validated by operator. Dispatching webhook -> http://localhost:5678/webhook/chimera`,
          ],
        };
        setPlaybookExecutions((prev) => ({
          ...prev,
          [incidentId]: initialExec,
        }));
      }
    } catch (err) {
      console.warn("[Incidents] Contain API error:", err);
    } finally {
      setActionLoading((prev) => ({ ...prev, [incidentId]: null }));
    }
  };

  const handleReject = async (incidentId: string) => {
    setActionLoading((prev) => ({ ...prev, [incidentId]: "reject" }));
    // Optimistic UI update
    setIncidents((prev) =>
      prev.map((inc) => (inc.id === incidentId ? { ...inc, status: "REJECTED" } : inc))
    );

    try {
      await fetch("http://localhost:8000/api/incidents/reject", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incident_id: incidentId }),
      });
    } catch (err) {
      console.warn("[Incidents] Reject API error:", err);
    } finally {
      setActionLoading((prev) => ({ ...prev, [incidentId]: null }));
    }
  };

  const isContainLoading = selectedIncident && actionLoading[selectedIncident.id] === "contain";
  const isRejectLoading = selectedIncident && actionLoading[selectedIncident.id] === "reject";
  const isGuardrailBlocked =
    selectedIncident?.status === "INTERCEPTED_BY_GUARDRAIL" ||
    blockedAlert?.id === selectedIncident?.id;
  const selectedPlaybook = selectedIncident ? playbookExecutions[selectedIncident.id] : null;

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
              Enforcing Swytchcode Zero-Trust Pre-Execution Guardrails & Autonomous Playbooks
            </p>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-2 font-mono text-xs">
          {["ALL", "PENDING_APPROVAL", "CONTAINED", "INTERCEPTED_BY_GUARDRAIL", "REJECTED"].map((status) => (
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
              {status === "INTERCEPTED_BY_GUARDRAIL" ? "GUARDRAIL BLOCKED" : status.replace(/_/g, " ")}
            </button>
          ))}
        </div>
      </div>

      {/* Full-Width Guardrail Intercept Alert Banner */}
      {isGuardrailBlocked && (
        <div className="p-4 rounded-xl border border-[#ff003c]/70 bg-[#ff003c]/15 text-[#ff003c] flex items-center gap-4 font-mono text-xs shadow-[0_0_35px_rgba(255,0,60,0.35)] animate-pulse">
          <ShieldAlert className="w-7 h-7 shrink-0 text-[#ff003c]" />
          <div className="flex-1">
            <span className="font-bold text-sm block tracking-wide text-white">
              🚨 SWYTCHCODE POLICY INTERCEPT: Autonomous containment blocked on protected core subnet (10.0.0.5). Zero-Trust Execution Layer Active.
            </span>
            <span className="text-[11px] text-white/80 mt-1 block">
              Pre-execution policy rule <code className="text-[#00f0ff]">[block-core-infrastructure-isolation]</code> intercepted rogue AI action targeting <code className="text-[#ff003c]">{selectedIncident?.source_ip || "10.0.0.5"}</code>.
            </span>
          </div>
        </div>
      )}

      {/* Main Grid: Left Incident List (5 cols), Right Incident Details (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[580px]">
        {/* Incident List */}
        <div className="lg:col-span-5 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex justify-between items-center">
            <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
              Active Incident Queue ({filtered.length})
            </span>
            <div className="flex items-center gap-2 text-[10px] font-mono">
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-full",
                  isConnected ? "bg-[#00ff66] animate-ping" : "bg-[#ffb703]"
                )}
              />
              <span className={isConnected ? "text-[#00ff66]" : "text-[#ffb703]"}>
                {isConnected ? "LIVE STREAM" : "POLLING"}
              </span>
            </div>
          </div>

          <div className="flex-1 p-3.5 space-y-3 overflow-y-auto">
            {filtered.map((inc) => {
              const isSelected = selectedIncident?.id === inc.id;
              const isCritical = inc.severity === "CRITICAL";
              const isPending = inc.status === "PENDING_APPROVAL";
              const isContained = inc.status === "CONTAINED";
              const isIntercepted = inc.status === "INTERCEPTED_BY_GUARDRAIL";

              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncidentId(inc.id)}
                  className={cn(
                    "p-4 rounded-xl border transition-all cursor-pointer",
                    isSelected
                      ? isIntercepted
                        ? "bg-[#ff003c]/15 border-[#ff003c]/70 shadow-[0_0_25px_rgba(255,0,60,0.25)]"
                        : "bg-[#00f0ff]/10 border-[#00f0ff]/50 shadow-[0_0_20px_rgba(0,240,255,0.15)]"
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
                        isIntercepted
                          ? "bg-[#ff003c]/25 text-[#ff003c] border border-[#ff003c]/50 animate-pulse shadow-[0_0_8px_rgba(255,0,60,0.3)]"
                          : isPending
                          ? "bg-[#ffb703]/15 text-[#ffb703] border border-[#ffb703]/40 animate-pulse"
                          : isContained
                          ? "bg-[#00ff66]/15 text-[#00ff66] border border-[#00ff66]/40"
                          : "bg-white/10 text-white/50 border border-white/20"
                      )}
                    >
                      {isIntercepted ? "GUARDRAIL BLOCKED" : inc.status.replace(/_/g, " ")}
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-white mt-2 leading-snug">
                    {inc.title}
                  </h3>

                  {inc.cert_in_category && (
                    <div className="mt-2 flex items-center gap-1.5 text-[10px] font-mono text-[#00f0ff]/80 truncate">
                      <span className="text-white/40">CERT-In:</span>
                      <span className="truncate font-semibold">{inc.cert_in_category}</span>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-white/5 font-mono text-[11px] text-white/50">
                    <div>
                      <span>TARGET IP: </span>
                      <strong className={cn(isIntercepted ? "text-[#ff003c]" : "text-white")}>{inc.source_ip}</strong>
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
        {selectedIncident && (
          <div className="lg:col-span-7 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex flex-wrap gap-2 justify-between items-center">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-[#00f0ff]" />
                <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
                  Incident Dossier: {selectedIncident.id}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <ReportExportButton incident={selectedIncident} variant="compact" />
                <span className="text-xs font-mono text-white/40">
                  {formatLocalTime(selectedIncident.created_at)}
                </span>
              </div>
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

              {/* CERT-In 6-Hour Statutory Compliance Clock */}
              <CertInClock incident={selectedIncident} />

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
                  <span className="text-[10px] text-white/40 uppercase">TARGET / DECOY</span>
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
                  Target IP origin <code className="text-[#00f0ff]">{selectedIncident.source_ip}</code> is flagged in the telemetry stream. Swytchcode Zero-Trust layer monitors and evaluates pre-execution policies on all outgoing containment actions.
                </p>
              </div>

              {/* Human-in-the-loop Action Bar / Playbook Execution Panel */}
              {isGuardrailBlocked ? (
                <div className="p-5 rounded-xl border border-[#ff003c]/40 bg-[#ff003c]/10 space-y-3 shadow-[0_0_20px_rgba(255,0,60,0.2)]">
                  <div className="flex items-center gap-2 text-[#ff003c] font-mono text-xs font-bold">
                    <ShieldAlert className="w-4 h-4 text-[#ff003c] animate-pulse" />
                    <span>SWYTCHCODE ZERO-TRUST GUARDRAIL ACTIVE</span>
                  </div>
                  <p className="text-xs text-white/70 font-mono">
                    Unauthorized isolation on protected core infrastructure (10.0.0.5) has been permanently blocked.
                  </p>
                  <button
                    disabled={true}
                    className="w-full py-4 px-6 rounded-xl font-mono text-sm font-bold bg-[#ff003c]/20 border-2 border-[#ff003c] text-[#ff003c] flex items-center justify-center gap-2.5 shadow-[0_0_25px_rgba(255,0,60,0.4)] cursor-not-allowed opacity-95"
                  >
                    <Ban className="w-5 h-5 text-[#ff003c]" />
                    <span>🛑 BLOCKED BY SWYTCHCODE GUARDRAIL</span>
                  </button>
                </div>
              ) : selectedPlaybook ? (
                <PlaybookExecutionPanel execution={selectedPlaybook} />
              ) : selectedIncident.status === "PENDING_APPROVAL" ? (
                <div className="p-5 rounded-xl border border-[#ffb703]/30 bg-[#ffb703]/5 space-y-3">
                  <div className="flex items-center gap-2 text-[#ffb703] font-mono text-xs font-bold">
                    <AlertOctagon className="w-4 h-4" />
                    <span>HUMAN AUTHORIZATION REQUIRED (Risk Dial &gt;= 0.40)</span>
                  </div>
                  <p className="text-xs text-white/60 font-mono">
                    Approve IP perimeter isolation and host containment via Swytchcode and n8n webhook.
                  </p>
                  <div className="flex items-center gap-3 pt-2">
                    <button
                      onClick={() => handleContain(selectedIncident.id)}
                      disabled={isContainLoading || isRejectLoading}
                      className={cn(
                        "flex-1 flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg font-mono text-xs font-bold transition-all",
                        isContainLoading
                          ? "bg-[#ffb703]/20 border border-[#ffb703]/50 text-[#ffb703] animate-pulse cursor-wait"
                          : "bg-[#00ff66] text-black hover:bg-[#00ff66]/80 shadow-[0_0_15px_rgba(0,255,102,0.3)] cursor-pointer"
                      )}
                    >
                      {isContainLoading ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin text-[#ffb703]" />
                          <span>AUTHORIZING...</span>
                        </>
                      ) : (
                        <>
                          <UserCheck className="w-4 h-4" />
                          <span>AUTHORIZE CONTAINMENT</span>
                        </>
                      )}
                    </button>

                    <button
                      onClick={() => handleReject(selectedIncident.id)}
                      disabled={isContainLoading || isRejectLoading}
                      className={cn(
                        "py-2.5 px-4 rounded-lg border font-mono text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer",
                        isRejectLoading
                          ? "border-[#ffb703]/50 text-[#ffb703] bg-[#ffb703]/10 animate-pulse cursor-wait"
                          : "border-[#ff003c]/40 text-[#ff003c] hover:bg-[#ff003c]/10"
                      )}
                    >
                      {isRejectLoading ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Ban className="w-4 h-4" />
                      )}
                      <span>REJECT / FALSE POSITIVE</span>
                    </button>
                  </div>
                </div>
              ) : selectedIncident.status === "CONTAINED" ? (
                <div className="p-4 rounded-xl border border-[#00ff66]/30 bg-[#00ff66]/5 flex items-center gap-3 font-mono text-xs text-[#00ff66]">
                  <Lock className="w-5 h-5" />
                  <div>
                    <span className="font-bold">CONTAINMENT ACTIVE: </span>
                    <span>IP {selectedIncident.source_ip} blocked at perimeter firewall via n8n playbook.</span>
                  </div>
                </div>
              ) : (
                <div className="p-4 rounded-xl border border-white/20 bg-white/[0.02] flex items-center gap-3 font-mono text-xs text-white/60">
                  <XCircle className="w-5 h-5 text-white/40" />
                  <div>
                    <span className="font-bold">INCIDENT DISMISSED: </span>
                    <span>Marked as FALSE POSITIVE / REJECTED by operator.</span>
                  </div>
                </div>
              )}

              {/* Decision-Provenance Chronological Timeline */}
              <DecisionTimeline incident={selectedIncident} />

              {/* Ask the SOC Explainability Q&A Interface */}
              <AskTheSoc
                incidentId={selectedIncident.id}
                incident={selectedIncident}
              />
            </div>
          </div>

        )}
      </div>
    </div>
  );
}
