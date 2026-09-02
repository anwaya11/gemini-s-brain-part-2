"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ShieldAlert,
  ArrowLeft,
  FileText,
  Radio,
  UserCheck,
  Ban,
  Clock,
  Globe,
  Layers,
  Cpu,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useSOCStream, IncidentItem } from "@/hooks/useSOCStream";
import { AskTheSoc } from "@/components/soc/AskTheSoc";
import { DecisionTimeline } from "@/components/soc/DecisionTimeline";
import { ReportExportButton } from "@/components/soc/ReportExportButton";

export default function IncidentDetailPage() {
  const params = useParams();
  const incidentId = (params?.id as string) || "INC-2026-0891";
  const { incidents } = useSOCStream("ws://localhost:8000/ws/console");

  const currentIncident: IncidentItem = useMemo(() => {
    const found = incidents.find((i) => i.id === incidentId);
    if (found) return found;
    return {
      id: incidentId,
      title: "SQL Injection on Public Endpoint (/api/admin/config)",
      source_ip: "185.220.101.42",
      severity: "CRITICAL",
      cert_in_category: "Unauthorized access to IT systems or data",
      risk_score: 0.842,
      confidence: 0.94,
      status: "PENDING_APPROVAL",
      mitre_technique: "T1190 – Exploit Public-Facing Application",
      decoy_path: "/decoy/db-admin",
      created_at: new Date().toISOString(),
    };
  }, [incidents, incidentId]);

  return (
    <div className="flex flex-col h-full space-y-5">
      {/* Top Breadcrumb & Actions */}
      <div className="flex items-center justify-between p-4 rounded-xl glass-card hud-corner-border">
        <Link
          href="/incidents"
          className="flex items-center gap-2 text-xs font-mono text-white/60 hover:text-[#00f0ff] transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>BACK TO INCIDENTS QUEUE</span>
        </Link>

        <div className="flex items-center gap-3">
          <span
            className={cn(
              "px-2.5 py-1 text-xs font-mono font-bold rounded border",
              currentIncident.severity === "CRITICAL"
                ? "bg-[#ff003c]/20 text-[#ff003c] border-[#ff003c]/30"
                : "bg-[#ffb703]/20 text-[#ffb703] border-[#ffb703]/30"
            )}
          >
            {currentIncident.severity} SEVERITY
          </span>
          <span
            className={cn(
              "px-2.5 py-1 text-xs font-mono font-bold rounded border uppercase",
              currentIncident.status === "CONTAINED"
                ? "bg-[#00ff66]/20 text-[#00ff66] border-[#00ff66]/30"
                : currentIncident.status === "INTERCEPTED_BY_GUARDRAIL"
                ? "bg-[#ff003c]/20 text-[#ff003c] border-[#ff003c]/30 animate-pulse"
                : "bg-[#ffb703]/20 text-[#ffb703] border-[#ffb703]/30 animate-pulse"
            )}
          >
            {currentIncident.status.replace(/_/g, " ")}
          </span>
        </div>
      </div>

      {/* Main Dossier Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 font-mono text-xs">
        {/* Left Column: Forensic Report */}
        <div className="lg:col-span-8 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex flex-wrap gap-2 justify-between items-center">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#00f0ff]" />
              <h1 className="text-xs font-bold text-white uppercase tracking-wider">
                Full Forensic Dossier: {currentIncident.id}
              </h1>
            </div>
            <div className="flex items-center gap-3">
              <ReportExportButton incident={currentIncident} variant="compact" />
              <span className="text-white/40">GEN: ReportingAgent v2.0</span>
            </div>
          </div>

          <div className="flex-1 p-6 space-y-5 overflow-y-auto">
            {/* Header Description */}
            <div className="p-4 rounded-xl border border-white/10 bg-[#030303]/80 space-y-2">
              <h2 className="text-sm font-bold text-white">
                🛡️ Incident Analysis — {currentIncident.mitre_technique}
              </h2>
              <p className="text-white/70 leading-relaxed text-[11px]">
                Target endpoint <code className="text-[#00f0ff]">{currentIncident.decoy_path}</code> was subject to anomalous activity from origin IP <code className="text-[#ff003c]">{currentIncident.source_ip}</code> matching known threat actor signatures.
              </p>
            </div>

            {/* Decision-Provenance Chronological Timeline */}
            <DecisionTimeline incident={currentIncident} />

            {/* Ask the SOC Explainability Q&A Interface */}
            <div className="pt-2">
              <AskTheSoc incidentId={currentIncident.id} incident={currentIncident} />
            </div>
          </div>
        </div>



        {/* Right Column: Authorization Controls & Metadata */}
        <div className="lg:col-span-4 flex flex-col gap-5">
          {/* Action Card */}
          <div className="p-5 rounded-xl border border-[#ffb703]/30 bg-[#ffb703]/5 glass-card hud-corner-border space-y-4">
            <div className="flex items-center gap-2 text-[#ffb703] font-bold">
              <ShieldAlert className="w-4 h-4" />
              <span className="uppercase">Authorization Console</span>
            </div>
            <p className="text-white/60 text-[11px]">
              Authorize n8n containment playbook to drop IP traffic at boundary gateway and terminate active sessions.
            </p>
            <div className="space-y-2 pt-2">
              <button className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-[#00ff66] text-black font-bold hover:bg-[#00ff66]/80 transition-all shadow-[0_0_15px_rgba(0,255,102,0.3)]">
                <UserCheck className="w-4 h-4" />
                EXECUTE CONTAINMENT
              </button>
              <button className="w-full py-2.5 px-4 rounded-lg border border-[#ff003c]/40 text-[#ff003c] font-bold hover:bg-[#ff003c]/10 transition-all">
                <Ban className="w-4 h-4 inline mr-1" />
                DISMISS / FALSE POSITIVE
              </button>
            </div>
          </div>

          {/* Metrics */}
          <div className="glass-card hud-corner-border p-5 rounded-xl space-y-3">
            <span className="text-[10px] text-white/40 uppercase block">
              DIAL RISK METRICS
            </span>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-white/60">CONFIDENCE:</span>
                <span className="text-[#00f0ff] font-bold">94%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-white/60">BLAST RADIUS:</span>
                <span className="text-[#ffb703] font-bold">0.75 (High)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-white/60">ASSET CRITICALITY:</span>
                <span className="text-[#ff003c] font-bold">0.90 (Core DB)</span>
              </div>
              <div className="flex justify-between pt-2 border-t border-white/10">
                <span className="text-white font-bold">TOTAL RISK SCORE:</span>
                <span className="text-[#ff003c] font-bold">0.6210</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
