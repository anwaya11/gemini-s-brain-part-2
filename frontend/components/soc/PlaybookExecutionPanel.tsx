"useEsModule";
"use client";

import React, { useEffect, useRef } from "react";
import {
  CheckCircle2,
  Loader2,
  Terminal,
  ShieldCheck,
  Zap,
  Radio,
  ExternalLink,
  Lock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { PlaybookExecution } from "@/hooks/useSOCStream";

interface PlaybookExecutionPanelProps {
  execution: PlaybookExecution;
  onReset?: () => void;
}

export function PlaybookExecutionPanel({ execution, onReset }: PlaybookExecutionPanelProps) {
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal log as new lines arrive
  useEffect(() => {
    if (terminalBottomRef.current) {
      terminalBottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [execution.logs]);

  const isCompleted = execution.status === "COMPLETED";
  const isRunning = execution.status === "RUNNING";
  const isQueued = execution.status === "QUEUED";

  // Compute step active/completed states
  const step1Done = execution.step_index >= 1;
  const step2Done = execution.step_index >= 2;
  const step3Done = execution.step_index >= 3 || isCompleted;

  return (
    <div className="relative overflow-hidden rounded-xl border border-[#00f0ff]/30 bg-[#06090e]/90 p-4 shadow-[0_0_25px_rgba(0,240,255,0.12)] backdrop-blur-xl transition-all duration-300 font-mono">
      {/* Ambient background glow */}
      <div
        className={cn(
          "absolute -top-12 -right-12 h-32 w-32 rounded-full blur-[60px] pointer-events-none transition-colors duration-700",
          isCompleted ? "bg-[#00ff66]/20" : "bg-[#00f0ff]/15"
        )}
      />

      {/* ── Top Run ID & Engine Status Bar ───────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3">
        <div className="flex items-center gap-2.5">
          <div
            className={cn(
              "flex h-7 w-7 items-center justify-center rounded-lg border",
              isCompleted
                ? "border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66] shadow-[0_0_10px_rgba(0,255,102,0.3)]"
                : "border-[#00f0ff]/40 bg-[#00f0ff]/10 text-[#00f0ff] shadow-[0_0_10px_rgba(0,240,255,0.3)]"
            )}
          >
            {isCompleted ? (
              <ShieldCheck className="h-4 w-4" />
            ) : isRunning ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Zap className="h-4 w-4 text-[#ffb703] animate-pulse" />
            )}
          </div>

          <div>
            <div className="flex items-center gap-2 text-xs font-bold tracking-wider uppercase text-white">
              <span>n8n Playbook Lifecycle</span>
              <span className="text-[#00f0ff] font-extrabold">{execution.execution_id}</span>
            </div>
            <div className="text-[10px] text-white/50">
              Target: <span className="text-[#ff003c] font-semibold">{execution.target_ip}</span> · Incident:{" "}
              <span className="text-white/80">{execution.incident_id}</span>
            </div>
          </div>
        </div>

        {/* Status Badge */}
        <div
          className={cn(
            "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[10px] font-bold tracking-wider uppercase border",
            isCompleted
              ? "border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66] shadow-[0_0_8px_rgba(0,255,102,0.2)]"
              : isRunning
              ? "border-[#00f0ff]/40 bg-[#00f0ff]/10 text-[#00f0ff] animate-pulse shadow-[0_0_8px_rgba(0,240,255,0.2)]"
              : "border-[#ffb703]/40 bg-[#ffb703]/10 text-[#ffb703]"
          )}
        >
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              isCompleted ? "bg-[#00ff66]" : isRunning ? "bg-[#00f0ff] animate-ping" : "bg-[#ffb703]"
            )}
          />
          <span>{execution.status}</span>
        </div>
      </div>

      {/* ── 3-Step Visual Progression Indicator ──────────────────────────── */}
      <div className="my-4 space-y-2">
        <div className="grid grid-cols-3 gap-2 text-[10px] font-bold tracking-wide uppercase">
          {/* Step 1: Dispatched */}
          <div
            className={cn(
              "flex items-center gap-1.5 rounded-lg border p-2 transition-all duration-300",
              step1Done
                ? "border-[#00f0ff]/40 bg-[#00f0ff]/10 text-[#00f0ff] shadow-[0_0_8px_rgba(0,240,255,0.15)]"
                : "border-white/10 bg-white/[0.02] text-white/40"
            )}
          >
            {step2Done ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-[#00ff66]" />
            ) : isQueued ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[#00f0ff]" />
            ) : (
              <span className="h-3.5 w-3.5 rounded-full border border-white/30 text-center leading-3 text-[9px]">1</span>
            )}
            <span className="truncate">1. Dispatched</span>
          </div>

          {/* Step 2: Executing Playbook */}
          <div
            className={cn(
              "flex items-center gap-1.5 rounded-lg border p-2 transition-all duration-300",
              step2Done
                ? isCompleted
                  ? "border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66]"
                  : "border-[#ffb703]/40 bg-[#ffb703]/10 text-[#ffb703] shadow-[0_0_8px_rgba(255,183,3,0.2)] animate-pulse"
                : "border-white/10 bg-white/[0.02] text-white/40"
            )}
          >
            {step3Done ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-[#00ff66]" />
            ) : isRunning ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[#ffb703]" />
            ) : (
              <span className="h-3.5 w-3.5 rounded-full border border-white/30 text-center leading-3 text-[9px]">2</span>
            )}
            <span className="truncate">2. Executing</span>
          </div>

          {/* Step 3: Edge Block Verified */}
          <div
            className={cn(
              "flex items-center gap-1.5 rounded-lg border p-2 transition-all duration-300",
              step3Done
                ? "border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66] shadow-[0_0_12px_rgba(0,255,102,0.25)]"
                : "border-white/10 bg-white/[0.02] text-white/40"
            )}
          >
            {step3Done ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-[#00ff66]" />
            ) : (
              <Lock className="h-3.5 w-3.5 text-white/30" />
            )}
            <span className="truncate">3. Block Verified</span>
          </div>
        </div>

        {/* Animated Progress Bar */}
        <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-white/10">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-500",
              isCompleted
                ? "bg-[#00ff66] shadow-[0_0_12px_#00ff66]"
                : "bg-gradient-to-r from-[#00f0ff] to-[#ffb703] shadow-[0_0_10px_#00f0ff]"
            )}
            style={{ width: `${Math.max(execution.progress, 15)}%` }}
          />
        </div>
      </div>

      {/* Current Step Description */}
      <div className="mb-3 flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-xs">
        <Radio className="h-3.5 w-3.5 shrink-0 text-[#00f0ff] animate-pulse" />
        <span className="text-white/60">ACTION:</span>
        <span className="font-semibold text-white tracking-wide truncate">{execution.step}</span>
      </div>

      {/* ── Real-Time Terminal Execution Logs ────────────────────────────── */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-[10px] text-white/40 uppercase">
          <div className="flex items-center gap-1.5">
            <Terminal className="h-3 w-3 text-[#00f0ff]" />
            <span>n8n Webhook / Automation Stream</span>
          </div>
          <span>RUN: {execution.execution_id}</span>
        </div>

        <div className="h-28 overflow-y-auto rounded-lg border border-white/10 bg-[#020407] p-2.5 text-[11px] leading-relaxed text-white/80 shadow-inner select-text">
          {execution.logs && execution.logs.length > 0 ? (
            execution.logs.map((log, index) => {
              const isHighlight = log.includes("[VERIFIED]") || log.includes("[FIREWALL]");
              const isInit = log.includes("[N8N-INIT]") || log.includes("[N8N-AUTH]");
              return (
                <div
                  key={index}
                  className={cn(
                    "font-mono py-0.5",
                    isHighlight
                      ? "text-[#00ff66] font-semibold drop-shadow-[0_0_5px_rgba(0,255,102,0.4)]"
                      : isInit
                      ? "text-[#00f0ff]"
                      : "text-white/70"
                  )}
                >
                  {log}
                </div>
              );
            })
          ) : (
            <div className="flex items-center gap-2 text-white/40 italic py-1">
              <Loader2 className="h-3 w-3 animate-spin" />
              <span>Awaiting telemetry broadcast...</span>
            </div>
          )}
          <div ref={terminalBottomRef} />
        </div>
      </div>

      {/* ── Completed Containment Action Banner ──────────────────────────── */}
      {isCompleted && (
        <div className="mt-3 flex items-center justify-between rounded-lg border border-[#00ff66]/30 bg-[#00ff66]/10 px-3.5 py-2 text-xs text-[#00ff66] shadow-[0_0_15px_rgba(0,255,102,0.15)] animate-in fade-in duration-300">
          <div className="flex items-center gap-2 font-bold">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>PLAYBOOK EXECUTION SUCCEEDED · HOST ISOLATED</span>
          </div>
          <span className="text-[10px] font-mono text-[#00ff66]/80">{execution.timestamp}</span>
        </div>
      )}
    </div>
  );
}
export default PlaybookExecutionPanel;
