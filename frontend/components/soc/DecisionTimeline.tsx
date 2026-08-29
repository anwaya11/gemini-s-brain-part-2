"use client";

import React, { useMemo } from "react";
import {
  ShieldAlert,
  Globe,
  Scale,
  Zap,
  Lock,
  Ban,
  XCircle,
  GitCommit,
  CheckCircle2,
  Clock,
  Sparkles,
  Layers,
} from "lucide-react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { IncidentItem } from "@/hooks/useSOCStream";

interface DecisionTimelineProps {
  incident: IncidentItem;
  className?: string;
}

interface TimelineStep {
  id: string;
  agentName: string;
  emoji: string;
  title: string;
  description: string;
  timestamp: string;
  tagColor: string;
  borderColor: string;
  badgeBg: string;
  icon: React.ElementType;
  pillValue?: string;
  isLatest?: boolean;
}

export function DecisionTimeline({ incident, className }: DecisionTimelineProps) {
  const steps = useMemo<TimelineStep[]>(() => {
    const isCritical = incident.severity === "CRITICAL";
    const isHighRisk = incident.risk_score >= 0.40;
    const isIntercepted = incident.status === "INTERCEPTED_BY_GUARDRAIL";
    const isContained = incident.status === "CONTAINED";
    const isRejected = incident.status === "REJECTED";

    const list: TimelineStep[] = [
      // Step 1: Triage Agent
      {
        id: "step-triage",
        agentName: "TRIAGE AGENT",
        emoji: "🛡️",
        title: "Threat Identified & MITRE ATT&CK Mapped",
        description: `Flagged anomalous payload targeting ${incident.source_ip}. Mapped to ${incident.mitre_technique} with ${(incident.confidence * 100).toFixed(0)}% detection confidence.`,
        timestamp: "T+0.01s",
        tagColor: "#00f0ff",
        borderColor: "border-[#00f0ff]/40",
        badgeBg: "bg-[#00f0ff]/10 text-[#00f0ff]",
        icon: ShieldAlert,
        pillValue: incident.mitre_technique.split("–")[0].trim(),
      },

      // Step 2: Threat Intel Agent
      {
        id: "step-intel",
        agentName: "THREAT INTEL AGENT",
        emoji: "🌐",
        title: "Tavily & Swytchcode Reputation Enrichment",
        description: `Enriched IOC (${incident.source_ip}) via VirusTotal, AbuseIPDB, and Tavily live threat intelligence. Hostile exploit signature confirmed.`,
        timestamp: "T+0.42s",
        tagColor: "#00f0ff",
        borderColor: "border-[#00f0ff]/40",
        badgeBg: "bg-[#00f0ff]/10 text-[#00f0ff]",
        icon: Globe,
        pillValue: isCritical ? "Critical Flag" : "Malicious IOC",
      },

      // Step 3: Risk Engine
      {
        id: "step-risk",
        agentName: "RISK ENGINE",
        emoji: "⚖️",
        title: `Composite Risk Evaluated: ${incident.risk_score.toFixed(3)}`,
        description: isHighRisk
          ? `Risk score (${incident.risk_score.toFixed(3)}) exceeds autonomy cutoff (0.40). Blast radius evaluated across critical infrastructure. Escalated for human authorization.`
          : `Risk score (${incident.risk_score.toFixed(3)}) within autonomy cutoff (< 0.40). Qualified for autonomous containment without human delay.`,
        timestamp: "T+0.85s",
        tagColor: isHighRisk ? "#ffb703" : "#00ff66",
        borderColor: isHighRisk ? "border-[#ffb703]/40" : "border-[#00ff66]/40",
        badgeBg: isHighRisk ? "bg-[#ffb703]/10 text-[#ffb703]" : "bg-[#00ff66]/10 text-[#00ff66]",
        icon: Scale,
        pillValue: `Risk: ${incident.risk_score.toFixed(3)}`,
      },
    ];

    // Step 4: Deception Agent (if decoy path exists)
    if (incident.decoy_path) {
      list.push({
        id: "step-deception",
        agentName: "DECEPTION AGENT",
        emoji: "🪤",
        title: "Decoy Honeypot Routing & Topology Commit",
        description: `Attacker traffic transparently rerouted to decoy honeypot (${incident.decoy_path}). Synthetic telemetry responses committed to blast radius graph.`,
        timestamp: "T+1.20s",
        tagColor: "#00ff66",
        borderColor: "border-[#00ff66]/40",
        badgeBg: "bg-[#00ff66]/10 text-[#00ff66]",
        icon: Zap,
        pillValue: incident.decoy_path,
      });
    }

    // Step 5: Containment Engine (ONLY if actually Contained, Blocked, or Dismissed)
    if (isIntercepted) {
      list.push({
        id: "step-containment-blocked",
        agentName: "SWYTCHCODE GUARDRAIL",
        emoji: "🛑",
        title: "Zero-Trust Pre-Execution Policy Intercept",
        description: `Autonomous containment blocked on protected core subnet (${incident.source_ip}). Swytchcode pre-execution guardrail [policy_protect_core_infrastructure] prevented disruption.`,
        timestamp: "T+1.45s",
        tagColor: "#ff003c",
        borderColor: "border-[#ff003c]/60",
        badgeBg: "bg-[#ff003c]/15 text-[#ff003c]",
        icon: Ban,
        pillValue: "POLICY_BLOCKED",
        isLatest: true,
      });
    } else if (isContained) {
      list.push({
        id: "step-containment-success",
        agentName: "CONTAINMENT ENGINE",
        emoji: "⚡",
        title: "Perimeter Firewall Edge Block Executed",
        description: `Perimeter firewall DROP rule deployed via n8n automated playbook. IP ${incident.source_ip} isolated at edge gateway. Slack alerted and Jira incident ticket created.`,
        timestamp: "T+1.85s",
        tagColor: "#00ff66",
        borderColor: "border-[#00ff66]/60",
        badgeBg: "bg-[#00ff66]/15 text-[#00ff66]",
        icon: Lock,
        pillValue: "CONTAINED",
        isLatest: true,
      });
    } else if (isRejected) {
      list.push({
        id: "step-containment-rejected",
        agentName: "OPERATOR DISPOSITION",
        emoji: "🛡️",
        title: "Incident Dismissed / False Positive",
        description: `Incident marked as FALSE POSITIVE by security operator. Perimeter suppression filter committed and risk model tuned.`,
        timestamp: "T+2.10s",
        tagColor: "#a855f7",
        borderColor: "border-[#a855f7]/40",
        badgeBg: "bg-[#a855f7]/15 text-[#a855f7]",
        icon: XCircle,
        pillValue: "DISMISSED",
        isLatest: true,
      });
    } else {
      // If Pending Approval, mark Step 4/3 as current latest
      if (list.length > 0) {
        list[list.length - 1].isLatest = true;
      }
    }

    return list;
  }, [incident]);

  return (
    <div
      className={cn(
        "w-full rounded-xl border border-white/10 bg-[#06090e]/70 backdrop-blur-md p-4 sm:p-5 font-mono text-xs shadow-[0_4px_25px_rgba(0,0,0,0.4)]",
        className
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/10">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-[#00f0ff]/10 border border-[#00f0ff]/30 text-[#00f0ff] shadow-[0_0_10px_rgba(0,240,255,0.15)]">
            <GitCommit className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold tracking-widest text-white uppercase flex items-center gap-2">
              Decision-Provenance Timeline
              <span className="px-1.5 py-0.2 text-[9px] font-bold rounded bg-[#00ff66]/10 text-[#00ff66] border border-[#00ff66]/30">
                AUDIT TRACE
              </span>
            </h3>
            <p className="text-[10px] text-white/40 mt-0.5">
              Autonomous AI agent decision sequence with sub-second execution latency.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-[10px] font-mono text-white/40">
          <Clock className="w-3 h-3 text-[#00f0ff]" />
          <span>{steps.length} STAGES</span>
        </div>
      </div>

      {/* Vertical Chronological Timeline Track */}
      <div className="relative pl-5 ml-2 border-l-2 border-[#00f0ff]/20 space-y-4 my-1">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          return (
            <motion.div
              key={step.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.25, delay: idx * 0.06 }}
              className="relative group"
            >
              {/* Glowing Node Dot on Timeline Track */}
              <div
                className="absolute -left-[27px] top-1 flex items-center justify-center w-4 h-4 rounded-full bg-[#030303] border-2 transition-all duration-300 group-hover:scale-125"
                style={{ borderColor: step.tagColor }}
              >
                <div
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ backgroundColor: step.tagColor }}
                />
                {step.isLatest && (
                  <span
                    className="absolute inline-flex w-full h-full rounded-full opacity-75 animate-ping"
                    style={{ backgroundColor: step.tagColor }}
                  />
                )}
              </div>

              {/* Step Card Content */}
              <div
                className={cn(
                  "p-3 rounded-lg border bg-[#030303]/60 transition-all duration-200 hover:bg-[#030303]/90 hover:border-white/20",
                  step.borderColor
                )}
              >
                {/* Step Header Row */}
                <div className="flex flex-wrap items-center justify-between gap-1.5 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        "px-1.5 py-0.5 text-[9px] font-bold uppercase rounded border tracking-wider",
                        step.badgeBg,
                        step.borderColor
                      )}
                    >
                      {step.emoji} {step.agentName}
                    </span>
                    <span className="text-[10px] font-bold text-white/90">
                      {step.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-[10px]">
                    {step.pillValue && (
                      <span className="px-1.5 py-0.2 text-[9px] rounded bg-white/5 text-white/60 border border-white/10 truncate max-w-[140px]">
                        {step.pillValue}
                      </span>
                    )}
                    <span className="text-[#00f0ff] font-bold bg-[#00f0ff]/10 px-1.5 py-0.2 rounded border border-[#00f0ff]/20">
                      {step.timestamp}
                    </span>
                  </div>
                </div>

                {/* Step Description */}
                <p className="text-white/70 text-[11px] leading-relaxed pl-0.5">
                  {step.description}
                </p>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}

export default DecisionTimeline;
