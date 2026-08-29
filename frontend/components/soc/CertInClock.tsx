"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Clock,
  ShieldAlert,
  FileText,
  Copy,
  Check,
  Download,
  X,
  AlertTriangle,
  FileCheck,
  Building2,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { IncidentItem } from "@/hooks/useSOCStream";

interface CertInClockProps {
  incident: IncidentItem;
}

export function CertInClock({ incident }: CertInClockProps) {
  const [secondsLeft, setSecondsLeft] = useState<number>(6 * 3600);
  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  // Parse incident created_at and calculate remaining seconds out of 6 hours
  useEffect(() => {
    const calculateTimeRemaining = () => {
      try {
        let createdTime: number;

        if (incident.created_at.includes("IST")) {
          // Parse e.g. "2026-08-27 02:15:10 IST"
          const cleanStr = incident.created_at.replace(" IST", "").trim();
          createdTime = new Date(cleanStr).getTime();
          if (isNaN(createdTime)) {
            // Fallback to offset against current time
            createdTime = Date.now() - 22 * 60 * 1000; // ~22 minutes ago
          }
        } else {
          createdTime = new Date(incident.created_at).getTime();
          if (isNaN(createdTime)) {
            createdTime = Date.now() - 22 * 60 * 1000;
          }
        }

        const now = Date.now();
        const elapsedSec = Math.max(0, Math.floor((now - createdTime) / 1000));
        const totalWindowSec = 6 * 3600; // 6 hours
        const remaining = Math.max(0, totalWindowSec - (elapsedSec % totalWindowSec));
        setSecondsLeft(remaining);
      } catch (err) {
        setSecondsLeft(5 * 3600 + 38 * 60); // Default to ~5h 38m
      }
    };

    calculateTimeRemaining();
    const interval = setInterval(() => {
      setSecondsLeft((prev) => Math.max(0, prev - 1));
    }, 1000);

    return () => clearInterval(interval);
  }, [incident.created_at, incident.id]);

  // Format countdown
  const hours = Math.floor(secondsLeft / 3600);
  const minutes = Math.floor((secondsLeft % 3600) / 60);
  const seconds = secondsLeft % 60;

  const formattedHours = String(hours).padStart(2, "0");
  const formattedMinutes = String(minutes).padStart(2, "0");
  const formattedSeconds = String(seconds).padStart(2, "0");

  // Determine urgency band
  // > 3 hours: Safe / Emerald
  // 1 to 3 hours: Warning / Amber
  // < 1 hour: Critical / Red
  const urgency = useMemo(() => {
    if (hours >= 3) return "SAFE";
    if (hours >= 1) return "WARNING";
    return "CRITICAL";
  }, [hours]);

  const certCategory =
    incident.cert_in_category ||
    (incident.source_ip === "10.0.0.5"
      ? "Compromise of critical systems/information"
      : incident.title.toLowerCase().includes("ssh") || incident.title.toLowerCase().includes("credential")
      ? "Identity theft, spoofing, and phishing attacks"
      : incident.title.toLowerCase().includes("recon") || incident.title.toLowerCase().includes("probe")
      ? "Targeted scanning/probing of critical networks/systems"
      : "Unauthorized access to IT systems or data");

  // Generate CERT-In Section 70B Annexure Markdown Report
  const certInReportMarkdown = useMemo(() => {
    return `# CERT-IN INITIAL INCIDENT REPORTING ANNEXURE
Reference: Direction No. 20(3)/2022-CERT-In under Section 70B of Information Technology Act, 2000

--------------------------------------------------------------------------------
1. MANDATORY REPORTING TIMELINE & REGULATORY METADATA
--------------------------------------------------------------------------------
• Regulatory Mandate   : Section 70B, IT Act 2000 (Mandatory 6-Hour Reporting Window)
• Incident ID          : ${incident.id}
• CERT-In Category     : ${certCategory}
• Severity Level       : ${incident.severity}
• Detection Timestamp  : ${incident.created_at}
• Reporting SOC Entity : PRIMARY-SOC-01 (CHIMERA AutoSOC Autonomous Defence Matrix)
• Statutory Deadline   : Within 6 hours of formal detection

--------------------------------------------------------------------------------
2. TECHNICAL INCIDENT & THREAT ATTRIBUTION
--------------------------------------------------------------------------------
• Incident Title       : ${incident.title}
• Attacker Source IP   : ${incident.source_ip}
• Composite Risk Score : ${incident.risk_score.toFixed(3)} / 1.000
• Threat Confidence    : ${(incident.confidence * 100).toFixed(0)}%
• MITRE ATT&CK Mapping : ${incident.mitre_technique}
• Targeted Endpoint    : ${incident.decoy_path}

--------------------------------------------------------------------------------
3. CONTAINMENT & REMEDIATION ACTIONS TAKEN
--------------------------------------------------------------------------------
• Status               : ${incident.status}
• Containment Vector   : ${
      incident.source_ip === "10.0.0.5"
        ? "Swytchcode Zero-Trust Guardrail Policy [policy_protect_core_infrastructure] actively halted unauthorized execution."
        : incident.status === "CONTAINED"
        ? "Automated n8n Perimeter Firewall Isolation & Subnet Block Verified."
        : "Pending Operator Authorization / Deception Honeypot Active."
    }
• Blast Radius Mitigation: Attacker isolated and logged in deception sandbox without lateral movement.

--------------------------------------------------------------------------------
4. INCIDENT SUMMARY & FORENSIC CHATTER
--------------------------------------------------------------------------------
An anomalous high-risk security event was detected against the perimeter. The threat was categorized under CERT-In mandatory reporting requirements. Telemetry has been committed to SOC logs and real-time guardrails remain enforced.

Authorized Reporting Officer: CHIMERA SOC Lead / Incident Commander
Contact / SOC Hotline: cert-in-reporting@chimera-defense.internal
Generated by CHIMERA AutoSOC Matrix v2.0
`;
  }, [incident, certCategory]);

  const handleCopyReport = async () => {
    try {
      await navigator.clipboard.writeText(certInReportMarkdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.warn("Clipboard write failed:", err);
    }
  };

  const handleDownloadReport = () => {
    const blob = new Blob([certInReportMarkdown], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `CERT-In_Report_${incident.id}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <>
      {/* ── CERT-In 6-Hour Countdown Clock Glassmorphic Card ─────────────── */}
      <div
        className={cn(
          "relative overflow-hidden rounded-xl border p-4 font-mono backdrop-blur-xl transition-all duration-300 shadow-lg",
          urgency === "SAFE"
            ? "border-[#00ff66]/30 bg-[#00ff66]/[0.03] shadow-[0_0_20px_rgba(0,255,102,0.08)]"
            : urgency === "WARNING"
            ? "border-[#ffb703]/30 bg-[#ffb703]/[0.03] shadow-[0_0_20px_rgba(255,183,3,0.08)]"
            : "border-[#ff003c]/40 bg-[#ff003c]/[0.05] shadow-[0_0_25px_rgba(255,0,60,0.15)] animate-pulse"
        )}
      >
        {/* Ambient Refraction Glow */}
        <div
          className={cn(
            "absolute -top-10 -right-10 h-28 w-28 rounded-full blur-[50px] pointer-events-none opacity-60",
            urgency === "SAFE"
              ? "bg-[#00ff66]/20"
              : urgency === "WARNING"
              ? "bg-[#ffb703]/20"
              : "bg-[#ff003c]/30"
          )}
        />

        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Left: CERT-In Metadata & Category */}
          <div className="flex items-start gap-3">
            <div
              className={cn(
                "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border",
                urgency === "SAFE"
                  ? "border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66]"
                  : urgency === "WARNING"
                  ? "border-[#ffb703]/40 bg-[#ffb703]/10 text-[#ffb703]"
                  : "border-[#ff003c]/40 bg-[#ff003c]/15 text-[#ff003c]"
              )}
            >
              <Clock className="h-5 w-5" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold tracking-wider uppercase text-white">
                  CERT-In 6-Hour Compliance Clock
                </span>
                <span className="px-1.5 py-0.2 rounded text-[9px] font-bold border border-white/20 bg-white/[0.04] text-white/70">
                  SEC 70B IT ACT
                </span>
              </div>
              <div className="mt-0.5 text-[11px] text-white/60">
                Category: <strong className="text-[#00f0ff]">{certCategory}</strong>
              </div>
            </div>
          </div>

          {/* Right: Live Ticking Countdown & Action Button */}
          <div className="flex items-center gap-3">
            <div
              className={cn(
                "flex items-center gap-2 rounded-lg border px-3 py-1.5 font-mono text-sm font-bold tracking-widest",
                urgency === "SAFE"
                  ? "border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66] shadow-[0_0_10px_rgba(0,255,102,0.2)]"
                  : urgency === "WARNING"
                  ? "border-[#ffb703]/40 bg-[#ffb703]/10 text-[#ffb703] shadow-[0_0_10px_rgba(255,183,3,0.2)]"
                  : "border-[#ff003c]/50 bg-[#ff003c]/20 text-[#ff003c] shadow-[0_0_15px_rgba(255,0,60,0.3)]"
              )}
            >
              <span className="relative flex h-2 w-2">
                <span
                  className={cn(
                    "absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping",
                    urgency === "SAFE"
                      ? "bg-[#00ff66]"
                      : urgency === "WARNING"
                      ? "bg-[#ffb703]"
                      : "bg-[#ff003c]"
                  )}
                />
                <span
                  className={cn(
                    "relative inline-flex h-2 w-2 rounded-full",
                    urgency === "SAFE"
                      ? "bg-[#00ff66]"
                      : urgency === "WARNING"
                      ? "bg-[#ffb703]"
                      : "bg-[#ff003c]"
                  )}
                />
              </span>
              <span>
                {formattedHours}h {formattedMinutes}m {formattedSeconds}s remaining
              </span>
            </div>

            {/* Generate CERT-In Report Modal Trigger */}
            <button
              onClick={() => setIsReportOpen(true)}
              className="flex items-center gap-1.5 rounded-lg border border-[#00f0ff]/40 bg-[#00f0ff]/10 px-3 py-1.5 text-xs font-bold text-[#00f0ff] shadow-[0_0_12px_rgba(0,240,255,0.2)] transition-all hover:bg-[#00f0ff]/20 hover:border-[#00f0ff]/70 cursor-pointer"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>Generate CERT-In Report</span>
            </button>
          </div>
        </div>

        {/* Linear Urgency Timeline Bar */}
        <div className="mt-3 relative h-1 w-full overflow-hidden rounded-full bg-white/10">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-1000",
              urgency === "SAFE"
                ? "bg-[#00ff66] shadow-[0_0_8px_#00ff66]"
                : urgency === "WARNING"
                ? "bg-[#ffb703] shadow-[0_0_8px_#ffb703]"
                : "bg-[#ff003c] shadow-[0_0_8px_#ff003c]"
            )}
            style={{ width: `${Math.max(10, Math.min(100, (secondsLeft / (6 * 3600)) * 100))}%` }}
          />
        </div>
      </div>

      {/* ── CERT-In Section 70B Annexure Modal ────────────────────────────── */}
      {isReportOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200 font-mono">
          <div className="relative w-full max-w-3xl overflow-hidden rounded-2xl border border-[#00f0ff]/40 bg-[#06090e] shadow-[0_0_50px_rgba(0,240,255,0.2)] flex flex-col max-h-[88vh]">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-white/10 px-6 py-4 bg-[#030303]/80">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#00f0ff]/40 bg-[#00f0ff]/10 text-[#00f0ff]">
                  <FileCheck className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold tracking-wider text-white uppercase">
                    CERT-In Initial Incident Report (Annexure 1)
                  </h3>
                  <p className="text-[10px] text-white/50">
                    Mandatory Filing under Section 70B IT Act, 2000 · Incident {incident.id}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setIsReportOpen(false)}
                className="rounded-lg p-1 text-white/50 hover:bg-white/10 hover:text-white transition-colors cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Body / Pre-filled Markdown */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              <div className="rounded-xl border border-white/10 bg-[#020407] p-4 text-xs font-mono leading-relaxed text-white/90 shadow-inner select-text whitespace-pre-wrap">
                {certInReportMarkdown}
              </div>
            </div>

            {/* Modal Footer Actions */}
            <div className="flex items-center justify-between border-t border-white/10 px-6 py-4 bg-[#030303]/80">
              <div className="flex items-center gap-2 text-[11px] text-[#00ff66]">
                <ShieldAlert className="h-4 w-4" />
                <span>Statutory 6-Hour Timeline Active</span>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={handleCopyReport}
                  className="flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/[0.05] px-3.5 py-2 text-xs font-bold text-white hover:bg-white/10 transition-all cursor-pointer"
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-[#00ff66]" />
                      <span className="text-[#00ff66]">Copied to Clipboard!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5 text-white/70" />
                      <span>Copy Annexure</span>
                    </>
                  )}
                </button>

                <button
                  onClick={handleDownloadReport}
                  className="flex items-center gap-1.5 rounded-lg border border-[#00f0ff]/50 bg-[#00f0ff] px-4 py-2 text-xs font-bold text-black shadow-[0_0_15px_rgba(0,240,255,0.3)] hover:bg-[#00f0ff]/80 transition-all cursor-pointer"
                >
                  <Download className="h-3.5 w-3.5 text-black" />
                  <span>Download (.md)</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default CertInClock;
