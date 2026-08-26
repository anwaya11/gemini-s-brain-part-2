"use client";

import React, { useState } from "react";
import {
  Cpu,
  Search,
  Globe,
  ShieldAlert,
  Database,
  ExternalLink,
  Tag,
  CheckCircle,
  AlertTriangle,
  Radio,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

const MOCK_INTEL_RECORDS = [
  {
    ioc: "185.220.101.42",
    type: "IPv4",
    confidence: 0.94,
    tags: ["tor-exit-node", "scanner", "c2-server", "virustotal-flagged"],
    vt_score: "48/72 Engines Flagged",
    abuse_score: "98% Abuse Confidence",
    summary:
      "Active Tor Exit node observed conducting automated vulnerability scanning against public authentication gateways and API admin endpoints.",
    source: "Tavily Web Intel + Swytchcode VirusTotal",
    last_seen: "2 mins ago",
  },
  {
    ioc: "CVE-2024-3400",
    type: "CVE",
    confidence: 0.98,
    tags: ["critical", "rce", "active-exploitation", "zero-day"],
    vt_score: "Known Exploit Payload",
    abuse_score: "High Severity Threat",
    summary:
      "Palo Alto Networks PAN-OS Command Injection Vulnerability allowing unauthenticated attackers to execute arbitrary code with root privileges.",
    source: "NVD + Tavily Live Threat QnA",
    last_seen: "15 mins ago",
  },
  {
    ioc: "45.154.255.89",
    type: "IPv4",
    confidence: 0.88,
    tags: ["botnet", "credential-stuffing", "abuseipdb-reported"],
    vt_score: "32/72 Engines Flagged",
    abuse_score: "85% Abuse Confidence",
    summary:
      "Host associated with distributed brute-force attacks against SSH services and WordPress XML-RPC endpoints across multiple European datacenters.",
    source: "Swytchcode AbuseIPDB Connector",
    last_seen: "1 hour ago",
  },
];

export default function ThreatIntelPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedRecord, setSelectedRecord] = useState(MOCK_INTEL_RECORDS[0]);

  return (
    <div className="flex flex-col h-full space-y-5">
      {/* Header & Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-xl glass-card hud-corner-border">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#00f0ff]/10 border border-[#00f0ff]/30 text-[#00f0ff]">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-wider text-white uppercase font-mono">
              Threat Intelligence & IOC Enrichment Engine
            </h1>
            <p className="text-xs text-white/50 font-mono">
              Parallel enrichment via Tavily Live Web Intelligence & Swytchcode (VirusTotal / AbuseIPDB)
            </p>
          </div>
        </div>

        {/* Search Bar */}
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/40" />
          <input
            type="text"
            placeholder="Search IP, Domain, CVE, or Hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-[#030303]/80 border border-[#00f0ff]/20 text-white placeholder-white/30 text-xs font-mono focus:outline-none focus:border-[#00f0ff] focus:shadow-[0_0_15px_rgba(0,240,255,0.25)] transition-all"
          />
        </div>
      </div>

      {/* Main Intel Body: Left Grid of Known IOCs, Right Detailed Dossier */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[580px]">
        {/* Left: IOC List */}
        <div className="lg:col-span-5 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex justify-between items-center">
            <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
              Recent IOC Query Cache
            </span>
            <span className="text-[10px] font-mono text-[#00ff66]">
              TAVILY + SWYTCHCODE ACTIVE
            </span>
          </div>

          <div className="flex-1 p-3.5 space-y-3 overflow-y-auto">
            {MOCK_INTEL_RECORDS.map((item) => {
              const isSelected = selectedRecord.ioc === item.ioc;

              return (
                <div
                  key={item.ioc}
                  onClick={() => setSelectedRecord(item)}
                  className={cn(
                    "p-4 rounded-xl border transition-all cursor-pointer",
                    isSelected
                      ? "bg-[#00f0ff]/10 border-[#00f0ff]/50 shadow-[0_0_20px_rgba(0,240,255,0.15)]"
                      : "bg-[#030303]/60 border-white/10 hover:border-white/20"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-white">
                        {item.ioc}
                      </span>
                      <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold rounded bg-white/10 text-white/70">
                        {item.type}
                      </span>
                    </div>

                    <span className="text-[10px] font-mono font-bold text-[#ff003c]">
                      {(item.confidence * 100).toFixed(0)}% THREAT
                    </span>
                  </div>

                  <p className="text-xs text-white/60 mt-2 line-clamp-2 leading-relaxed">
                    {item.summary}
                  </p>

                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {item.tags.map((tag) => (
                      <span
                        key={tag}
                        className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/20"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Detailed Threat Intelligence Dossier */}
        <div className="lg:col-span-7 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex justify-between items-center">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-[#00f0ff]" />
              <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
                Synthesized Intelligence Dossier: {selectedRecord.ioc}
              </span>
            </div>
            <span className="text-xs font-mono text-white/40">
              {selectedRecord.last_seen}
            </span>
          </div>

          <div className="flex-1 p-6 space-y-6 overflow-y-auto font-mono text-xs">
            {/* Confidence & Sources Grid */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3.5 rounded-lg border border-[#ff003c]/20 bg-[#ff003c]/5">
                <span className="text-[10px] text-white/40 uppercase">CONFIDENCE RATING</span>
                <p className="text-xl font-bold text-[#ff003c] mt-1">
                  {(selectedRecord.confidence * 100).toFixed(0)}%
                </p>
                <span className="text-[10px] text-[#ff003c]">High Malicious Probability</span>
              </div>

              <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02]">
                <span className="text-[10px] text-white/40 uppercase">VIRUSTOTAL REPUTATION</span>
                <p className="text-xs font-bold text-[#00f0ff] mt-2">
                  {selectedRecord.vt_score}
                </p>
                <span className="text-[10px] text-white/40">Swytchcode Connector</span>
              </div>

              <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02]">
                <span className="text-[10px] text-white/40 uppercase">ABUSEIPDB CONFIDENCE</span>
                <p className="text-xs font-bold text-[#ffb703] mt-2">
                  {selectedRecord.abuse_score}
                </p>
                <span className="text-[10px] text-white/40">Real-time Telemetry</span>
              </div>
            </div>

            {/* Narrative Intelligence Summary */}
            <div className="p-4 rounded-xl border border-[#00f0ff]/20 bg-[#00f0ff]/5 space-y-2">
              <div className="flex items-center gap-2 text-[#00f0ff] font-bold">
                <Radio className="w-3.5 h-3.5 animate-pulse" />
                <span>TAVILY LIVE WEB SYNTHESIS</span>
              </div>
              <p className="text-white/80 leading-relaxed text-[11px]">
                {selectedRecord.summary}
              </p>
            </div>

            {/* Threat Tags */}
            <div>
              <span className="text-[10px] text-white/40 uppercase block mb-2">
                CLASSIFIED THREAT TAXONOMY
              </span>
              <div className="flex flex-wrap gap-2">
                {selectedRecord.tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-2.5 py-1 text-[10px] font-bold rounded-md bg-white/[0.04] text-[#00f0ff] border border-[#00f0ff]/30 shadow-[0_0_8px_rgba(0,240,255,0.15)]"
                  >
                    #{tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Provider Connectivity Status */}
            <div className="p-4 rounded-xl border border-white/10 bg-[#030303]/80 space-y-2">
              <span className="text-[10px] text-white/40 uppercase block">
                CONNECTOR HEALTH
              </span>
              <div className="space-y-1.5 text-[11px] text-white/60">
                <div className="flex justify-between">
                  <span>TAVILY SEARCH API:</span>
                  <span className="text-[#00ff66] font-bold">OPERATIONAL</span>
                </div>
                <div className="flex justify-between">
                  <span>SWYTCHCODE CONNECTOR:</span>
                  <span className="text-[#00ff66] font-bold">OPERATIONAL (MOCK/LIVE)</span>
                </div>
                <div className="flex justify-between">
                  <span>MITRE ATT&CK MATRIX:</span>
                  <span className="text-[#00f0ff] font-bold">v14.1 MAPPED</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
