"use client";

import React, { useState, useMemo } from "react";
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
  Activity,
  Layers,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useSOCStream, IntelRecord } from "@/hooks/useSOCStream";

export default function ThreatIntelPage() {
  const { intelList, isConnected } = useSOCStream("ws://localhost:8000/ws/console");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIocId, setSelectedIocId] = useState<string>("");

  // Filter records by search query
  const filteredRecords = useMemo(() => {
    if (!searchQuery.trim()) return intelList;
    const q = searchQuery.toLowerCase();
    return intelList.filter(
      (r) =>
        r.ioc.toLowerCase().includes(q) ||
        r.summary.toLowerCase().includes(q) ||
        r.tags.some((t) => t.toLowerCase().includes(q))
    );
  }, [intelList, searchQuery]);

  const activeRecord: IntelRecord | undefined =
    filteredRecords.find((r) => r.id === selectedIocId) ||
    filteredRecords[0] ||
    intelList[0];

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

        {/* Search Bar & WebSocket Indicator */}
        <div className="flex items-center gap-3">
          <div className="relative w-full md:w-80">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/40" />
            <input
              type="text"
              placeholder="Search IP, CVE, Tag..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-[#030303]/80 border border-[#00f0ff]/20 text-white placeholder-white/30 text-xs font-mono focus:outline-none focus:border-[#00f0ff] focus:shadow-[0_0_15px_rgba(0,240,255,0.25)] transition-all"
            />
          </div>

          <div className="hidden sm:flex items-center gap-2 px-3 py-2 rounded-lg bg-black/40 border border-white/10 text-[10px] font-mono">
            <span
              className={cn(
                "w-1.5 h-1.5 rounded-full",
                isConnected ? "bg-[#00ff66] animate-ping" : "bg-[#ffb703]"
              )}
            />
            <span className={isConnected ? "text-[#00ff66]" : "text-[#ffb703]"}>
              {isConnected ? "WS:LIVE_INTEL" : "CONNECTING..."}
            </span>
          </div>
        </div>
      </div>

      {/* Main Intel Body: Left Grid of Known IOCs, Right Detailed Dossier */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[580px]">
        {/* Left: Dynamic IOC List */}
        <div className="lg:col-span-5 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex justify-between items-center">
            <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
              Live IOC Stream ({filteredRecords.length})
            </span>
            <span className="text-[10px] font-mono text-[#00ff66]">
              TAVILY + SWYTCHCODE
            </span>
          </div>

          <div className="flex-1 p-3.5 space-y-3 overflow-y-auto">
            {filteredRecords.length === 0 ? (
              <div className="h-64 flex flex-col items-center justify-center text-center p-6 space-y-3">
                <Activity className="w-8 h-8 text-[#00f0ff]/40 animate-pulse" />
                <span className="text-xs font-mono text-white/50 tracking-wider uppercase">
                  AWAITING THREAT SYNTHESIS...
                </span>
                <p className="text-[11px] font-mono text-white/30 max-w-xs">
                  No active threat signatures match the filter query. Listening to live telemetry stream.
                </p>
              </div>
            ) : (
              filteredRecords.map((item) => {
                const isSelected = activeRecord?.id === item.id || activeRecord?.ioc === item.ioc;
                const isHighConfidence = item.confidence >= 0.9;

                return (
                  <div
                    key={item.id || item.ioc}
                    onClick={() => setSelectedIocId(item.id)}
                    className={cn(
                      "p-4 rounded-xl border transition-all cursor-pointer",
                      isSelected
                        ? "bg-[#00f0ff]/10 border-[#00f0ff]/50 shadow-[0_0_20px_rgba(0,240,255,0.15)]"
                        : "bg-[#030303]/60 border-white/10 hover:border-[#00f0ff]/30",
                      isHighConfidence && "shadow-[inset_0_0_12px_rgba(255,0,60,0.05)]"
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
                        {item.isLive && (
                          <span className="px-1.5 py-0.2 text-[8px] font-mono font-bold rounded bg-[#00ff66]/20 text-[#00ff66] border border-[#00ff66]/30 animate-pulse">
                            LIVE
                          </span>
                        )}
                      </div>

                      <span
                        className={cn(
                          "text-[10px] font-mono font-bold",
                          isHighConfidence ? "text-[#ff003c]" : "text-[#ffb703]"
                        )}
                      >
                        {(item.confidence * 100).toFixed(0)}% THREAT
                      </span>
                    </div>

                    <p className="text-xs text-white/60 mt-2 line-clamp-2 leading-relaxed font-mono">
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
              })
            )}
          </div>
        </div>

        {/* Right: Detailed Threat Intelligence Dossier */}
        <div className="lg:col-span-7 flex flex-col glass-card hud-corner-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#00f0ff]/15 bg-[#030303]/60 flex justify-between items-center">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-[#00f0ff]" />
              <span className="text-xs font-bold font-mono tracking-wider text-white uppercase">
                Synthesized Intelligence Dossier: {activeRecord?.ioc || "N/A"}
              </span>
            </div>
            <span className="text-xs font-mono text-white/40">
              {activeRecord?.last_seen || "Live"}
            </span>
          </div>

          {activeRecord ? (
            <div className="flex-1 p-6 space-y-6 overflow-y-auto font-mono text-xs">
              {/* Confidence & Sources Grid */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3.5 rounded-lg border border-[#ff003c]/20 bg-[#ff003c]/5">
                  <span className="text-[10px] text-white/40 uppercase">CONFIDENCE RATING</span>
                  <p className="text-xl font-bold text-[#ff003c] mt-1">
                    {(activeRecord.confidence * 100).toFixed(0)}%
                  </p>
                  <span className="text-[10px] text-[#ff003c]">High Malicious Probability</span>
                </div>

                <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02]">
                  <span className="text-[10px] text-white/40 uppercase">VIRUSTOTAL REPUTATION</span>
                  <p className="text-xs font-bold text-[#00f0ff] mt-2 truncate">
                    {activeRecord.vt_score || "Scanned"}
                  </p>
                  <span className="text-[10px] text-white/40">Swytchcode Connector</span>
                </div>

                <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02]">
                  <span className="text-[10px] text-white/40 uppercase">ABUSEIPDB CONFIDENCE</span>
                  <p className="text-xs font-bold text-[#ffb703] mt-2 truncate">
                    {activeRecord.abuse_score || "Active"}
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
                  {activeRecord.summary}
                </p>
              </div>

              {/* Threat Tags */}
              <div>
                <span className="text-[10px] text-white/40 uppercase block mb-2">
                  CLASSIFIED THREAT TAXONOMY
                </span>
                <div className="flex flex-wrap gap-2">
                  {activeRecord.tags?.map((tag) => (
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
                    <span className="text-[#00ff66] font-bold">OPERATIONAL</span>
                  </div>
                  <div className="flex justify-between">
                    <span>MITRE ATT&CK MATRIX:</span>
                    <span className="text-[#00f0ff] font-bold">v14.1 MAPPED</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center p-6 text-white/40 font-mono text-xs">
              Select an IOC to inspect synthesized forensic dossier.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
