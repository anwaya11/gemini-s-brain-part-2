"use client";

import React, { useState, useEffect, useRef } from "react";
import { Activity, Radio, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";

interface LogEntry {
  id: string;
  ip: string;
  endpoint: string;
  score: number;
  action: "DROPPED" | "ESCALATED" | "AUTO_CONTAINED" | "DECEPTION_ACTIVE";
  timestamp: string;
}

const SAMPLE_IPS = [
  "185.220.101.42",
  "45.154.255.89",
  "192.168.1.105",
  "103.203.57.18",
  "194.26.29.112",
  "89.248.165.74",
  "172.16.0.24",
  "198.51.100.14",
];

const SAMPLE_ENDPOINTS = [
  "/api/v1/auth/login",
  "/api/admin/config",
  "/metrics",
  "/decoy/db-admin",
  "/health",
  "/api/v2/users/export",
  "/decoy/ssh-login",
  "/api/internal/tokens",
];

export default function IncidentFeed() {
  const [logs, setLogs] = useState<LogEntry[]>([
    {
      id: "evt-1001",
      ip: "185.220.101.42",
      endpoint: "/api/admin/config",
      score: 0.94,
      action: "ESCALATED",
      timestamp: "22:01:12",
    },
    {
      id: "evt-1000",
      ip: "192.168.1.105",
      endpoint: "/metrics",
      score: 0.12,
      action: "DROPPED",
      timestamp: "22:01:10",
    },
    {
      id: "evt-0999",
      ip: "45.154.255.89",
      endpoint: "/api/v1/auth/login",
      score: 0.88,
      action: "AUTO_CONTAINED",
      timestamp: "22:01:08",
    },
    {
      id: "evt-0998",
      ip: "103.203.57.18",
      endpoint: "/decoy/db-admin",
      score: 0.96,
      action: "DECEPTION_ACTIVE",
      timestamp: "22:01:05",
    },
  ]);

  const feedRef = useRef<HTMLDivElement>(null);

  // Push new log every 1.5 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      const randomIp = SAMPLE_IPS[Math.floor(Math.random() * SAMPLE_IPS.length)];
      const randomEndpoint =
        SAMPLE_ENDPOINTS[Math.floor(Math.random() * SAMPLE_ENDPOINTS.length)];
      const randomScore = parseFloat((Math.random() * 0.98).toFixed(2));

      let action: LogEntry["action"] = "DROPPED";
      if (randomEndpoint.startsWith("/decoy")) {
        action = "DECEPTION_ACTIVE";
      } else if (randomScore >= 0.8) {
        action = "ESCALATED";
      } else if (randomScore >= 0.4) {
        action = "AUTO_CONTAINED";
      }

      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];

      const newEntry: LogEntry = {
        id: `evt-${Math.floor(1000 + Math.random() * 9000)}`,
        ip: randomIp,
        endpoint: randomEndpoint,
        score: randomScore,
        action: action,
        timestamp: timeStr,
      };

      setLogs((prev) => [newEntry, ...prev.slice(0, 29)]);
    }, 1500);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="w-full h-full min-h-[300px] flex flex-col bg-white/[0.02] backdrop-blur-md border border-white/5 rounded-xl overflow-hidden hover:border-[#00f0ff]/30 transition-all">
      {/* Panel Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-black/40">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-[#00f0ff]" />
          <h3 className="text-xs font-mono text-gray-300 tracking-widest uppercase">
            LIVE_LOG_STREAM [ingest.py]
          </h3>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono text-white/50">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00ff66] animate-ping" />
          <span className="text-[#00ff66]">INGESTING</span>
        </div>
      </div>

      {/* Terminal Log Stream Table */}
      <div
        ref={feedRef}
        className="flex-1 p-3 space-y-2 overflow-y-auto font-mono text-xs"
      >
        {logs.map((log) => {
          const isEscalated = log.action === "ESCALATED";
          const isDeception = log.action === "DECEPTION_ACTIVE";
          const isAutoContained = log.action === "AUTO_CONTAINED";

          return (
            <div
              key={log.id}
              className={cn(
                "flex items-center justify-between px-3 py-2 rounded border transition-all text-[11px]",
                isEscalated
                  ? "bg-[#ff003c]/10 border-[#ff003c]/30 text-[#ff003c] shadow-[0_0_10px_rgba(255,0,60,0.1)]"
                  : isDeception
                  ? "bg-[#ffb703]/10 border-[#ffb703]/30 text-[#ffb703]"
                  : isAutoContained
                  ? "bg-[#00f0ff]/10 border-[#00f0ff]/20 text-[#00f0ff]"
                  : "bg-white/[0.01] border-white/5 text-[#00ff66]/90"
              )}
            >
              <div className="flex items-center gap-2.5 truncate max-w-[65%]">
                <span className="text-white/40 text-[10px] shrink-0">
                  {log.timestamp}
                </span>
                <span className="font-bold shrink-0">{log.ip}</span>
                <span className="text-white/60 truncate">{log.endpoint}</span>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span className="text-[10px] opacity-75">
                  XGB: {log.score.toFixed(2)}
                </span>
                <span
                  className={cn(
                    "px-1.5 py-0.5 text-[9px] font-bold rounded uppercase",
                    isEscalated
                      ? "bg-[#ff003c]/20 text-[#ff003c]"
                      : isDeception
                      ? "bg-[#ffb703]/20 text-[#ffb703]"
                      : isAutoContained
                      ? "bg-[#00f0ff]/20 text-[#00f0ff]"
                      : "bg-[#00ff66]/10 text-[#00ff66]"
                  )}
                >
                  {log.action}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
