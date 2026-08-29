"use client";

import React, { useRef } from "react";
import { Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSOCStream } from "@/hooks/useSOCStream";

export default function IncidentFeed() {
  const { logs, isConnected } = useSOCStream("ws://localhost:8000/ws/console");
  const feedRef = useRef<HTMLDivElement>(null);

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
        <div className="flex items-center gap-2 text-[10px] font-mono">
          <span
            className={cn(
              "w-1.5 h-1.5 rounded-full",
              isConnected ? "bg-[#00ff66] animate-ping" : "bg-[#ffb703]"
            )}
          />
          <span className={isConnected ? "text-[#00ff66]" : "text-[#ffb703]"}>
            {isConnected ? "WS:STREAMING" : "CONNECTING..."}
          </span>
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
