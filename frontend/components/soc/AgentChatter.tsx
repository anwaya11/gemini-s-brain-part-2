"use client";

import React, { useRef } from "react";
import { Cpu } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSOCStream } from "@/hooks/useSOCStream";

export default function AgentChatter() {
  const { chatter, isConnected } = useSOCStream("ws://localhost:8000/ws/console");
  const chatterRef = useRef<HTMLDivElement>(null);

  return (
    <div className="w-full h-full min-h-[300px] flex flex-col bg-white/[0.02] backdrop-blur-md border border-white/5 rounded-xl overflow-hidden hover:border-[#00f0ff]/30 transition-all">
      {/* Panel Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-black/40">
        <div className="flex items-center gap-2">
          <Cpu className="w-3.5 h-3.5 text-[#00f0ff]" />
          <h3 className="text-xs font-mono text-gray-300 tracking-widest uppercase">
            AGENT_REASONING_CHATTER [orchestrator.py]
          </h3>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono">
          <span
            className={cn(
              "w-1.5 h-1.5 rounded-full",
              isConnected ? "bg-[#00f0ff] animate-pulse" : "bg-[#ffb703]"
            )}
          />
          <span className={isConnected ? "text-[#00f0ff]" : "text-[#ffb703]"}>
            {isConnected ? "LYZR CREW ACTIVE" : "CONNECTING..."}
          </span>
        </div>
      </div>

      {/* Message Feed */}
      <div
        ref={chatterRef}
        className="flex-1 p-3.5 space-y-2.5 overflow-y-auto font-mono text-xs"
      >
        {chatter.map((msg) => (
          <div
            key={msg.id}
            className="p-3 rounded border border-white/5 bg-black/30 backdrop-blur-sm space-y-1.5 transition-all hover:border-white/15"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span
                  className="px-2 py-0.5 text-[9px] font-bold rounded uppercase border font-mono tracking-wider"
                  style={{
                    color: msg.tagColor || "#00f0ff",
                    borderColor: `${msg.tagColor || "#00f0ff"}40`,
                    backgroundColor: `${msg.tagColor || "#00f0ff"}15`,
                  }}
                >
                  [{msg.agent}]
                </span>
                {msg.step && (
                  <span className="text-[10px] text-white/40">
                    [{msg.step}]
                  </span>
                )}
              </div>
              <span className="text-[10px] text-white/30">{msg.timestamp}</span>
            </div>

            <p className="text-white/80 text-[11px] leading-relaxed pl-1">
              {msg.reasoning}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
