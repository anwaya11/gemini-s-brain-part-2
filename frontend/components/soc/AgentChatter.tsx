"use client";

import React, { useState, useEffect, useRef } from "react";
import { Cpu, Radio, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

interface AgentMessage {
  id: string;
  agent: "TRIAGE" | "INTEL" | "RISK" | "DECEPTION" | "CONTAINMENT" | "REPORTING";
  reasoning: string;
  timestamp: string;
  tagColor: string;
}

const AGENT_MESSAGES_POOL: Array<{
  agent: AgentMessage["agent"];
  reasoning: string;
  tagColor: string;
}> = [
  {
    agent: "TRIAGE",
    reasoning:
      "High-entropy payload detected on /api/admin/config. MITRE T1190 mapped (Exploit Public-Facing Application).",
    tagColor: "#00f0ff",
  },
  {
    agent: "INTEL",
    reasoning:
      "Querying Tavily for live CVE-2024-3400 context & VirusTotal via Swytchcode. Reputation Score: 0.94.",
    tagColor: "#00f0ff",
  },
  {
    agent: "RISK",
    reasoning:
      "Risk Dial evaluated: Confidence(0.94) × BlastRadius(0.85) × Criticality(0.90) = 0.7191 ➔ ESCALATE (Human Auth Req).",
    tagColor: "#ffb703",
  },
  {
    agent: "DECEPTION",
    reasoning:
      "Attacker 185.220.101.42 rerouted to honeypot /decoy/db-admin. Graph edge inserted into topology.",
    tagColor: "#00ff66",
  },
  {
    agent: "CONTAINMENT",
    reasoning:
      "Autonomous containment playbook executed via n8n webhook (execution_id: mock-7f3a9d). Blocked perimeter IP.",
    tagColor: "#ff003c",
  },
  {
    agent: "REPORTING",
    reasoning:
      "Generating forensic Markdown dossier with MITRE attack chain & recommended remediation steps.",
    tagColor: "#a855f7",
  },
  {
    agent: "INTEL",
    reasoning:
      "Tavily search returned active exploit reports matching Tor Exit Node 45.154.255.89.",
    tagColor: "#00f0ff",
  },
  {
    agent: "TRIAGE",
    reasoning:
      "SQL injection heuristic flagged (anomaly 0.96) on endpoint /decoy/db-admin. Attacker is trapped.",
    tagColor: "#00f0ff",
  },
];

export default function AgentChatter() {
  const [messages, setMessages] = useState<AgentMessage[]>([
    {
      id: "msg-1",
      agent: "TRIAGE",
      reasoning:
        "High-entropy payload detected on /api/admin/config. MITRE T1190 mapped.",
      timestamp: "22:01:10",
      tagColor: "#00f0ff",
    },
    {
      id: "msg-2",
      agent: "INTEL",
      reasoning:
        "Querying Tavily for live threat intelligence & VirusTotal via Swytchcode connector.",
      timestamp: "22:01:12",
      tagColor: "#00f0ff",
    },
    {
      id: "msg-3",
      agent: "RISK",
      reasoning:
        "Blast radius calculated: 0.84 ➔ Risk score 0.6210. Escalating for Human Authorization.",
      timestamp: "22:01:15",
      tagColor: "#ffb703",
    },
    {
      id: "msg-4",
      agent: "DECEPTION",
      reasoning:
        "Attacker rerouted to honeypot /decoy/db-admin. Topology graph edge committed.",
      timestamp: "22:01:17",
      tagColor: "#00ff66",
    },
  ]);

  const chatterRef = useRef<HTMLDivElement>(null);

  // Push new agent message every 2.5 seconds
  useEffect(() => {
    let poolIndex = 0;
    const interval = setInterval(() => {
      const item = AGENT_MESSAGES_POOL[poolIndex % AGENT_MESSAGES_POOL.length];
      poolIndex++;

      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];

      const newMsg: AgentMessage = {
        id: `msg-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        agent: item.agent,
        reasoning: item.reasoning,
        timestamp: timeStr,
        tagColor: item.tagColor,
      };

      setMessages((prev) => [newMsg, ...prev.slice(0, 24)]);
    }, 2500);

    return () => clearInterval(interval);
  }, []);

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
        <div className="flex items-center gap-2 text-[10px] font-mono text-white/50">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00f0ff] animate-pulse" />
          <span className="text-[#00f0ff]">LYZR CREW ACTIVE</span>
        </div>
      </div>

      {/* Message Feed */}
      <div
        ref={chatterRef}
        className="flex-1 p-3.5 space-y-2.5 overflow-y-auto font-mono text-xs"
      >
        {messages.map((msg) => (
          <div
            key={msg.id}
            className="p-3 rounded border border-white/5 bg-black/30 backdrop-blur-sm space-y-1.5 transition-all hover:border-white/15"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span
                  className="px-2 py-0.5 text-[9px] font-bold rounded uppercase border font-mono tracking-wider"
                  style={{
                    color: msg.tagColor,
                    borderColor: `${msg.tagColor}40`,
                    backgroundColor: `${msg.tagColor}15`,
                  }}
                >
                  [{msg.agent}]
                </span>
                <span className="text-[10px] text-white/30">{msg.timestamp}</span>
              </div>
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
