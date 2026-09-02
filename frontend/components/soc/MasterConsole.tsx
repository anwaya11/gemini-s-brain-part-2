"use client";

import React, { useEffect } from "react";
import IncidentFeed from "@/components/soc/IncidentFeed";
import AgentChatter from "@/components/soc/AgentChatter";
import BlastRadiusGraph from "@/components/soc/BlastRadiusGraph";
import RiskDial from "@/components/soc/RiskDial";
import BreachCostAvoidedCard from "@/components/soc/BreachCostAvoidedCard";
import { Activity } from "lucide-react";
import { hydrateFromBackend } from "@/hooks/useSOCStream";

export function MasterConsole() {
  // Fetch historical incidents & telemetry logs on mount to hydrate LIVE_LOG_STREAM & BLAST_RADIUS before WebSocket takes over
  useEffect(() => {
    async function fetchHistoricalData() {
      try {
        await hydrateFromBackend();
      } catch (err) {
        console.warn("[MasterConsole] Historical data hydration note:", err);
      }
    }
    fetchHistoricalData();
  }, []);
  return (
    <div className="w-full h-full flex flex-col gap-6">
      {/* HUD Header */}
      <div className="w-full flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#00f0ff]/20 pb-4">
        <div className="flex items-center gap-3">
          <Activity className="text-[#00f0ff] w-6 h-6 animate-pulse" />
          <h2 className="text-xl font-mono text-white tracking-widest uppercase">
            MASTER CONSOLE
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff66] opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-[#00ff66]"></span>
          </span>
          <span className="text-xs font-mono text-[#00ff66] tracking-widest uppercase font-bold">
            WS://LIVE_TELEMETRY
          </span>
        </div>
      </div>

      {/* 4-Quadrant Tactical Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 min-h-[640px]">
        {/* Q1: Ingestion Feed (Live Log Stream) */}
        <IncidentFeed />

        {/* Q2: Multi-Agent Chatter (LLM Reasoning Stream) */}
        <AgentChatter />

        {/* Q3: Blast Radius Graph (Topology Visualizer) */}
        <BlastRadiusGraph />

        {/* Q4: Autonomy Risk Dial (Risk Engine) + Breach Exposure Avoided Live Metric Card */}
        <div className="flex flex-col gap-4 h-full">
          <BreachCostAvoidedCard />
          <div className="flex-1 min-h-[280px]">
            <RiskDial initialRisk={0.35} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default MasterConsole;
