"use client";

import React, { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { Layers } from "lucide-react";

// Dynamically import react-force-graph-2d with SSR disabled
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center">
      <span className="text-xs font-mono text-cyan-400/50 animate-pulse">
        INITIALIZING_TOPOLOGY_CANVAS...
      </span>
    </div>
  ),
});

interface GraphNode {
  id: string;
  label: string;
  color: string;
  val?: number;
}

interface GraphLink {
  source: string;
  target: string;
}

export default function BlastRadiusGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({
    width: 400,
    height: 300,
  });
  const [isMounted, setIsMounted] = useState(false);

  // Simulated attack graph data
  const [graphData, setGraphData] = useState<{
    nodes: GraphNode[];
    links: GraphLink[];
  }>({
    nodes: [
      { id: "attacker", label: "185.220.101.42 (Attacker)", color: "#ff003c", val: 8 },
      { id: "waf", label: "Cloudflare WAF / Boundary", color: "#00f0ff", val: 6 },
      { id: "gateway", label: "API Gateway Service", color: "#00f0ff", val: 5 },
      { id: "decoy_db", label: "Decoy DB Admin (/decoy/db-admin)", color: "#ffb703", val: 7 },
      { id: "decoy_ssh", label: "Decoy SSH Trap (/decoy/ssh-login)", color: "#ffb703", val: 5 },
      { id: "core_db", label: "Core Postgres DB (ISOLATED)", color: "#00ff66", val: 6 },
    ],
    links: [
      { source: "attacker", target: "waf" },
      { source: "waf", target: "gateway" },
      { source: "gateway", target: "decoy_db" },
      { source: "attacker", target: "decoy_ssh" },
      { source: "gateway", target: "core_db" },
    ],
  });

  useEffect(() => {
    setIsMounted(true);

    const updateDimensions = () => {
      if (containerRef.current) {
        const { clientWidth, clientHeight } = containerRef.current;
        if (clientWidth > 0 && clientHeight > 0) {
          setDimensions({
            width: clientWidth,
            height: clientHeight,
          });
        }
      }
    };

    updateDimensions();

    const resizeObserver = new ResizeObserver(() => {
      updateDimensions();
    });

    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }

    return () => {
      resizeObserver.disconnect();
    };
  }, []);

  if (!isMounted) {
    return (
      <div className="w-full h-full min-h-[300px] bg-white/[0.02] backdrop-blur-md border border-[#00f0ff]/10 rounded-xl overflow-hidden relative flex items-center justify-center">
        <span className="text-xs font-mono text-gray-500 animate-pulse">
          MOUNTING_TOPOLOGY_ENGINE...
        </span>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="w-full h-full min-h-[300px] bg-white/[0.02] backdrop-blur-md border border-[#00f0ff]/10 rounded-xl overflow-hidden relative flex items-center justify-center cursor-move"
    >
      {/* Panel Header Label */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none flex items-center gap-2">
        <Layers className="w-3.5 h-3.5 text-[#00f0ff]" />
        <h3 className="text-xs font-mono text-gray-400 tracking-widest uppercase">
          BLAST_RADIUS [react-force-graph]
        </h3>
      </div>

      {/* Topology Legend */}
      <div className="absolute bottom-3 left-4 z-10 pointer-events-none flex items-center gap-3 text-[10px] font-mono">
        <span className="flex items-center gap-1 text-[#ff003c]">
          <span className="w-2 h-2 rounded-full bg-[#ff003c]" /> Attacker
        </span>
        <span className="flex items-center gap-1 text-[#00f0ff]">
          <span className="w-2 h-2 rounded-full bg-[#00f0ff]" /> WAF/Gateway
        </span>
        <span className="flex items-center gap-1 text-[#ffb703]">
          <span className="w-2 h-2 rounded-full bg-[#ffb703]" /> Decoy Honeypot
        </span>
        <span className="flex items-center gap-1 text-[#00ff66]">
          <span className="w-2 h-2 rounded-full bg-[#00ff66]" /> Protected Core
        </span>
      </div>

      {/* ForceGraph2D Canvas */}
      <div className="absolute inset-0 opacity-85 mix-blend-screen">
        <ForceGraph2D
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphData}
          nodeLabel="label"
          nodeColor="color"
          nodeRelSize={4}
          linkColor={() => "rgba(0, 240, 255, 0.4)"}
          linkWidth={1.5}
          linkDirectionalParticles={2}
          linkDirectionalParticleSpeed={0.006}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleColor={() => "#00f0ff"}
          backgroundColor="transparent"
          enableNodeDrag={true}
          enableZoomInteraction={true}
        />
      </div>
    </div>
  );
}
