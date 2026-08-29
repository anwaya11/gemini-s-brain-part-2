"use client";

import React, { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { Layers } from "lucide-react";
import { useSOCStream } from "@/hooks/useSOCStream";

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

export default function BlastRadiusGraph() {
  const { graphData, isConnected } = useSOCStream("ws://localhost:8000/ws/console");
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({
    width: 400,
    height: 300,
  });
  const [isMounted, setIsMounted] = useState(false);

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
      className="w-full h-full min-h-[300px] bg-white/[0.02] backdrop-blur-md border border-[#00f0ff]/10 rounded-xl overflow-hidden relative flex items-center justify-center cursor-move hover:border-[#00f0ff]/30 transition-all"
    >
      {/* Panel Header Label */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none flex items-center gap-2">
        <Layers className="w-3.5 h-3.5 text-[#00f0ff]" />
        <h3 className="text-xs font-mono text-gray-300 tracking-widest uppercase">
          BLAST_RADIUS [react-force-graph]
        </h3>
      </div>

      {/* Connection Status Badge */}
      <div className="absolute top-4 right-4 z-10 pointer-events-none flex items-center gap-2 text-[10px] font-mono">
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            isConnected ? "bg-[#00ff66] animate-ping" : "bg-[#ffb703]"
          }`}
        />
        <span className={isConnected ? "text-[#00ff66]" : "text-[#ffb703]"}>
          {isConnected ? `LIVE TOPOLOGY (${graphData?.nodes?.length || 0} NODES)` : "CONNECTING..."}
        </span>
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

      {/* ForceGraph2D Cyberpunk Telemetry Canvas */}
      <div className="absolute inset-0">
        <ForceGraph2D
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphData}
          backgroundColor="rgba(0,0,0,0)"
          linkColor={() => "rgba(0, 240, 255, 0.4)"}
          linkWidth={1.5}
          linkDirectionalParticles={4}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleSpeed={0.01}
          linkDirectionalParticleColor={() => "#00f0ff"}
          enableNodeDrag={true}
          enableZoomInteraction={true}
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D) => {
            const { x, y, color = "#00f0ff", label = "" } = node;
            if (typeof x !== "number" || typeof y !== "number") return;

            const isAttacker = color === "#ff003c" || String(node.id).startsWith("attacker");
            const radius = isAttacker ? 6 : 5;

            // 1. Draw glowing outer stroke / halo
            ctx.save();
            ctx.beginPath();
            ctx.arc(x, y, radius + 2.5, 0, 2 * Math.PI, false);
            ctx.strokeStyle = color;
            ctx.lineWidth = isAttacker ? 1.5 : 1.2;
            ctx.shadowColor = color;
            ctx.shadowBlur = isAttacker ? 14 : 8;
            ctx.stroke();
            ctx.restore();

            // 2. Draw solid inner core
            ctx.save();
            ctx.beginPath();
            ctx.arc(x, y, radius, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.restore();

            // 3. Draw node label directly below the node
            if (label) {
              ctx.save();
              ctx.font = "4px Courier";
              ctx.textAlign = "center";
              ctx.textBaseline = "top";
              ctx.fillStyle = isAttacker ? "rgba(255, 100, 100, 0.9)" : "rgba(255, 255, 255, 0.75)";
              ctx.fillText(label, x, y + radius + 3.5);
              ctx.restore();
            }
          }}
          nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
            const { x, y } = node;
            if (typeof x !== "number" || typeof y !== "number") return;
            ctx.beginPath();
            ctx.arc(x, y, 9, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.fill();
          }}
        />
      </div>
    </div>
  );
}
