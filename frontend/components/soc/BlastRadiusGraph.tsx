"use client";

import React, { useEffect, useRef, useState, useMemo } from "react";
import dynamic from "next/dynamic";
import { Layers } from "lucide-react";
import { forceCenter, forceX, forceY, forceCollide } from "d3-force-3d";
import { useSOCStream } from "@/hooks/useSOCStream";

// Dynamically import react-force-graph-2d with SSR disabled
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full min-h-[340px] flex items-center justify-center bg-black/40">
      <span className="text-xs font-mono text-[#00f0ff]/70 animate-pulse">
        INITIALIZING_TOPOLOGY_CANVAS...
      </span>
    </div>
  ),
});

interface GraphNode {
  id: string;
  name?: string;
  label?: string;
  color: string;
  val: number;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

interface GraphLink {
  source: string;
  target: string;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

// ── 1. BASE TOPOLOGY (PERMANENT ANCHORS) ───────────────────────────────
const BASE_NODES: GraphNode[] = [
  { id: "CoreDB", name: "Core DB (Protected)", label: "Core DB (Protected)", color: "#00ff88", val: 6 },
  { id: "Gateway", name: "API / Perimeter Gateway", label: "API / Perimeter Gateway", color: "#00d4ff", val: 5 },
  { id: "Honeypot", name: "Decoy Honeypot", label: "Decoy Honeypot", color: "#ffb700", val: 5 },
];

const BASE_LINKS: GraphLink[] = [
  { source: "Gateway", target: "CoreDB" },
  { source: "Gateway", target: "Honeypot" },
];

export default function BlastRadiusGraph() {
  const { incidents, isConnected } = useSOCStream("ws://localhost:8000/ws/console");
  const containerRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<any>(null);

  // Exact dynamic dimensions of parent box
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({
    width: 500,
    height: 350,
  });
  const [hoveredNode, setHoveredNode] = useState<any>(null);
  const [isMounted, setIsMounted] = useState(false);

  // ── 1. DYNAMIC PARENT CONTAINER SIZING (ResizeObserver) ─────────────
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

    window.addEventListener("resize", updateDimensions);

    return () => {
      resizeObserver.disconnect();
      window.removeEventListener("resize", updateDimensions);
    };
  }, []);

  // ── 2. PROGRESSIVE GRAPH BUILD-UP & 15-ATTACK RESTART CYCLE ─────────
  const graphData: GraphData = useMemo(() => {
    const nodes: GraphNode[] = [...BASE_NODES];
    const links: GraphLink[] = [...BASE_LINKS];

    // If incidents is empty (like after a database reset), return ONLY the 3 Base Nodes and 2 links
    if (!incidents || incidents.length === 0) {
      return { nodes, links };
    }

    // 15 max attacks + 3 base nodes = 18 nodes before cycle reset
    const cycleCount = incidents.length % 15;
    const displayIncidents = (cycleCount === 0 && incidents.length > 0)
      ? incidents.slice(-15)
      : incidents.slice(-cycleCount);

    if (displayIncidents.length === 0) {
      return { nodes, links };
    }

    displayIncidents.forEach((incident: any, index: number) => {
      if (!incident) return;
      const incidentId = incident.id || `inc-${incident.source_ip}-${Math.random().toString(36).substring(2, 6)}`;
      const sourceIp = incident.source_ip || incident.ip || "127.0.0.1";
      const endpoint = String(incident.endpoint || incident.decoy_path || "").toLowerCase();

      // Highlight the newest threat (the last item in displayIncidents): val=6 and color=#ff0000
      const isNewest = index === displayIncidents.length - 1;

      // 1. Add Attacker Node using absolute unique incident.id
      nodes.push({
        id: incidentId,
        name: sourceIp,
        label: sourceIp,
        color: isNewest ? "#ff0000" : "#ff3344",
        val: isNewest ? 6 : 3,
      });

      // 2. Link Routing:
      // If incident.endpoint contains 'decoy' or 'admin', link to Honeypot, else Gateway
      let targetId = "Gateway";
      if (endpoint.includes("decoy") || endpoint.includes("admin")) {
        targetId = "Honeypot";
      }

      links.push({
        source: incidentId,
        target: targetId,
      });
    });

    return { nodes, links };
  }, [incidents]);

  // ── 3. TUNED D3 PHYSICS (-180 CHARGE, 70 LINK DISTANCE) ────────────
  useEffect(() => {
    if (fgRef.current) {
      // 1. Charge repulsion: -180 for clean 15-node progressive spread
      const charge = fgRef.current.d3Force("charge");
      if (charge) {
        charge.strength(-180);
        if (typeof charge.distanceMax === "function") {
          charge.distanceMax(500);
        }
      }

      // 2. Center force: keep the cluster balanced in the middle
      const center = fgRef.current.d3Force("center");
      if (center) {
        if (typeof center.x === "function") center.x(0);
        if (typeof center.y === "function") center.y(0);
        if (typeof center.strength === "function") center.strength(1);
      } else {
        fgRef.current.d3Force("center", forceCenter(0, 0));
      }

      // 3. Link distance: 70 for breathing room around Gateway and Honeypot
      const link = fgRef.current.d3Force("link");
      if (link) {
        link.distance(70);
      }

      // 4. Collision force: prevent overlap
      fgRef.current.d3Force("collide", forceCollide(14));

      // Re-heat simulation smoothly
      if (typeof fgRef.current.d3ReheatSimulation === "function") {
        fgRef.current.d3ReheatSimulation();
      }
    }
  }, [graphData, dimensions.width, dimensions.height]);

  // ── 4. Auto Zoom-To-Fit & Centering on Mount / Resize ────────────────
  useEffect(() => {
    const timer = setTimeout(() => {
      if (fgRef.current) {
        if (typeof fgRef.current.centerAt === "function") {
          fgRef.current.centerAt(0, 0, 300);
        }
        if (typeof fgRef.current.zoomToFit === "function") {
          fgRef.current.zoomToFit(400, 35);
        }
      }
    }, 200);

    return () => clearTimeout(timer);
  }, [dimensions.width, dimensions.height]);

  const safeGraphData: GraphData = useMemo(() => {
    const rawNodes = Array.isArray(graphData?.nodes) && graphData.nodes.length > 0
      ? graphData.nodes
      : BASE_NODES;

    const rawLinks = Array.isArray(graphData?.links) && graphData.links.length > 0
      ? graphData.links
      : BASE_LINKS;

    return {
      nodes: rawNodes,
      links: rawLinks,
    };
  }, [graphData]);

  if (!isMounted) {
    return (
      <div
        className="w-full h-full min-h-[340px] bg-white/[0.02] backdrop-blur-md border border-[#00f0ff]/10 rounded-xl overflow-hidden relative flex items-center justify-center"
        style={{ width: "100%", height: "100%", position: "relative", flex: 1, minHeight: "340px" }}
      >
        <span className="text-xs font-mono text-gray-500 animate-pulse">
          MOUNTING_TOPOLOGY_ENGINE...
        </span>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="w-full h-full min-h-[340px] bg-white/[0.02] backdrop-blur-md border border-[#00f0ff]/10 rounded-xl overflow-hidden relative flex flex-col justify-center cursor-move hover:border-[#00f0ff]/30 transition-all"
      style={{ width: "100%", height: "100%", position: "relative", flex: 1, minHeight: "340px" }}
    >
      {/* Panel Header Label */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none flex items-center gap-2">
        <Layers className="w-3.5 h-3.5 text-[#00d4ff]" />
        <h3 className="text-xs font-mono text-gray-300 tracking-widest uppercase">
          BLAST_RADIUS [react-force-graph]
        </h3>
      </div>

      {/* Connection Status Badge */}
      <div className="absolute top-4 right-4 z-10 pointer-events-none flex items-center gap-2 text-[10px] font-mono">
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            isConnected ? "bg-[#00ff88] animate-ping" : "bg-[#ffb700]"
          }`}
        />
        <span className={isConnected ? "text-[#00ff88]" : "text-[#ffb700]"}>
          {isConnected ? `LIVE TOPOLOGY (${safeGraphData.nodes.length} NODES)` : "CONNECTING..."}
        </span>
      </div>

      {/* Topology Legend */}
      <div className="absolute bottom-3 left-4 z-10 pointer-events-none flex items-center gap-3 text-[10px] font-mono">
        <span className="flex items-center gap-1 text-[#ff0000]">
          <span className="w-2 h-2 rounded-full bg-[#ff0000] animate-pulse" /> Attacker IP
        </span>
        <span className="flex items-center gap-1 text-[#00d4ff]">
          <span className="w-2 h-2 rounded-full bg-[#00d4ff]" /> API / Perimeter Gateway
        </span>
        <span className="flex items-center gap-1 text-[#ffb700]">
          <span className="w-2 h-2 rounded-full bg-[#ffb700]" /> Decoy Honeypot
        </span>
        <span className="flex items-center gap-1 text-[#00ff88]">
          <span className="w-2 h-2 rounded-full bg-[#00ff88]" /> Core DB (Protected)
        </span>
      </div>

      {/* ForceGraph2D Full-Box Canvas with D3 Force Spacing */}
      {dimensions.width > 0 && dimensions.height > 0 && (
        <ForceGraph2D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={safeGraphData}
          backgroundColor="rgba(0,0,0,0)"
          d3AlphaDecay={0.04}
          d3VelocityDecay={0.25}
          nodeLabel={() => ""}
          onNodeHover={(node: any) => setHoveredNode(node || null)}
          onEngineStop={() => {
            if (fgRef.current && typeof fgRef.current.zoomToFit === "function") {
              fgRef.current.zoomToFit(400, 35);
            }
          }}
          linkColor={() => "rgba(0, 212, 255, 0.35)"}
          linkWidth={1.5}
          linkDirectionalParticles={3}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleSpeed={0.008}
          linkDirectionalParticleColor={(link: any) => {
            const targetId = typeof link.target === "object" ? link.target.id : link.target;
            return targetId === "Honeypot" ? "#ffcc00" : "#00ffff";
          }}
          enableNodeDrag={true}
          enableZoomInteraction={true}
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D) => {
            if (!node || typeof node.x !== "number" || typeof node.y !== "number") return;
            const x = node.x;
            const y = node.y;
            const isHovered = hoveredNode && hoveredNode.id === node.id;
            const color = node.color || "#00d4ff";
            const isAttacker = color === "#ff0000" || color === "#ff0033" || color === "#ff3344" || color === "#ff003c";
            const isNewestPulsing = color === "#ff0000" || node.val === 6;
            const isHoneypot = node.id === "Honeypot" || color === "#ffb700" || color === "#ffcc00";
            const isCore = node.id === "CoreDB" || color === "#00ff88" || color === "#00ff00";
            const radius = isHovered ? 8.5 : isNewestPulsing ? 6.5 : (node.val ? (isAttacker ? 4.5 : node.val + 1) : 5.5);

            // 1. Glowing outer stroke / halo
            ctx.save();
            ctx.beginPath();
            ctx.arc(x, y, radius + (isHovered ? 3.5 : isNewestPulsing ? 4 : 2.5), 0, 2 * Math.PI, false);
            ctx.strokeStyle = color;
            ctx.lineWidth = isHovered ? 2.5 : isNewestPulsing ? 2.2 : isAttacker ? 1.2 : 1.8;
            ctx.shadowColor = color;
            ctx.shadowBlur = isHovered ? 20 : isNewestPulsing ? 22 : (isAttacker ? 12 : 16);
            ctx.stroke();
            ctx.restore();

            // 2. Solid inner core
            ctx.save();
            ctx.beginPath();
            ctx.arc(x, y, radius, 0, 2 * Math.PI, false);
            ctx.fillStyle = isHovered ? "#ffffff" : color;
            ctx.fill();
            ctx.restore();

            // 3. Persistent Clean Text Label below node circle (4px Sans-Serif)
            const rawLabel = String(node.name || node.label || node.id || "");
            const displayLabel = rawLabel.replace(" (Attacker)", "");

            ctx.save();
            ctx.font = isHovered ? "bold 5px Sans-Serif" : isNewestPulsing ? "bold 4.5px Sans-Serif" : "4px Sans-Serif";
            ctx.textAlign = "center";
            ctx.textBaseline = "top";

            // High contrast text color with dark shadow for sharp readability
            ctx.shadowColor = "rgba(0, 0, 0, 0.9)";
            ctx.shadowBlur = 4;
            ctx.fillStyle = isHovered
              ? "#ffffff"
              : isNewestPulsing
              ? "#ff4d6d"
              : isAttacker
              ? "#ff8090"
              : isHoneypot
              ? "#ffc107"
              : isCore
              ? "#00ff88"
              : "#00d4ff";

            ctx.fillText(displayLabel, x, y + radius + 2.5);
            ctx.restore();

            // 4. Enhanced tooltip badge ONLY on hover
            if (isHovered) {
              const fullLabel = String(node.name || node.label || node.id || "");
              ctx.save();
              ctx.font = "bold 9px Courier, monospace";
              ctx.textAlign = "center";
              ctx.textBaseline = "bottom";

              const textWidth = ctx.measureText(fullLabel).width;
              ctx.fillStyle = "rgba(10, 15, 25, 0.95)";
              ctx.strokeStyle = color;
              ctx.lineWidth = 1;
              ctx.beginPath();
              if (typeof (ctx as any).roundRect === "function") {
                (ctx as any).roundRect(x - textWidth / 2 - 8, y - radius - 20, textWidth + 16, 18, 4);
              } else {
                ctx.rect(x - textWidth / 2 - 8, y - radius - 20, textWidth + 16, 18);
              }
              ctx.fill();
              ctx.stroke();

              ctx.fillStyle = isAttacker ? "#ff0033" : "#00d4ff";
              ctx.fillText(fullLabel, x, y - radius - 6);
              ctx.restore();
            }
          }}
          nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
            if (!node || typeof node.x !== "number" || typeof node.y !== "number") return;
            ctx.beginPath();
            ctx.arc(node.x, node.y, 14, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.fill();
          }}
        />
      )}
    </div>
  );
}
