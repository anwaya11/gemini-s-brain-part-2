"use client";

import { useState, useEffect, useRef } from "react";

export interface LogEntry {
  id: string;
  ip: string;
  endpoint: string;
  score: number;
  action: "DROPPED" | "ESCALATED" | "APPROVAL_REQ" | "AUTO_CONTAINED" | "DECEPTION_ACTIVE" | "ANALYZING" | string;
  timestamp: string;
}

export interface AgentChatMessage {
  id: string;
  agent: string;
  reasoning: string;
  step?: string;
  timestamp: string;
  tagColor: string;
}

export interface GraphNode {
  id: string;
  label: string;
  color: string;
  val?: number;
}

export interface GraphLink {
  source: string;
  target: string;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export interface IntelRecord {
  id: string;
  ioc: string;
  type: "IPv4" | "CVE" | "Domain" | "Hash";
  confidence: number;
  tags: string[];
  vt_score: string;
  abuse_score: string;
  summary: string;
  source: string;
  last_seen: string;
  isLive?: boolean;
}

export interface IncidentItem {
  id: string;
  title: string;
  source_ip: string;
  severity: string;
  risk_score: number;
  confidence: number;
  status: "PENDING_APPROVAL" | "CONTAINED" | "REJECTED" | "INTERCEPTED_BY_GUARDRAIL" | string;
  mitre_technique: string;
  cert_in_category?: string;
  decoy_path: string;
  endpoint?: string;
  created_at: string;
}

export interface SOCConfig {
  edge_threshold: number;
  autonomy_cutoff: number;
  containment_webhook: string;
}

export interface PlaybookExecution {
  execution_id: string;
  incident_id: string;
  target_ip: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  step_index: number;
  total_steps: number;
  step: string;
  progress: number;
  timestamp: string;
  logs: string[];
}

export interface SOCStreamState {
  logs: LogEntry[];
  chatter: AgentChatMessage[];
  riskScore: number;
  graphData: GraphData;
  intelList: IntelRecord[];
  incidents: IncidentItem[];
  config: SOCConfig;
  demoMode: boolean;
  activePlaybook?: PlaybookExecution | null;
  totalSaved: number;
  lastIncidentCost: number;
  isConnected: boolean;
}

export const MIN_AVERTED_COST_PER_INCIDENT = 50000; // ₹50,000
export const MAX_AVERTED_COST_PER_INCIDENT = 250000; // ₹2,50,000
export const IBM_INDIA_AVG_BREACH_COST = 255000000; // ₹25.5 Crore (25,50,00,000)

/**
 * Formats a monetary amount into the Indian numbering system:
 * - >= 1 Crore (10,000,000): "₹X.XX Cr"
 * - >= 1 Lakh (100,000): "₹X.X L"
 * - Default: "₹X,XX,XXX"
 */
export function formatIndianCurrency(amount: number): string {
  if (amount >= 10000000) {
    const cr = amount / 10000000;
    return `₹${cr.toFixed(2)} Cr`;
  } else if (amount >= 100000) {
    const lakh = amount / 100000;
    return `₹${lakh.toFixed(1)} L`;
  } else if (amount === 0) {
    return "₹0.00 Cr";
  } else {
    return `₹${amount.toLocaleString("en-IN")}`;
  }
}

/**
 * Calculates a deterministic randomized averted cost between ₹50,000 and ₹2,50,000
 * for each incident / event based on its unique ID.
 */
export function getIncidentAvertedCost(incidentId?: string): number {
  if (!incidentId) {
    return 50000 + Math.floor(Math.random() * 200) * 1000;
  }
  let hash = 0;
  for (let i = 0; i < incidentId.length; i++) {
    hash = (hash << 5) - hash + incidentId.charCodeAt(i);
    hash |= 0;
  }
  const factor = Math.abs(hash % 201) / 200; // 0.0 to 1.0
  const cost =
    MIN_AVERTED_COST_PER_INCIDENT +
    factor * (MAX_AVERTED_COST_PER_INCIDENT - MIN_AVERTED_COST_PER_INCIDENT);
  return Math.round(cost / 1000) * 1000;
}

/**
 * Parses any timestamp string (ISO 8601 UTC, epoch, or date string) and formats
 * it into local time (IST / user's local timezone) as HH:mm:ss.
 */
export function formatLocalTime(ts?: string | number | null): string {
  if (!ts) return new Date().toLocaleTimeString(undefined, { hour12: false });
  try {
    const raw = String(ts).trim();
    if (/^\d{2}:\d{2}:\d{2}$/.test(raw)) {
      return raw;
    }
    const d = new Date(raw);
    if (!isNaN(d.getTime())) {
      return d.toLocaleTimeString(undefined, {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    }
    const parts = raw.split(" ");
    if (parts.length > 1 && parts[1].includes(":")) {
      return parts[1].slice(0, 8);
    }
  } catch {
    // ignore
  }
  return String(ts).slice(0, 8);
}

// Initial baseline topology graph nodes & links
const INITIAL_GRAPH_DATA: GraphData = {
  nodes: [
    { id: "attacker-185.220.101.42", label: "185.220.101.42 (Attacker)", color: "#ff003c", val: 8 },
    { id: "waf", label: "Cloudflare WAF / Perimeter", color: "#00f0ff", val: 6 },
    { id: "gateway", label: "API Gateway Service", color: "#00f0ff", val: 5 },
    { id: "decoy-db", label: "Decoy DB (/decoy/db-admin)", color: "#ffb703", val: 7 },
    { id: "decoy-ssh", label: "Decoy SSH (/decoy/ssh-login)", color: "#ffb703", val: 5 },
    { id: "core_db", label: "Core Postgres DB (ISOLATED)", color: "#00ff66", val: 6 },
  ],
  links: [
    { source: "attacker-185.220.101.42", target: "waf" },
    { source: "waf", target: "gateway" },
    { source: "gateway", target: "decoy-db" },
    { source: "waf", target: "decoy-ssh" },
    { source: "gateway", target: "core_db" },
  ],
};

const INITIAL_INTEL: IntelRecord[] = [
  {
    id: "ioc-1",
    ioc: "185.220.101.42",
    type: "IPv4",
    confidence: 0.94,
    tags: ["tor-exit-node", "scanner", "c2-server", "virustotal-flagged"],
    vt_score: "48/72 Engines Flagged",
    abuse_score: "98% Abuse Confidence",
    summary:
      "Active Tor exit node observed conducting automated vulnerability scanning against public authentication gateways and API admin endpoints.",
    source: "Swytchcode VirusTotal + AbuseIPDB Feed",
    last_seen: "12 mins ago",
    isLive: true,
  },
  {
    id: "ioc-2",
    ioc: "CVE-2024-3400",
    type: "CVE",
    confidence: 0.98,
    tags: ["critical", "rce", "active-exploitation", "zero-day"],
    vt_score: "Known Exploit Payload",
    abuse_score: "High Severity Threat",
    summary:
      "Palo Alto Networks PAN-OS Command Injection Vulnerability allowing unauthenticated attackers to execute arbitrary code with root privileges.",
    source: "NVD + Tavily Live Threat QnA",
    last_seen: "10 mins ago",
    isLive: false,
  },
  {
    id: "ioc-3",
    ioc: "45.154.255.89",
    type: "IPv4",
    confidence: 0.88,
    tags: ["botnet", "credential-stuffing", "abuseipdb-reported"],
    vt_score: "32/72 Engines Flagged",
    abuse_score: "85% Abuse Confidence",
    summary:
      "Host associated with distributed brute-force attacks against SSH services and WordPress XML-RPC endpoints across multiple European datacenters.",
    source: "Swytchcode AbuseIPDB Connector",
    last_seen: "25 mins ago",
    isLive: false,
  },
];

const INITIAL_INCIDENTS: IncidentItem[] = [];
const INITIAL_LOGS: LogEntry[] = [];
const INITIAL_CHATTER: AgentChatMessage[] = [];

function getAgentColor(agent: string): string {
  const normalized = agent.toUpperCase().replace("AGENT", "").trim();
  switch (normalized) {
    case "TRIAGE":
      return "#00f0ff";
    case "INTEL":
    case "TAVILY":
    case "THREATINTEL":
      return "#00f0ff";
    case "ACTION":
    case "SWYTCHCODE":
    case "CONTAINMENT":
      return "#ff3344";
    case "RISK":
    case "RISKENGINE":
      return "#ffb703";
    case "DECEPTION":
      return "#00ff66";
    case "REPORTING":
      return "#a855f7";
    case "ORCHESTRATOR":
    case "LYZR":
    case "LYZR_CORE":
    case "LYZRCORE":
      return "#38bdf8";
    default:
      return "#00f0ff";
  }
}

// Global shared singleton state
type Listener = (state: SOCStreamState) => void;

let globalState: SOCStreamState = {
  logs: INITIAL_LOGS,
  chatter: INITIAL_CHATTER,
  riskScore: 0.35,
  graphData: INITIAL_GRAPH_DATA,
  intelList: INITIAL_INTEL,
  incidents: INITIAL_INCIDENTS,
  config: {
    edge_threshold: 0.80,
    autonomy_cutoff: 0.40,
    containment_webhook: "http://localhost:5678/webhook/chimera",
  },
  demoMode: true,
  activePlaybook: null,
  totalSaved: 0,
  lastIncidentCost: 150000,
  isConnected: false,
};

const listeners = new Set<Listener>();
let globalSocket: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let decayInterval: ReturnType<typeof setInterval> | null = null;
let isConnecting = false;

function notifyListeners() {
  listeners.forEach((listener) => listener(globalState));
}

// Smooth Risk Decay towards baseline 0.15 during idle intervals
function startRiskDecay() {
  if (decayInterval) return;
  decayInterval = setInterval(() => {
    if (globalState.riskScore > 0.15) {
      const decayed = Math.max(0.15, globalState.riskScore - 0.008);
      globalState = { ...globalState, riskScore: Number(decayed.toFixed(4)) };
      notifyListeners();
    }
  }, 1200);
}

function handleIncomingMessage(rawMessage: string) {
  try {
    const parsed = JSON.parse(rawMessage);
    const messageType = parsed.type || parsed.event;
    const payload = parsed.data || parsed.payload || parsed;

    // ── 1. Live Telemetry Event / Log Stream ──────────────────────────
    if (
      messageType === "log" ||
      messageType === "event_stream" ||
      messageType === "event"
    ) {
      const rawLog = payload.raw_log || {};
      const score =
        typeof payload.risk_score === "number"
          ? payload.risk_score
          : typeof payload.anomaly_score === "number"
          ? payload.anomaly_score
          : typeof payload.score === "number"
          ? payload.score
          : 0.0;
      const endpoint = payload.endpoint || rawLog.endpoint || rawLog.path || "/";
      const ip =
        payload.source_ip ||
        payload.source ||
        rawLog.source_ip ||
        payload.ip ||
        "127.0.0.1";

      const action = payload.action || payload.tag || (score >= 0.40 ? "APPROVAL_REQ" : "DROPPED");
      const rawTs = payload.timestamp || payload.created_at || new Date().toISOString();

      const newLog: LogEntry = {
        id: payload.id || payload.log_id || `evt-${Date.now().toString().slice(-4)}`,
        ip,
        endpoint,
        score,
        action,
        timestamp: rawTs,
      };

      // Functional state update: prepend new log without overwriting existing historical records
      const existingLogs = globalState.logs;
      const filteredLogs = existingLogs.filter((l) => l.id !== newLog.id);
      const updatedLogs = [newLog, ...filteredLogs].slice(0, 100);

      // ── DYNAMIC TOPOLOGY: Organically grow graph nodes & links (MAX_NODES = 30) ────
      const isDecoy = endpoint.includes("/decoy");
      const targetNodeId = endpoint.includes("/decoy/db")
        ? "decoy-db"
        : endpoint.includes("/decoy/ssh")
        ? "decoy-ssh"
        : isDecoy
        ? "decoy-db"
        : endpoint.includes("/metrics") || endpoint.includes("/products")
        ? "gateway"
        : "waf";

      const attackerNodeId = `attacker-${ip}`;
      const existingNodes = globalState.graphData.nodes.filter(
        (n) => n.id !== attackerNodeId
      );
      const newAttackerNode: GraphNode = {
        id: attackerNodeId,
        label: `${ip} (Attacker)`,
        color: "#ff003c",
        val: 8,
      };

      const targetNodes = existingNodes.filter((n) => !n.id.startsWith("attacker-"));
      const attackerNodes = existingNodes.filter((n) => n.id.startsWith("attacker-"));
      const maxAttackers = Math.max(1, 30 - targetNodes.length);
      const rollingAttackers = [...attackerNodes, newAttackerNode].slice(-maxAttackers);
      const currentNodes = [...targetNodes, ...rollingAttackers];
      const activeIds = new Set(currentNodes.map((n) => n.id));

      const newLink = { source: attackerNodeId, target: targetNodeId };
      const currentLinks = [
        ...globalState.graphData.links.filter((l) => {
          const s = typeof l.source === "object" ? (l.source as any).id : l.source;
          const t = typeof l.target === "object" ? (l.target as any).id : l.target;
          return activeIds.has(s) && activeIds.has(t) && !(s === attackerNodeId && t === targetNodeId);
        }),
        newLink,
      ];

      // ── LIVE STATE SYNC: Immediately increment averted breach exposure ──
      const incidentCost = getIncidentAvertedCost(newLog.id || ip);
      const isAverted =
        action === "AUTO_CONTAINED" ||
        action === "APPROVAL_REQ" ||
        action === "DECEPTION_ACTIVE" ||
        score >= 0.25;

      const newTotalSaved = isAverted
        ? globalState.totalSaved + incidentCost
        : globalState.totalSaved;

      globalState = {
        ...globalState,
        logs: updatedLogs,
        graphData: {
          nodes: currentNodes,
          links: currentLinks,
        },
        totalSaved: newTotalSaved,
        lastIncidentCost: isAverted ? incidentCost : globalState.lastIncidentCost,
      };
      notifyListeners();
    }

    // ── 2. Agent Reasoning Chatter ────────────────────────────────────
    else if (
      messageType === "chatter" ||
      messageType === "agent_chatter" ||
      messageType === "reasoning"
    ) {
      const agent = payload.agent || payload.agent_name || "AGENT";
      const reasoning = payload.reasoning || payload.message || JSON.stringify(payload);
      const step = payload.step || "";
      const rawTs = payload.timestamp || new Date().toISOString();

      const newChat: AgentChatMessage = {
        id: payload.id || `chat-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
        agent: agent.toUpperCase().replace("AGENT", ""),
        reasoning,
        step,
        timestamp: rawTs,
        tagColor: payload.tagColor || getAgentColor(agent),
      };

      const existingChatter = globalState.chatter;
      const updatedChatter = [newChat, ...existingChatter.filter((c) => c.id !== newChat.id)].slice(0, 60);

      globalState = {
        ...globalState,
        chatter: updatedChatter,
      };
      notifyListeners();
    }

    // ── 3. Dynamic Risk Dial Update ───────────────────────────────────
    else if (
      messageType === "risk" ||
      messageType === "incident_stream"
    ) {
      const newScore =
        typeof payload.risk_score === "number"
          ? payload.risk_score
          : typeof payload.score === "number"
          ? payload.score
          : globalState.riskScore;

      globalState = {
        ...globalState,
        riskScore: newScore,
      };
      notifyListeners();
    }

    // ── 4. Graph Topology Update (Merged safely) ──────────────────────
    else if (messageType === "graph" || messageType === "topology") {
      const incomingNodes = payload.nodes || (payload.data && payload.data.nodes) || [];
      const incomingLinks = payload.links || (payload.data && payload.data.links) || [];
      if (incomingNodes.length > 0) {
        const nodeMap = new Map(globalState.graphData.nodes.map((n) => [n.id, n]));
        incomingNodes.forEach((n: GraphNode) => nodeMap.set(n.id, n));

        const allNodes = Array.from(nodeMap.values());
        const targetNodes = allNodes.filter((n) => !n.id.startsWith("attacker-"));
        const attackerNodes = allNodes.filter((n) => n.id.startsWith("attacker-"));
        const maxAttackers = Math.max(1, 30 - targetNodes.length);
        const finalNodes = [...targetNodes, ...attackerNodes.slice(-maxAttackers)];
        const finalNodeIds = new Set(finalNodes.map((n) => n.id));

        const linkKey = (l: GraphLink) => {
          const s = typeof l.source === "object" ? (l.source as any).id : l.source;
          const t = typeof l.target === "object" ? (l.target as any).id : l.target;
          return `${s}->${t}`;
        };

        const linkMap = new Map(globalState.graphData.links.map((l) => [linkKey(l), l]));
        incomingLinks.forEach((l: GraphLink) => linkMap.set(linkKey(l), l));

        const finalLinks = Array.from(linkMap.values()).filter((l) => {
          const s = typeof l.source === "object" ? (l.source as any).id : l.source;
          const t = typeof l.target === "object" ? (l.target as any).id : l.target;
          return finalNodeIds.has(s) && finalNodeIds.has(t);
        });

        globalState = {
          ...globalState,
          graphData: {
            nodes: finalNodes,
            links: finalLinks,
          },
        };
        notifyListeners();
      }
    }

    // ── 5. Threat Intelligence Stream ─────────────────────────────────
    else if (messageType === "intel") {
      const iocRecord: IntelRecord = {
        id: payload.id || `intel-${Date.now()}`,
        ioc: payload.ioc || "Unknown",
        type: payload.type || "IPv4",
        confidence: typeof payload.confidence === "number" ? payload.confidence : 0.92,
        tags: payload.tags || ["live-stream", "tavily-enriched"],
        vt_score: payload.vt_score || "Scanned",
        abuse_score: payload.abuse_score || "Flagged",
        summary: payload.summary || "Observed threat vector.",
        source: payload.source || "ThreatIntelAgent",
        last_seen: payload.last_seen || "Just now",
        isLive: true,
      };

      const existingIndex = globalState.intelList.findIndex((i) => i.ioc === iocRecord.ioc);
      let updatedIntel: IntelRecord[];
      if (existingIndex >= 0) {
        updatedIntel = [...globalState.intelList];
        updatedIntel[existingIndex] = iocRecord;
      } else {
        updatedIntel = [iocRecord, ...globalState.intelList.slice(0, 24)];
      }

      globalState = {
        ...globalState,
        intelList: updatedIntel,
      };
      notifyListeners();
    }

    // ── 6. Live Incidents List Broadcast (Merged safely) ───────────────
    else if (messageType === "incidents" || messageType === "incident_update") {
      const incoming: IncidentItem[] = Array.isArray(payload)
        ? payload
        : Array.isArray(payload.data)
        ? payload.data
        : [];

      if (incoming.length > 0) {
        const existingMap = new Map(globalState.incidents.map((i) => [i.id, i]));
        let additionalSaved = 0;

        incoming.forEach((inc) => {
          if (!existingMap.has(inc.id)) {
            const incCost = getIncidentAvertedCost(inc.id);
            additionalSaved += incCost;
          }
          existingMap.set(inc.id, inc);
        });

        const mergedIncidents = Array.from(existingMap.values()).sort(
          (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
        );

        globalState = {
          ...globalState,
          incidents: mergedIncidents,
          totalSaved: globalState.totalSaved + additionalSaved,
        };
        notifyListeners();
      }
    }

    // ── 7. Runtime Configuration Broadcast ────────────────────────────
    else if (messageType === "config") {
      const cfg = payload.data || payload;
      globalState = {
        ...globalState,
        config: {
          edge_threshold: cfg.edge_threshold ?? globalState.config.edge_threshold,
          autonomy_cutoff: cfg.autonomy_cutoff ?? globalState.config.autonomy_cutoff,
          containment_webhook: cfg.containment_webhook ?? globalState.config.containment_webhook,
        },
      };
      notifyListeners();
    }

    // ── 8. Demo Mode Real-time Broadcast ──────────────────────────────
    else if (messageType === "demo_mode") {
      const isDemo = payload.enabled ?? payload.demo_mode ?? true;
      globalState = {
        ...globalState,
        demoMode: Boolean(isDemo),
      };
      notifyListeners();
    }

    // ── 9. Playbook Execution Lifecycle Real-time Broadcast ───────────
    else if (messageType === "playbook") {
      const pb = (payload.data || payload) as PlaybookExecution;
      let newTotalSaved = globalState.totalSaved;
      let lastCost = globalState.lastIncidentCost;

      if (pb.status === "COMPLETED") {
        const pbCost = getIncidentAvertedCost(pb.incident_id || pb.target_ip);
        newTotalSaved += pbCost;
        lastCost = pbCost;
      }

      globalState = {
        ...globalState,
        activePlaybook: pb,
        totalSaved: newTotalSaved,
        lastIncidentCost: lastCost,
      };
      notifyListeners();
    }

    // ── 10. System Snapshot on Connection Handshake ───────────────────
    else if (messageType === "system" && payload) {
      if (payload.config) {
        globalState = { ...globalState, config: { ...globalState.config, ...payload.config } };
      }
      if (Array.isArray(payload.incidents) && payload.incidents.length > 0) {
        const existingMap = new Map(globalState.incidents.map((i) => [i.id, i]));
        payload.incidents.forEach((inc: IncidentItem) => existingMap.set(inc.id, inc));
        globalState = {
          ...globalState,
          incidents: Array.from(existingMap.values()).sort(
            (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
          ),
        };
      }
      if (payload.graph && payload.graph.nodes && payload.graph.links) {
        globalState = { ...globalState, graphData: payload.graph };
      }
      if (payload.demo_mode !== undefined) {
        globalState = { ...globalState, demoMode: Boolean(payload.demo_mode) };
      }
      notifyListeners();
    }
  } catch (err) {
    // Non-JSON ignored
  }
}

function initSocketConnection(url: string) {
  if (typeof window === "undefined") return;
  if (globalSocket && (globalSocket.readyState === WebSocket.OPEN || globalSocket.readyState === WebSocket.CONNECTING)) {
    return;
  }
  if (isConnecting) return;
  isConnecting = true;

  try {
    const ws = new WebSocket(url);
    globalSocket = ws;

    ws.onopen = () => {
      isConnecting = false;
      globalState = { ...globalState, isConnected: true };
      notifyListeners();
      startRiskDecay();
    };

    ws.onmessage = (event) => {
      handleIncomingMessage(event.data);
    };

    ws.onerror = () => {
      isConnecting = false;
      globalState = { ...globalState, isConnected: false };
      notifyListeners();
    };

    ws.onclose = () => {
      isConnecting = false;
      globalSocket = null;
      globalState = { ...globalState, isConnected: false };
      notifyListeners();

      // Auto-reconnect after 2.5s
      if (!reconnectTimer) {
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          initSocketConnection(url);
        }, 2500);
      }
    };
  } catch (e) {
    isConnecting = false;
    globalState = { ...globalState, isConnected: false };
    notifyListeners();
  }
}

export async function hydrateFromBackend() {
  if (typeof window === "undefined") return;
  try {
    const [incRes, graphRes, eventsRes] = await Promise.allSettled([
      fetch("http://localhost:8000/api/incidents"),
      fetch("http://localhost:8000/api/graph"),
      fetch("http://localhost:8000/api/events"),
    ]);

    let updated = false;
    let baselineTotal = 0;

    // 1. Hydrate Incidents & LIVE_LOG_STREAM
    if (incRes.status === "fulfilled" && incRes.value.ok) {
      const incData = await incRes.value.json();
      if (Array.isArray(incData.incidents) && incData.incidents.length > 0) {
        const existingIncMap = new Map(globalState.incidents.map((i) => [i.id, i]));
        incData.incidents.forEach((inc: IncidentItem) => {
          existingIncMap.set(inc.id, inc);
          if (inc.status === "CONTAINED" || inc.risk_score >= 0.25) {
            baselineTotal += getIncidentAvertedCost(inc.id);
          }
        });

        const mergedIncidents = Array.from(existingIncMap.values()).sort(
          (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
        );

        // Map incidents to historical logs for LIVE_LOG_STREAM
        const historicalLogs: LogEntry[] = incData.incidents.slice(0, 50).map((inc: any) => ({
          id: inc.id || `evt-${Math.random().toString(36).substring(2, 8)}`,
          ip: inc.source_ip || "127.0.0.1",
          endpoint: inc.endpoint || (inc.decoy_path ? inc.decoy_path : "/api/v1/auth/login"),
          score: typeof inc.risk_score === "number" ? inc.risk_score : 0.85,
          action:
            inc.status === "CONTAINED"
              ? "AUTO_CONTAINED"
              : inc.status === "INTERCEPTED_BY_GUARDRAIL"
              ? "ESCALATED"
              : inc.risk_score >= 0.80
              ? "APPROVAL_REQ"
              : "ESCALATED",
          timestamp: inc.created_at || new Date().toISOString(),
        }));

        const existingLogsMap = new Map(globalState.logs.map((l) => [l.id, l]));
        historicalLogs.forEach((l) => {
          if (!existingLogsMap.has(l.id)) {
            existingLogsMap.set(l.id, l);
          }
        });
        const mergedLogs = Array.from(existingLogsMap.values()).slice(0, 100);

        // Populate graph nodes with incident attacker IPs (MAX_NODES = 30)
        const targetNodes = globalState.graphData.nodes.filter((n) => !n.id.startsWith("attacker-"));
        const attackerMap = new Map<string, { node: GraphNode; target: string }>();

        globalState.graphData.nodes.forEach((n) => {
          if (n.id.startsWith("attacker-")) {
            const existingLink = globalState.graphData.links.find((l) => {
              const s = typeof l.source === "object" ? (l.source as any).id : l.source;
              return s === n.id;
            });
            const t = existingLink ? (typeof existingLink.target === "object" ? (existingLink.target as any).id : existingLink.target) : "waf";
            attackerMap.set(n.id, { node: n, target: t });
          }
        });

        incData.incidents.forEach((inc: any) => {
          const ip = inc.source_ip;
          if (ip) {
            const attackerId = `attacker-${ip}`;
            const target = inc.decoy_path && inc.decoy_path.includes("decoy") ? "decoy-db" : "waf";
            attackerMap.set(attackerId, {
              node: {
                id: attackerId,
                label: `${ip} (Attacker)`,
                color: "#ff003c",
                val: 8,
              },
              target,
            });
          }
        });

        const maxAttackers = Math.max(1, 30 - targetNodes.length);
        const rollingAttackers = Array.from(attackerMap.values()).slice(-maxAttackers);
        const currentNodes = [...targetNodes, ...rollingAttackers.map((a) => a.node)];
        const activeIds = new Set(currentNodes.map((n) => n.id));

        const currentLinks: GraphLink[] = [
          ...globalState.graphData.links.filter((l) => {
            const s = typeof l.source === "object" ? (l.source as any).id : l.source;
            const t = typeof l.target === "object" ? (l.target as any).id : l.target;
            return activeIds.has(s) && activeIds.has(t);
          }),
        ];

        rollingAttackers.forEach((a) => {
          if (!currentLinks.some((l) => {
            const s = typeof l.source === "object" ? (l.source as any).id : l.source;
            const t = typeof l.target === "object" ? (l.target as any).id : l.target;
            return s === a.node.id && t === a.target;
          })) {
            currentLinks.push({ source: a.node.id, target: a.target });
          }
        });

        globalState = {
          ...globalState,
          incidents: mergedIncidents,
          logs: mergedLogs,
          graphData: { nodes: currentNodes, links: currentLinks },
          totalSaved: Math.max(baselineTotal, globalState.totalSaved),
        };
        updated = true;
      }
    }

    // 2. Hydrate Telemetry Events
    if (eventsRes.status === "fulfilled" && eventsRes.value.ok) {
      const eventsData = await eventsRes.value.json();
      if (Array.isArray(eventsData.events) && eventsData.events.length > 0) {
        const rawEventsLogs: LogEntry[] = eventsData.events.map((evt: any) => {
          const p = evt.payload || {};
          return {
            id: evt.id,
            ip: evt.source || p.source_ip || "127.0.0.1",
            endpoint: p.endpoint || p.path || "/api/v1/auth/login",
            score: typeof p.xgb_score === "number" ? p.xgb_score : 0.75,
            action: p.action ? String(p.action).toUpperCase() : (evt.severity === "CRITICAL" ? "APPROVAL_REQ" : "AUTO_CONTAINED"),
            timestamp: evt.timestamp || evt.created_at || new Date().toISOString(),
          };
        });

        const logsMap = new Map(globalState.logs.map((l) => [l.id, l]));
        rawEventsLogs.forEach((l) => {
          if (!logsMap.has(l.id)) {
            logsMap.set(l.id, l);
          }
        });
        globalState = {
          ...globalState,
          logs: Array.from(logsMap.values()).slice(0, 100),
        };
        updated = true;
      }
    }

    // 3. Hydrate BLAST_RADIUS Topology
    if (graphRes.status === "fulfilled" && graphRes.value.ok) {
      const graphData = await graphRes.value.json();
      if (graphData.nodes && graphData.links) {
        const nodeMap = new Map(globalState.graphData.nodes.map((n) => [n.id, n]));
        graphData.nodes.forEach((n: GraphNode) => nodeMap.set(n.id, n));

        const allNodes = Array.from(nodeMap.values());
        const targetNodes = allNodes.filter((n) => !n.id.startsWith("attacker-"));
        const attackerNodes = allNodes.filter((n) => n.id.startsWith("attacker-"));
        const maxAttackers = Math.max(1, 30 - targetNodes.length);
        const finalNodes = [...targetNodes, ...attackerNodes.slice(-maxAttackers)];
        const finalNodeIds = new Set(finalNodes.map((n) => n.id));

        const linkKey = (l: GraphLink) => {
          const s = typeof l.source === "object" ? (l.source as any).id : l.source;
          const t = typeof l.target === "object" ? (l.target as any).id : l.target;
          return `${s}->${t}`;
        };
        const linkMap = new Map(globalState.graphData.links.map((l) => [linkKey(l), l]));
        graphData.links.forEach((l: GraphLink) => linkMap.set(linkKey(l), l));

        const finalLinks = Array.from(linkMap.values()).filter((l) => {
          const s = typeof l.source === "object" ? (l.source as any).id : l.source;
          const t = typeof l.target === "object" ? (l.target as any).id : l.target;
          return finalNodeIds.has(s) && finalNodeIds.has(t);
        });

        globalState = {
          ...globalState,
          graphData: {
            nodes: finalNodes,
            links: finalLinks,
          },
        };
        updated = true;
      }
    }

    if (updated) {
      notifyListeners();
    }
  } catch (err) {
    // Non-blocking fallback
  }
}

/**
 * useSOCStream — Custom React Hook connecting directly to FastAPI WebSocket
 * Endpoint: ws://localhost:8000/ws/console
 */
export function useSOCStream(url: string = "ws://localhost:8000/ws/console"): SOCStreamState {
  const [state, setState] = useState<SOCStreamState>(globalState);
  const urlRef = useRef(url);
  urlRef.current = url;

  useEffect(() => {
    // Immediately hydrate persistent state from PostgreSQL
    hydrateFromBackend();

    // Start rolling decay
    startRiskDecay();

    // Subscribe to shared state updates
    const listener: Listener = (newState) => {
      setState(newState);
    };
    listeners.add(listener);

    // Initialize connection
    initSocketConnection(urlRef.current);

    return () => {
      listeners.delete(listener);
    };
  }, []);

  return state;
}

export default useSOCStream;
