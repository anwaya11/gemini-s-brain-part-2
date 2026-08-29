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
  decoy_path: string;
  created_at: string;
}

export interface SOCConfig {
  edge_threshold: number;
  autonomy_cutoff: number;
  containment_webhook: string;
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
  isConnected: boolean;
}

// Initial baseline nodes & links
const INITIAL_GRAPH_DATA: GraphData = {
  nodes: [
    {"id": "attacker-185.220.101.42", "label": "185.220.101.42 (Attacker)", "color": "#ff003c", "val": 8},
    {"id": "waf", "label": "Cloudflare WAF / Perimeter", "color": "#00f0ff", "val": 6},
    {"id": "gateway", "label": "API Gateway Service", "color": "#00f0ff", "val": 5},
    {"id": "decoy-db", "label": "Decoy DB (/decoy/db-admin)", "color": "#ffb703", "val": 7},
    {"id": "decoy-ssh", "label": "Decoy SSH (/decoy/ssh-login)", "color": "#ffb703", "val": 5},
    {"id": "core_db", "label": "Core Postgres DB (ISOLATED)", "color": "#00ff66", "val": 6},
  ],
  links: [
    {"source": "attacker-185.220.101.42", "target": "waf"},
    {"source": "waf", "target": "gateway"},
    {"source": "gateway", "target": "decoy-db"},
    {"source": "waf", "target": "decoy-ssh"},
    {"source": "gateway", "target": "core_db"},
  ],
};

const INITIAL_INTEL: IntelRecord[] = [
  {
    id: "intel-base-1",
    ioc: "185.220.101.42",
    type: "IPv4",
    confidence: 0.94,
    tags: ["tor-exit-node", "scanner", "c2-server", "virustotal-flagged"],
    vt_score: "48/72 Engines Flagged",
    abuse_score: "98% Abuse Confidence",
    summary:
      "Active Tor Exit node observed conducting automated vulnerability scanning against public authentication gateways and API admin endpoints.",
    source: "Tavily Web Intel + Swytchcode VirusTotal",
    last_seen: "Just now",
    isLive: false,
  },
  {
    id: "intel-base-2",
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
    id: "intel-base-3",
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

const INITIAL_INCIDENTS: IncidentItem[] = [
  {
    id: "INC-2026-0891",
    title: "SQL Injection on Public Endpoint (/api/admin/config)",
    source_ip: "185.220.101.42",
    severity: "CRITICAL",
    risk_score: 0.842,
    confidence: 0.94,
    status: "PENDING_APPROVAL",
    mitre_technique: "T1190 – Exploit Public-Facing Application",
    decoy_path: "/decoy/db-admin",
    created_at: "2026-08-27 02:15:10 IST",
  },
  {
    id: "INC-2026-0890",
    title: "Credential Stuffing / SSH Brute Force Campaign",
    source_ip: "45.154.255.89",
    severity: "HIGH",
    risk_score: 0.385,
    confidence: 0.88,
    status: "CONTAINED",
    mitre_technique: "T1110 – Brute Force Credentials",
    decoy_path: "/decoy/ssh-login",
    created_at: "2026-08-27 02:10:05 IST",
  },
  {
    id: "INC-2026-0889",
    title: "Internal Reconnaissance & Port Probing",
    source_ip: "103.203.57.18",
    severity: "MEDIUM",
    risk_score: 0.320,
    confidence: 0.72,
    status: "CONTAINED",
    mitre_technique: "T1046 – Network Service Discovery",
    decoy_path: "/decoy/health-internal",
    created_at: "2026-08-27 02:05:40 IST",
  },
  {
    id: "INC-2026-0888",
    title: "Unsecured Configuration Exfiltration Attempt",
    source_ip: "194.26.29.112",
    severity: "HIGH",
    risk_score: 0.710,
    confidence: 0.86,
    status: "PENDING_APPROVAL",
    mitre_technique: "T1552 – Unsecured Credentials & Config",
    decoy_path: "/decoy/config",
    created_at: "2026-08-27 01:55:18 IST",
  },
];

const INITIAL_LOGS: LogEntry[] = [
  {
    id: "evt-1001",
    ip: "185.220.101.42",
    endpoint: "/api/admin/config",
    score: 0.94,
    action: "APPROVAL_REQ",
    timestamp: "02:20:12",
  },
  {
    id: "evt-1000",
    ip: "192.168.1.105",
    endpoint: "/metrics",
    score: 0.08,
    action: "DROPPED",
    timestamp: "02:20:10",
  },
  {
    id: "evt-0999",
    ip: "45.154.255.89",
    endpoint: "/api/v1/auth/login",
    score: 0.88,
    action: "AUTO_CONTAINED",
    timestamp: "02:20:08",
  },
  {
    id: "evt-0998",
    ip: "103.203.57.18",
    endpoint: "/decoy/db-admin",
    score: 0.96,
    action: "DECEPTION_ACTIVE",
    timestamp: "02:20:05",
  },
];

const INITIAL_CHATTER: AgentChatMessage[] = [
  {
    id: "msg-1",
    agent: "TRIAGE",
    reasoning:
      "High-entropy payload detected on /api/admin/config. MITRE T1190 mapped (Exploit Public-Facing Application).",
    step: "triage",
    timestamp: "02:20:10",
    tagColor: "#00f0ff",
  },
  {
    id: "msg-2",
    agent: "INTEL",
    reasoning:
      "Querying Tavily for live threat intelligence & VirusTotal via Swytchcode connector. Known malicious IP.",
    step: "threat_intel",
    timestamp: "02:20:12",
    tagColor: "#00f0ff",
  },
  {
    id: "msg-3",
    agent: "RISK",
    reasoning:
      "Blast radius calculated: 0.84 ➔ Risk score 0.6210. Escalating for Human Authorization.",
    step: "risk_evaluation",
    timestamp: "02:20:15",
    tagColor: "#ffb703",
  },
  {
    id: "msg-4",
    agent: "DECEPTION",
    reasoning:
      "Attacker 185.220.101.42 rerouted to honeypot /decoy/db-admin. Topology graph edge committed.",
    step: "deception",
    timestamp: "02:20:17",
    tagColor: "#00ff66",
  },
];

function getAgentColor(agent: string): string {
  const normalized = agent.toUpperCase().replace("AGENT", "").trim();
  switch (normalized) {
    case "TRIAGE":
      return "#00f0ff";
    case "INTEL":
    case "THREATINTEL":
      return "#00f0ff";
    case "RISK":
    case "RISKENGINE":
      return "#ffb703";
    case "DECEPTION":
      return "#00ff66";
    case "CONTAINMENT":
      return "#ff003c";
    case "REPORTING":
      return "#a855f7";
    case "ORCHESTRATOR":
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
      // Decay by 3% each second down towards 0.15
      const decayed = Math.max(0.15, globalState.riskScore - 0.015);
      globalState = { ...globalState, riskScore: parseFloat(decayed.toFixed(3)) };
      notifyListeners();
    }
  }, 1000);
}

function handleIncomingMessage(rawText: string) {
  try {
    const data = JSON.parse(rawText);
    const messageType = data.type || data.channel || "";
    const payload = data.data || data.payload || data;
    const now = new Date();
    const timeStr = now.toTimeString().split(" ")[0];

    // ── 1. Ingest Log Event ───────────────────────────────────────────
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

      const newLog: LogEntry = {
        id: payload.id || payload.log_id || `evt-${Date.now().toString().slice(-4)}`,
        ip,
        endpoint,
        score,
        action,
        timestamp: payload.timestamp ? (payload.timestamp.includes("T") ? payload.timestamp.substring(11, 19) : payload.timestamp) : timeStr,
      };

      // Automatically add IP to graph if not present
      const attackerNodeId = `attacker-${ip}`;
      let updatedGraph = globalState.graphData;
      if (!globalState.graphData.nodes.some((n) => n.id === attackerNodeId)) {
        const nodes = [
          ...globalState.graphData.nodes,
          { id: attackerNodeId, label: `${ip} (Attacker)`, color: "#ff003c", val: 8 },
        ];
        const links = [
          ...globalState.graphData.links,
          { source: attackerNodeId, target: endpoint.startsWith("/decoy") ? "decoy-db" : "waf" },
        ];
        updatedGraph = { nodes, links };
      }

      globalState = {
        ...globalState,
        logs: [newLog, ...globalState.logs.slice(0, 49)],
        graphData: updatedGraph,
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

      const newChat: AgentChatMessage = {
        id: payload.id || `chat-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
        agent: agent.toUpperCase().replace("AGENT", ""),
        reasoning,
        step,
        timestamp: payload.timestamp ? (payload.timestamp.includes("T") ? payload.timestamp.substring(11, 19) : payload.timestamp) : timeStr,
        tagColor: payload.tagColor || getAgentColor(agent),
      };

      globalState = {
        ...globalState,
        chatter: [newChat, ...globalState.chatter.slice(0, 39)],
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

    // ── 4. Graph Topology Update ──────────────────────────────────────
    else if (messageType === "graph" || messageType === "topology") {
      if (payload.nodes && payload.links) {
        globalState = {
          ...globalState,
          graphData: {
            nodes: payload.nodes,
            links: payload.links,
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
        last_seen: payload.last_seen || timeStr,
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

    // ── 6. Live Incidents List Broadcast ──────────────────────────────
    else if (messageType === "incidents" || messageType === "incident_update") {
      if (Array.isArray(payload)) {
        globalState = {
          ...globalState,
          incidents: payload,
        };
        notifyListeners();
      } else if (Array.isArray(payload.data)) {
        globalState = {
          ...globalState,
          incidents: payload.data,
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

    // ── 9. System Snapshot on Connection Handshake ────────────────────
    else if (messageType === "system" && payload) {
      if (payload.config) {
        globalState = { ...globalState, config: { ...globalState.config, ...payload.config } };
      }
      if (Array.isArray(payload.incidents)) {
        globalState = { ...globalState, incidents: payload.incidents };
      }
      if (payload.graph) {
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

/**
 * useSOCStream — Custom React Hook connecting directly to FastAPI WebSocket
 * Endpoint: ws://localhost:8000/ws/console
 */
export function useSOCStream(url: string = "ws://localhost:8000/ws/console"): SOCStreamState {
  const [state, setState] = useState<SOCStreamState>(globalState);
  const urlRef = useRef(url);
  urlRef.current = url;

  useEffect(() => {
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
