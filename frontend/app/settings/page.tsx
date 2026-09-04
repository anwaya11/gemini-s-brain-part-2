"use client";

import React, { useState, useEffect } from "react";
import {
  Settings,
  Server,
  Key,
  Sliders,
  ShieldCheck,
  Save,
  CheckCircle2,
  Database,
  Radio,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const [escalationThreshold, setEscalationThreshold] = useState("0.80");
  const [autonomyThreshold, setAutonomyThreshold] = useState("0.40");
  const [n8nWebhookUrl, setN8nWebhookUrl] = useState(
    "http://localhost:5678/webhook/chimera"
  );
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">("idle");

  // Fetch live configuration on mount
  useEffect(() => {
    let isMounted = true;
    async function loadConfig() {
      try {
        const res = await fetch("https://chimera-backend-5jwu.onrender.com/api/config");
        if (res.ok) {
          const data = await res.json();
          if (isMounted) {
            if (data.autonomyThreshold !== undefined) {
              setAutonomyThreshold(String(data.autonomyThreshold));
            } else if (data.autonomy_threshold !== undefined) {
              setAutonomyThreshold(String(data.autonomy_threshold));
            }

            if (data.escalationThreshold !== undefined) {
              setEscalationThreshold(String(data.escalationThreshold));
            } else if (data.escalation_threshold !== undefined) {
              setEscalationThreshold(String(data.escalation_threshold));
            }

            if (data.n8nWebhookUrl) {
              setN8nWebhookUrl(data.n8nWebhookUrl);
            } else if (data.n8n_webhook_url) {
              setN8nWebhookUrl(data.n8n_webhook_url);
            }
          }
        }
      } catch (err) {
        console.warn("[Settings] Config fetch offline fallback:", err);
      }
    }

    loadConfig();
    return () => {
      isMounted = false;
    };
  }, []);

  // Save configuration via API
  const handleSave = async () => {
    if (saveStatus === "saving") return;
    setSaveStatus("saving");

    try {
      await fetch("https://chimera-backend-5jwu.onrender.com/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          autonomyThreshold: parseFloat(autonomyThreshold) || 0.40,
          escalationThreshold: parseFloat(escalationThreshold) || 0.80,
          n8nWebhookUrl: n8nWebhookUrl,
        }),
      });
    } catch (err) {
      console.warn("[Settings] Save fallback:", err);
    } finally {
      setSaveStatus("saved");
      setTimeout(() => {
        setSaveStatus("idle");
      }, 2500);
    }
  };

  return (
    <div className="flex flex-col h-full space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between p-6 rounded-xl glass-card hud-corner-border">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#00f0ff]/10 border border-[#00f0ff]/30 text-[#00f0ff]">
            <Settings className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-wider text-white uppercase font-mono">
              SOC System & Agent Threshold Configuration
            </h1>
            <p className="text-xs text-white/50 font-mono">
              Configure Edge Filter ML thresholds, LLM agent providers, and n8n containment webhooks
            </p>
          </div>
        </div>

        <button
          onClick={handleSave}
          disabled={saveStatus === "saving"}
          className={cn(
            "flex items-center gap-2 px-5 py-2.5 rounded-lg font-mono text-xs font-bold transition-all",
            saveStatus === "saving"
              ? "bg-[#ffb703]/20 border border-[#ffb703]/50 text-[#ffb703] animate-pulse cursor-wait"
              : saveStatus === "saved"
              ? "bg-[#00ff66]/20 border border-[#00ff66]/60 text-[#00ff66] shadow-[0_0_15px_rgba(0,255,102,0.3)]"
              : "bg-[#00f0ff] text-black hover:bg-[#00f0ff]/80 shadow-[0_0_15px_rgba(0,240,255,0.4)]"
          )}
        >
          {saveStatus === "saving" ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-[#ffb703]" />
              <span>SAVING...</span>
            </>
          ) : saveStatus === "saved" ? (
            <>
              <CheckCircle2 className="w-4 h-4 text-[#00ff66]" />
              <span>CONFIG SAVED</span>
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              <span>APPLY SETTINGS</span>
            </>
          )}
        </button>
      </div>

      {/* Settings Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 font-mono text-xs">
        {/* ML & Edge Filter Configuration */}
        <div className="glass-card hud-corner-border p-6 rounded-xl space-y-4">
          <div className="flex items-center gap-2 text-[#00f0ff] font-bold border-b border-white/10 pb-3">
            <Sliders className="w-4 h-4" />
            <span className="uppercase tracking-wider">XGBoost & Risk Dial Thresholds</span>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-white/70 mb-1.5">
                XGBoost EdgeFilter Escalation Threshold (0.00 – 1.00):
              </label>
              <input
                type="text"
                value={escalationThreshold}
                onChange={(e) => setEscalationThreshold(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#030303]/80 border border-white/15 text-white focus:outline-none focus:border-[#00f0ff]"
              />
              <span className="text-[10px] text-white/40 block mt-1">
                Logs with anomaly score &gt;= this value spawn the multi-agent SOC orchestrator.
              </span>
            </div>

            <div>
              <label className="block text-white/70 mb-1.5">
                Risk Engine Autonomy Cutoff (0.00 – 1.00):
              </label>
              <input
                type="text"
                value={autonomyThreshold}
                onChange={(e) => setAutonomyThreshold(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#030303]/80 border border-white/15 text-white focus:outline-none focus:border-[#00f0ff]"
              />
              <span className="text-[10px] text-white/40 block mt-1">
                Risk scores &lt; threshold auto-contain; scores &gt;= threshold require human authorization.
              </span>
            </div>
          </div>
        </div>

        {/* Integration & Containment Webhooks */}
        <div className="glass-card hud-corner-border p-6 rounded-xl space-y-4">
          <div className="flex items-center gap-2 text-[#00ff66] font-bold border-b border-white/10 pb-3">
            <Server className="w-4 h-4" />
            <span className="uppercase tracking-wider">n8n & External Service Integrations</span>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-white/70 mb-1.5">
                n8n Containment Webhook Endpoint:
              </label>
              <input
                type="text"
                value={n8nWebhookUrl}
                onChange={(e) => setN8nWebhookUrl(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#030303]/80 border border-white/15 text-white focus:outline-none focus:border-[#00ff66]"
              />
              <span className="text-[10px] text-white/40 block mt-1">
                Triggered automatically on auto-contain decisions or manual human approvals.
              </span>
            </div>

            <div className="p-3.5 rounded-lg border border-white/10 bg-white/[0.02] space-y-2">
              <span className="text-white/40 text-[10px] uppercase block">
                ACTIVE MULTI-AGENT CREW CONFIGURATION
              </span>
              <div className="flex justify-between text-white/80">
                <span>LLM Engine:</span>
                <span className="text-[#00f0ff] font-bold">Groq Llama3-8b-8192 / Lyzr</span>
              </div>
              <div className="flex justify-between text-white/80">
                <span>Database Backend:</span>
                <span className="text-[#00ff66] font-bold">PostgreSQL (Asyncpg)</span>
              </div>
              <div className="flex justify-between text-white/80">
                <span>WebSocket Stream:</span>
                <span className="text-[#ffb703] font-bold">FastAPI ConnectionManager</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
