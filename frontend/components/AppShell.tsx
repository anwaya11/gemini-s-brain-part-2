"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  Activity,
  Cpu,
  Settings,
  Radio,
  Terminal,
  Zap,
  Clock,
  Wifi,
  Server,
  Layers,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

import { useSOCStream } from "@/hooks/useSOCStream";

interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  {
    name: "Live Console",
    href: "/dashboard",
    icon: Activity,
    badge: "LIVE",
  },
  {
    name: "Incidents & Containment",
    href: "/incidents",
    icon: ShieldAlert,
    badge: "ACTIVE",
  },
  {
    name: "Threat Intelligence",
    href: "/intel",
    icon: Cpu,
  },
  {
    name: "SOC System Configuration",
    href: "/settings",
    icon: Settings,
  },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { demoMode: streamDemoMode } = useSOCStream("ws://localhost:8000/ws/console");
  const [demoMode, setDemoMode] = useState<boolean>(true);
  const [isTogglingDemo, setIsTogglingDemo] = useState<boolean>(false);
  const [utcTime, setUtcTime] = useState<string>("");
  const [istTime, setIstTime] = useState<string>("");
  const [activeDefenders, setActiveDefenders] = useState<number>(4);

  // Synchronize with WebSocket stream demoMode
  useEffect(() => {
    if (typeof streamDemoMode === "boolean") {
      setDemoMode(streamDemoMode);
    }
  }, [streamDemoMode]);

  // Initial fetch from backend API
  useEffect(() => {
    async function checkDemoMode() {
      try {
        const res = await fetch("http://localhost:8000/api/system/demo-mode");
        if (res.ok) {
          const data = await res.json();
          if (typeof data.demo_mode === "boolean") {
            setDemoMode(data.demo_mode);
          }
        }
      } catch (err) {
        // keep fallback
      }
    }
    checkDemoMode();
  }, []);

  const handleToggleDemoMode = async () => {
    const nextState = !demoMode;
    setDemoMode(nextState);
    setIsTogglingDemo(true);
    try {
      await fetch("http://localhost:8000/api/system/demo-mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: nextState }),
      });
    } catch (err) {
      console.warn("[DEMO_MODE] Toggle error:", err);
    } finally {
      setIsTogglingDemo(false);
    }
  };

  // Live HUD clocks
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(
        now.toISOString().replace("T", " ").substring(0, 19) + " UTC"
      );
      setIstTime(
        now.toLocaleTimeString("en-IN", {
          timeZone: "Asia/Kolkata",
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }) + " IST"
      );
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#030303] text-[#f0f4f8] antialiased select-none">
      {/* ── Left Cyberpunk Glassmorphic Sidebar ──────────────────────────── */}
      <aside className="relative flex flex-col w-72 shrink-0 border-r border-[#00f0ff]/15 bg-[#06090e]/80 backdrop-blur-xl z-30 transition-all duration-300">
        {/* Top Brand Logo & Defense Badge */}
        <div className="flex items-center gap-3.5 px-6 py-5 border-b border-[#00f0ff]/15 bg-[#030303]/60">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-[#ff003c]/10 border border-[#ff003c]/40 shadow-[0_0_15px_rgba(255,0,60,0.35)]">
            <ShieldAlert className="w-5 h-5 text-[#ff003c] animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-[#00f0ff] rounded-full animate-ping opacity-75" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-[#00f0ff] rounded-full" />
          </div>

          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="text-lg font-black tracking-widest text-white uppercase font-mono">
                CHIMERA
              </span>
              <span className="px-1.5 py-0.5 text-[10px] font-bold tracking-wider uppercase rounded bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/30 font-mono">
                v2.0
              </span>
            </div>
            <span className="text-[11px] font-medium tracking-wider text-white/40 uppercase">
              Autonomous SOC Matrix
            </span>
          </div>
        </div>

        {/* Navigation Menu Links */}
        <nav className="flex-1 px-3.5 py-6 space-y-2 overflow-y-auto">
          <div className="px-3 mb-2 text-[10px] font-bold tracking-widest uppercase text-white/30 font-mono">
            Navigation Channels
          </div>

          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive =
              pathname === item.href ||
              (item.href !== "/dashboard" && pathname.startsWith(item.href));

            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "group relative flex items-center gap-3 px-3.5 py-3 rounded-lg text-sm font-medium transition-all duration-200",
                  isActive
                    ? "bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 shadow-[0_0_15px_rgba(0,240,255,0.15)]"
                    : "text-white/60 hover:text-white hover:bg-white/[0.03] hover:border-white/10 border border-transparent"
                )}
              >
                {/* Active Indicator Bar */}
                {isActive && (
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-[#00f0ff] rounded-r-full shadow-[0_0_8px_#00f0ff]" />
                )}

                <Icon
                  className={cn(
                    "w-4 h-4 shrink-0 transition-transform duration-200 group-hover:scale-110",
                    isActive
                      ? "text-[#00f0ff] drop-shadow-[0_0_8px_rgba(0,240,255,0.6)]"
                      : "text-white/40 group-hover:text-white"
                  )}
                />

                <span className="flex-1 truncate tracking-wide">
                  {item.name}
                </span>

                {item.badge && (
                  <span
                    className={cn(
                      "px-1.5 py-0.5 text-[9px] font-bold uppercase rounded font-mono border tracking-wider",
                      item.badge === "LIVE"
                        ? "bg-[#00ff66]/10 text-[#00ff66] border-[#00ff66]/30 shadow-[0_0_8px_rgba(0,255,102,0.2)]"
                        : "bg-[#ff003c]/10 text-[#ff003c] border-[#ff003c]/30 shadow-[0_0_8px_rgba(255,0,60,0.2)]"
                    )}
                  >
                    {item.badge}
                  </span>
                )}

                <ChevronRight
                  className={cn(
                    "w-3.5 h-3.5 opacity-0 -translate-x-1 transition-all duration-200 group-hover:opacity-100 group-hover:translate-x-0",
                    isActive ? "opacity-100 translate-x-0 text-[#00f0ff]" : "text-white/30"
                  )}
                />
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Footer — Autonomous Agent Status */}
        <div className="p-4 m-3.5 rounded-xl border border-[#00f0ff]/15 bg-[#030303]/80 backdrop-blur-md">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Radio className="w-3.5 h-3.5 text-[#00ff66] animate-pulse" />
              <span className="text-[11px] font-bold tracking-wider uppercase text-white/80 font-mono">
                CREW STATUS
              </span>
            </div>
            <span className="text-[10px] font-mono text-[#00ff66] font-semibold">
              ONLINE
            </span>
          </div>

          <div className="space-y-1.5 text-[10px] font-mono text-white/50">
            <div className="flex justify-between">
              <span>ACTIVE AGENTS:</span>
              <span className="text-[#00f0ff] font-bold">5 CREW</span>
            </div>
            <div className="flex justify-between">
              <span>CONTAINMENT MODE:</span>
              <span className="text-[#00ff66] font-bold">AUTONOMOUS</span>
            </div>
            <div className="flex justify-between">
              <span>ML INFERENCE LATENCY:</span>
              <span className="text-white/80">3.8 ms</span>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main Layout Body ────────────────────────────────────────────── */}
      <div className="flex flex-col flex-1 h-screen min-w-0 overflow-hidden">
        {/* Top HUD Telemetry Navigation Bar */}
        <header className="relative flex items-center justify-between h-16 px-6 shrink-0 border-b border-[#00f0ff]/15 bg-[#06090e]/70 backdrop-blur-xl z-20">
          {/* Left: Shield Status Banner */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg border border-[#00ff66]/30 bg-[#00ff66]/10 shadow-[0_0_12px_rgba(0,255,102,0.15)]">
              <span className="relative flex w-2 h-2">
                <span className="absolute inline-flex w-full h-full rounded-full opacity-75 animate-ping bg-[#00ff66]" />
                <span className="relative inline-flex w-2 h-2 rounded-full bg-[#00ff66]" />
              </span>
              <span className="text-xs font-bold tracking-widest text-[#00ff66] uppercase font-mono">
                AUTONOMOUS SHIELD: ACTIVE
              </span>
            </div>

            <div className="hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.02]">
              <Cpu className="w-3.5 h-3.5 text-[#00f0ff]" />
              <span className="text-xs font-mono tracking-wider text-white/60">
                ENGINE: <strong className="text-white">XGBOOST + LYZR CREW</strong>
              </span>
            </div>
          </div>

          {/* Center / Right: Interactive Status Pill & Live Telemetry */}
          <div className="flex items-center gap-4 font-mono text-xs">
            {/* Interactive DEMO_MODE / LIVE Pill */}
            <button
              onClick={handleToggleDemoMode}
              disabled={isTogglingDemo}
              title="Click to toggle between Zero-Latency Offline Demo Fixtures and Live External Telemetry"
              className={cn(
                "relative flex items-center gap-2.5 px-3.5 py-1.5 rounded-lg border font-mono text-xs font-bold uppercase transition-all duration-300 cursor-pointer select-none",
                demoMode
                  ? "bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/40 shadow-[0_0_15px_rgba(0,240,255,0.25)] hover:bg-[#00f0ff]/20 hover:border-[#00f0ff]/70"
                  : "bg-[#00ff66]/10 text-[#00ff66] border-[#00ff66]/40 shadow-[0_0_15px_rgba(0,255,102,0.25)] hover:bg-[#00ff66]/20 hover:border-[#00ff66]/70"
              )}
            >
              {demoMode ? (
                <>
                  <span className="text-[#ffb703] text-sm animate-pulse">◈</span>
                  <span className="tracking-wider">DEMO FIXTURE MODE</span>
                  <span className="px-1.5 py-0.2 text-[9px] rounded bg-[#ffb703]/20 text-[#ffb703] border border-[#ffb703]/40">
                    OFFLINE-SAFE
                  </span>
                </>
              ) : (
                <>
                  <span className="relative flex w-2 h-2">
                    <span className="absolute inline-flex w-full h-full rounded-full opacity-75 animate-ping bg-[#00ff66]" />
                    <span className="relative inline-flex w-2 h-2 rounded-full bg-[#00ff66]" />
                  </span>
                  <span className="tracking-wider">LIVE TELEMETRY</span>
                  <span className="px-1.5 py-0.2 text-[9px] rounded bg-[#00ff66]/20 text-[#00ff66] border border-[#00ff66]/40">
                    LIVE
                  </span>
                </>
              )}
            </button>

            <div className="hidden md:flex items-center gap-3 px-3 py-1.5 rounded-lg border border-[#00f0ff]/20 bg-[#00f0ff]/5 text-[#00f0ff]">
              <Clock className="w-3.5 h-3.5" />
              <span>{utcTime || "00:00:00 UTC"}</span>
              <span className="text-white/30">|</span>
              <span className="text-white/80">{istTime || "00:00:00 IST"}</span>
            </div>

            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.02]">
              <Wifi className="w-3.5 h-3.5 text-[#00ff66]" />
              <span className="text-white/60">NODE:</span>
              <span className="text-white font-bold">PRIMARY-SOC-01</span>
            </div>
          </div>
        </header>

        {/* Dynamic Page Container with Ambient Lighting Mesh */}
        <main className="relative flex-1 overflow-y-auto overflow-x-hidden p-6 bg-[#030303]/40">
          {/* Ambient Mesh Lighting for Glassmorphic Refraction */}
          <div className="absolute -top-24 -left-24 w-[450px] h-[450px] rounded-full bg-cyan-900/20 blur-[120px] pointer-events-none z-0" />
          <div className="absolute -bottom-24 -right-24 w-[450px] h-[450px] rounded-full bg-rose-900/10 blur-[120px] pointer-events-none z-0" />

          <div className="relative z-10 max-w-[1920px] mx-auto h-full">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
