"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { TrendingUp, ShieldCheck, IndianRupee, Sparkles, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSOCStream } from "@/hooks/useSOCStream";

// IBM Cost of a Data Breach Report 2026 Grounding Constants
export const BASE_EXPOSURE_PER_CONTAINED_INCIDENT = 5100000; // ₹51,00,000 (scaled per-incident exposure avoided)
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

interface BreachCostAvoidedCardProps {
  className?: string;
  compact?: boolean;
}

export default function BreachCostAvoidedCard({
  className,
  compact = false,
}: BreachCostAvoidedCardProps) {
  const { incidents, activePlaybook, isConnected } = useSOCStream(
    "ws://localhost:8000/ws/console"
  );

  // Pure arithmetic on existing incident state (count of CONTAINED incidents)
  const containedCount = useMemo(() => {
    const containedSet = new Set(
      (incidents || [])
        .filter((i) => i.status === "CONTAINED")
        .map((i) => i.id)
    );
    if (activePlaybook?.status === "COMPLETED" && activePlaybook.incident_id) {
      containedSet.add(activePlaybook.incident_id);
    }
    return containedSet.size;
  }, [incidents, activePlaybook]);

  const targetAmount = containedCount * BASE_EXPOSURE_PER_CONTAINED_INCIDENT;

  // Smooth numeric counter animation state
  const [displayAmount, setDisplayAmount] = useState<number>(targetAmount);
  const [isPulsing, setIsPulsing] = useState<boolean>(false);
  const [justIncremented, setJustIncremented] = useState<boolean>(false);
  const prevCountRef = useRef<number>(containedCount);
  const animFrameRef = useRef<number | null>(null);

  // Real-time smooth increment animation whenever an incident is contained
  useEffect(() => {
    const startVal = displayAmount;
    const endVal = targetAmount;
    const isIncrease = containedCount > prevCountRef.current;

    if (isIncrease) {
      setIsPulsing(true);
      setJustIncremented(true);
      const timer = setTimeout(() => {
        setIsPulsing(false);
        setJustIncremented(false);
      }, 3000);

      prevCountRef.current = containedCount;

      // Animate smoothly over 900ms
      const duration = 900;
      const startTime = performance.now();

      const step = (now: number) => {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Ease out cubic
        const ease = 1 - Math.pow(1 - progress, 3);
        const current = startVal + (endVal - startVal) * ease;
        setDisplayAmount(current);

        if (progress < 1) {
          animFrameRef.current = requestAnimationFrame(step);
        } else {
          setDisplayAmount(endVal);
        }
      };

      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      animFrameRef.current = requestAnimationFrame(step);

      return () => {
        clearTimeout(timer);
        if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      };
    } else {
      setDisplayAmount(endVal);
      prevCountRef.current = containedCount;
    }
  }, [targetAmount, containedCount]);

  const formattedValue = formatIndianCurrency(displayAmount);
  const rawIndianFormatted = `₹${Math.round(displayAmount).toLocaleString("en-IN")}`;
  const percentOfAvgBreach = Math.min(
    100,
    parseFloat(((displayAmount / IBM_INDIA_AVG_BREACH_COST) * 100).toFixed(1))
  );

  return (
    <motion.div
      className={cn(
        "relative w-full flex flex-col justify-between bg-white/[0.02] backdrop-blur-md border rounded-xl overflow-hidden transition-all duration-300",
        isPulsing
          ? "border-[#00ff66]/60 shadow-[0_0_30px_rgba(0,255,102,0.25)] bg-[#00ff66]/[0.04]"
          : "border-[#00ff66]/20 hover:border-[#00ff66]/40 shadow-[0_4px_20px_rgba(0,0,0,0.4)]",
        compact ? "p-3.5" : "p-4 sm:p-5",
        className
      )}
      animate={
        isPulsing
          ? {
              scale: [1, 1.015, 1],
              transition: { duration: 0.8, repeat: 1 },
            }
          : {}
      }
    >
      {/* Background Cyber Grid & Ambient Radial Glow */}
      <div className="absolute inset-0 bg-[radial-gradient(rgba(0,255,102,0.06)_1px,transparent_1px)] bg-[size:16px_16px] opacity-30 pointer-events-none" />
      <div
        className={cn(
          "absolute -top-12 -right-12 w-32 h-32 rounded-full bg-[#00ff66]/10 blur-2xl pointer-events-none transition-opacity duration-500",
          isPulsing ? "opacity-100 scale-125" : "opacity-40"
        )}
      />

      {/* Top Header Row */}
      <div className="relative z-10 flex items-center justify-between gap-2 mb-2.5">
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "flex items-center justify-center w-7 h-7 rounded-lg border transition-all",
              isPulsing
                ? "bg-[#00ff66]/20 border-[#00ff66]/60 text-[#00ff66] shadow-[0_0_12px_rgba(0,255,102,0.4)] animate-pulse"
                : "bg-[#00ff66]/10 border-[#00ff66]/30 text-[#00ff66]"
            )}
          >
            <TrendingUp className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-mono font-bold text-gray-200 tracking-widest uppercase flex items-center gap-1.5">
              BREACH EXPOSURE AVOIDED
              {isPulsing && (
                <Sparkles className="w-3.5 h-3.5 text-[#00ff66] animate-spin" />
              )}
            </h3>
          </div>
        </div>

        {/* Live Telemetry / ROI Pill */}
        <div className="flex items-center gap-2">
          <AnimatePresence>
            {justIncremented && (
              <motion.span
                initial={{ opacity: 0, x: 10, scale: 0.85 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.85 }}
                className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-bold text-[#00ff66] bg-[#00ff66]/20 border border-[#00ff66]/50 rounded shadow-[0_0_10px_rgba(0,255,102,0.3)] animate-pulse uppercase"
              >
                +₹51.0L PREVENTED
              </motion.span>
            )}
          </AnimatePresence>
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-white/5 bg-black/40 text-[10px] font-mono">
            <span
              className={cn(
                "w-1.5 h-1.5 rounded-full",
                isConnected ? "bg-[#00ff66] animate-ping" : "bg-[#ffb703]"
              )}
            />
            <span className="text-white/60">LIVE_ROI</span>
          </div>
        </div>
      </div>

      {/* Center Main Value Row */}
      <div className="relative z-10 my-1 flex flex-col sm:flex-row sm:items-baseline justify-between gap-2">
        <div className="flex items-baseline gap-2.5">
          <motion.span
            key={formattedValue}
            initial={{ opacity: 0.8, y: -2 }}
            animate={{ opacity: 1, y: 0 }}
            className={cn(
              "font-mono text-3xl sm:text-4xl font-black tracking-tight select-all",
              "text-[#00ff66] drop-shadow-[0_0_15px_rgba(0,255,102,0.5)]",
              isPulsing && "drop-shadow-[0_0_25px_rgba(0,255,102,0.85)]"
            )}
          >
            {formattedValue}
          </motion.span>

          <span className="text-xs font-mono text-white/50 tracking-wider">
            ({rawIndianFormatted})
          </span>
        </div>

        {/* Contained Incidents Badge */}
        <div className="flex items-center gap-1.5 self-start sm:self-auto px-2.5 py-1 rounded-md border border-[#00ff66]/20 bg-[#00ff66]/5 text-[11px] font-mono text-[#00ff66]">
          <ShieldCheck className="w-3.5 h-3.5 text-[#00ff66] shrink-0" />
          <span className="font-bold">{containedCount}</span>
          <span className="text-white/60">CONTAINED</span>
          <span className="text-white/30">|</span>
          <span className="text-white/50">₹51L / inc</span>
        </div>
      </div>

      {/* Progress towards benchmark bar */}
      <div className="relative z-10 mt-3 mb-2 w-full space-y-1">
        <div className="flex justify-between text-[10px] font-mono text-white/40">
          <span>Averted vs. National Breach Baseline</span>
          <span className="text-[#00ff66]/90 font-bold">
            {percentOfAvgBreach}% of ₹25.5 Cr India Avg
          </span>
        </div>
        <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden border border-white/5">
          <motion.div
            className="h-full bg-gradient-to-r from-[#00ff66]/60 to-[#00ff66] rounded-full shadow-[0_0_8px_#00ff66]"
            initial={{ width: 0 }}
            animate={{ width: `${percentOfAvgBreach}%` }}
            transition={{ duration: 1, ease: "easeOut" }}
          />
        </div>
      </div>

      {/* Subtext Citation */}
      <div className="relative z-10 pt-1.5 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-white/40">
        <span className="italic truncate">
          *Est. based on IBM Cost of a Data Breach Report 2026 (₹25.5 Cr India avg)
        </span>
        <span className="hidden md:inline text-white/30 shrink-0 ml-2">
          Zero-Trust Automated ROI
        </span>
      </div>
    </motion.div>
  );
}
