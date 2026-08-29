"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, Unlock, Radio } from "lucide-react";
import { useSOCStream } from "@/hooks/useSOCStream";

export default function RiskDial({ initialRisk = 0.2 }: { initialRisk?: number }) {
  const { riskScore, isConnected } = useSOCStream("ws://localhost:8000/ws/console");
  
  // Safe numeric risk initialization to prevent hydration mismatch
  const [risk, setRisk] = useState<number>(() => {
    return typeof riskScore === "number" && !isNaN(riskScore)
      ? riskScore
      : initialRisk ?? 0.2;
  });
  const [isMounted, setIsMounted] = useState<boolean>(false);
  const [isHovered, setIsHovered] = useState<boolean>(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  useEffect(() => {
    if (typeof riskScore === "number" && !isNaN(riskScore)) {
      setRisk(riskScore);
    }
  }, [riskScore]);

  const safeRisk = Math.min(Math.max(typeof risk === "number" && !isNaN(risk) ? risk : 0.2, 0), 1);
  const isHighRisk = safeRisk >= 0.4;
  
  // Guaranteed valid numeric strokeDashoffset (initializes safely at 283 on SSR)
  const strokeDashoffset = isMounted ? 283 - 283 * safeRisk : 283;
  const glowColor = isHighRisk ? "rgba(255, 0, 60, 0.6)" : "rgba(0, 255, 102, 0.6)";

  return (
    <motion.div
      className="relative w-full h-full min-h-[300px] flex flex-col items-center justify-center bg-white/[0.02] backdrop-blur-md border border-[#00f0ff]/10 rounded-xl overflow-hidden cursor-crosshair hover:border-[#00f0ff]/30 transition-all"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      whileHover={{ scale: 1.01, boxShadow: `0 0 30px ${glowColor}` }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
    >
      {/* Background Grid & Scanline */}
      <div className="absolute inset-0 bg-[radial-gradient(rgba(255,255,255,0.05)_1px,transparent_1px)] bg-[size:20px_20px] opacity-20 pointer-events-none" />
      {isHovered && (
        <motion.div
          className="absolute top-0 left-0 w-full h-[2px] bg-[#00f0ff]/50"
          animate={{ y: [0, 300] }}
          transition={{ repeat: Infinity, duration: 1.5, ease: "linear" }}
        />
      )}

      {/* Header Label */}
      <div className="absolute top-4 left-4 flex items-center gap-2">
        <Radio className="w-3.5 h-3.5 text-[#ffb703] animate-pulse" />
        <h3 className="text-xs font-mono text-gray-400 tracking-widest uppercase">
          AUTONOMY_DIAL [risk_engine.py]
        </h3>
      </div>

      {/* WebSocket Status Badge */}
      <div className="absolute top-4 right-4 flex items-center gap-2 text-[10px] font-mono">
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            isConnected ? "bg-[#00ff66] animate-ping" : "bg-[#ffb703]"
          }`}
        />
        <span className={isConnected ? "text-[#00ff66]" : "text-[#ffb703]"}>
          {isConnected ? "LIVE DIAL" : "CONNECTING..."}
        </span>
      </div>

      {/* SVG Interactive Gauge */}
      <div className="relative w-48 h-48 flex items-center justify-center mt-4">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="8"
          />
          <motion.circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={isHighRisk ? "#ff003c" : "#00ff66"}
            strokeWidth="8"
            strokeDasharray="283"
            initial={{ strokeDashoffset: 283 }}
            animate={{ strokeDashoffset }}
            transition={{ type: "spring", bounce: 0, duration: 1.2 }}
            style={{ filter: `drop-shadow(0 0 8px ${isHighRisk ? "#ff003c" : "#00ff66"})` }}
            strokeLinecap="round"
          />
        </svg>

        {/* Center Readout */}
        <div className="absolute flex flex-col items-center">
          <motion.span
            key={isHighRisk ? "high" : "low"}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`text-3xl font-bold font-mono ${
              isHighRisk
                ? "text-[#ff003c] drop-shadow-[0_0_10px_rgba(255,0,60,0.6)]"
                : "text-[#00ff66] drop-shadow-[0_0_10px_rgba(0,255,102,0.6)]"
            }`}
          >
            {safeRisk.toFixed(2)}
          </motion.span>
          <span className="text-xs text-gray-500 font-mono mt-1">RISK_SCORE</span>
        </div>
      </div>

      {/* Decision Status Panel */}
      <div className="mt-5 w-[80%] flex justify-between items-center border border-white/5 bg-black/40 px-4 py-2 rounded">
        <div className="flex items-center gap-2">
          {isHighRisk ? (
            <ShieldAlert className="w-4 h-4 text-[#ff003c] animate-pulse" />
          ) : (
            <Unlock className="w-4 h-4 text-[#00ff66]" />
          )}
          <span className="text-xs font-mono text-gray-300">
            {isHighRisk ? "APPROVAL_REQ" : "AUTO_CONTAIN"}
          </span>
        </div>
        <span className="text-[10px] font-mono text-white/40">
          Threshold: 0.40
        </span>
      </div>
    </motion.div>
  );
}
