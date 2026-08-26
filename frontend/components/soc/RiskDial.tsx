'use client';

import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import { ShieldAlert, Unlock } from 'lucide-react';

export default function RiskDial({ initialRisk = 0.2 }) {
  const [risk, setRisk] = useState(initialRisk);
  const [isHovered, setIsHovered] = useState(false);

  // Simulate live risk fluctuations for the demo
  useEffect(() => {
    const interval = setInterval(() => {
      setRisk((prev) => Math.min(Math.max(prev + (Math.random() * 0.1 - 0.05), 0), 1));
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const isHighRisk = risk >= 0.4;
  const strokeDashoffset = 283 - 283 * risk;
  const glowColor = isHighRisk ? 'rgba(255, 0, 60, 0.6)' : 'rgba(0, 255, 102, 0.6)';

  return (
    <motion.div 
      className="relative w-full h-full min-h-[300px] flex flex-col items-center justify-center bg-white/[0.02] backdrop-blur-md border border-cyber-cyan/10 rounded-xl overflow-hidden cursor-crosshair"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      whileHover={{ scale: 1.02, boxShadow: `0 0 30px ${glowColor}` }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
    >
      {/* Background Grid & Scanline */}
      <div className="absolute inset-0 bg-[radial-gradient(rgba(255,255,255,0.05)_1px,transparent_1px)] bg-[size:20px_20px] opacity-20 pointer-events-none" />
      {isHovered && <motion.div className="absolute top-0 left-0 w-full h-[2px] bg-cyber-cyan/50" animate={{ y: [0, 300] }} transition={{ repeat: Infinity, duration: 1.5, ease: "linear" }} />}

      <h3 className="absolute top-4 left-4 text-xs font-mono text-gray-400 tracking-widest">
        AUTONOMY_DIAL [risk_engine.py]
      </h3>

      {/* SVG Interactive Gauge */}
      <div className="relative w-48 h-48 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
          <motion.circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={isHighRisk ? '#ff003c' : '#00ff66'}
            strokeWidth="8"
            strokeDasharray="283"
            animate={{ strokeDashoffset }}
            transition={{ type: "spring", bounce: 0, duration: 1.5 }}
            style={{ filter: `drop-shadow(0 0 8px ${isHighRisk ? '#ff003c' : '#00ff66'})` }}
            strokeLinecap="round"
          />
        </svg>

        {/* Center Readout */}
        <div className="absolute flex flex-col items-center">
          <motion.span 
            key={isHighRisk ? 'high' : 'low'}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`text-3xl font-bold font-mono ${isHighRisk ? 'text-cyber-magenta drop-shadow-neon-magenta' : 'text-cyber-green drop-shadow-neon-green'}`}
          >
            {risk.toFixed(2)}
          </motion.span>
          <span className="text-xs text-gray-500 font-mono mt-1">RISK_SCORE</span>
        </div>
      </div>

      {/* Decision Status Panel */}
      <div className="mt-6 w-[80%] flex justify-between items-center border border-white/5 bg-black/40 px-4 py-2 rounded">
        <div className="flex items-center gap-2">
           {isHighRisk ? <ShieldAlert className="w-4 h-4 text-cyber-magenta animate-pulse" /> : <Unlock className="w-4 h-4 text-cyber-green" />}
           <span className="text-xs font-mono text-gray-300">
             {isHighRisk ? 'APPROVAL_REQ' : 'AUTO_CONTAIN'}
           </span>
        </div>
      </div>
    </motion.div>
  );
}
