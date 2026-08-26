'use client';
import dynamic from 'next/dynamic';
import { useEffect, useState } from 'react';

// Dynamically import to disable SSR (ForceGraph requires the browser window)
const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

export default function BlastRadiusGraph() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  useEffect(() => {
    // Simulated incident graph to demonstrate the canvas
    setGraphData({
      nodes: [
        { id: 'attacker', group: 1, label: '185.220.101.42', color: '#ff003c' },
        { id: 'firewall', group: 2, label: 'WAF', color: '#00f0ff' },
        { id: 'decoy', group: 3, label: '/decoy/db-admin', color: '#ffb703' }
      ],
      links: [
        { source: 'attacker', target: 'firewall' },
        { source: 'firewall', target: 'decoy' }
      ]
    });
  }, []);

  return (
    <div className="w-full h-full min-h-[300px] bg-white/[0.02] backdrop-blur-md border border-cyber-cyan/10 rounded-xl overflow-hidden relative flex items-center justify-center cursor-move">
      <h3 className="absolute top-4 left-4 text-xs font-mono text-gray-400 tracking-widest z-10 pointer-events-none">
        BLAST_RADIUS [react-force-graph]
      </h3>
      <div className="absolute inset-0 opacity-80 mix-blend-screen">
        <ForceGraph2D
          graphData={graphData}
          nodeLabel="label"
          nodeColor="color"
          linkColor={() => 'rgba(0, 240, 255, 0.4)'}
          backgroundColor="transparent"
        />
      </div>
    </div>
  );
}
