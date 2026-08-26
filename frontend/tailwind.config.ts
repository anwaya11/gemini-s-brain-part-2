import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        cyber: {
          black: "#030303",
          dark: "#06090e",
          card: "#080c14",
          panel: "rgba(10, 15, 25, 0.65)",
          cyan: "#00f0ff",
          magenta: "#ff003c",
          green: "#00ff66",
          amber: "#ffb703",
          border: "rgba(0, 240, 255, 0.12)",
          muted: "rgba(255, 255, 255, 0.45)",
          accent: "#121b2d",
        },
      },
      boxShadow: {
        "neon-cyan": "0 0 15px rgba(0, 240, 255, 0.4)",
        "neon-cyan-lg": "0 0 25px rgba(0, 240, 255, 0.6), 0 0 50px rgba(0, 240, 255, 0.2)",
        "neon-magenta": "0 0 15px rgba(255, 0, 60, 0.4)",
        "neon-magenta-lg": "0 0 25px rgba(255, 0, 60, 0.6), 0 0 50px rgba(255, 0, 60, 0.2)",
        "neon-green": "0 0 15px rgba(0, 255, 102, 0.4)",
        "neon-amber": "0 0 15px rgba(255, 183, 3, 0.4)",
        "glass-panel": "0 8px 32px 0 rgba(0, 0, 0, 0.6)",
        "glass-inset": "inset 0 0 20px rgba(255, 255, 255, 0.02), 0 8px 32px 0 rgba(0, 0, 0, 0.6)",
        "hud-glow": "0 0 20px rgba(0, 240, 255, 0.15), inset 0 0 15px rgba(0, 240, 255, 0.05)",
      },
      dropShadow: {
        "neon-cyan": "0 0 8px rgba(0, 240, 255, 0.6)",
        "neon-magenta": "0 0 8px rgba(255, 0, 60, 0.6)",
        "neon-green": "0 0 8px rgba(0, 255, 102, 0.6)",
        "neon-amber": "0 0 8px rgba(255, 183, 3, 0.6)",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "Inter", "Geist", "system-ui", "sans-serif"],
        mono: [
          "var(--font-mono)",
          "JetBrains Mono",
          "Fira Code",
          "Courier New",
          "monospace",
        ],
      },
      keyframes: {
        "pulse-glow": {
          "0%, 100%": {
            opacity: "1",
            boxShadow: "0 0 15px rgba(0, 240, 255, 0.4)",
          },
          "50%": {
            opacity: "0.6",
            boxShadow: "0 0 5px rgba(0, 240, 255, 0.2)",
          },
        },
        "pulse-magenta": {
          "0%, 100%": {
            opacity: "1",
            boxShadow: "0 0 20px rgba(255, 0, 60, 0.5)",
          },
          "50%": {
            opacity: "0.5",
            boxShadow: "0 0 8px rgba(255, 0, 60, 0.2)",
          },
        },
        scanline: {
          "0%": {
            transform: "translateY(-100%)",
          },
          "100%": {
            transform: "translateY(1000%)",
          },
        },
        "radar-sweep": {
          "0%": {
            transform: "rotate(0deg)",
          },
          "100%": {
            transform: "rotate(360deg)",
          },
        },
        glitch: {
          "0%, 100%": { transform: "translate(0)" },
          "20%": { transform: "translate(-2px, 2px)" },
          "40%": { transform: "translate(-2px, -2px)" },
          "60%": { transform: "translate(2px, 2px)" },
          "80%": { transform: "translate(2px, -2px)" },
        },
      },
      animation: {
        "pulse-glow": "pulse-glow 2.5s infinite ease-in-out",
        "pulse-magenta": "pulse-magenta 2s infinite ease-in-out",
        scanline: "scanline 8s linear infinite",
        "radar-sweep": "radar-sweep 4s linear infinite",
        glitch: "glitch 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94) both",
      },
    },
  },
  plugins: [],
};

export default config;
