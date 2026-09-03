/**
 * frontend/lib/config.ts
 *
 * Central configuration for Project-CHIMERA frontend API and WebSocket endpoints.
 * Prioritizes environment variables with production Render fallback.
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "https://chimera-backend-5jwu.onrender.com";

export const WS_BASE_URL =
  process.env.NEXT_PUBLIC_WS_URL || "wss://chimera-backend-5jwu.onrender.com/ws/console";
