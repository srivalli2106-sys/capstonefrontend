/// <reference types="vite/client" />

function readEnv(name: 'VITE_API_BASE_URL' | 'VITE_WS_BASE_URL', fallback?: string): string {
  const value = import.meta.env[name];
  if (typeof value === 'string' && value.length > 0) {
    return value;
  }
  if (fallback !== undefined) {
    return fallback;
  }
  throw new Error(`Missing required environment variable: ${name}`);
}

/**
 * Derive the WebSocket base URL from the API base URL.
 *
 * The WebSocket endpoint lives on the backend host (`{apiBaseUrl}/ws`), NOT
 * on the frontend origin. Without an explicit `VITE_WS_BASE_URL`, a relative
 * `/ws` would resolve against `window.location.origin` (e.g. the Vercel SPA)
 * and 404. This mirrors the API scheme as ws:/wss: so the production SPA
 * connects to `wss://<backend>/ws` and local dev (`http://localhost:...`)
 * still works.
 */
function deriveWsBaseUrl(apiBaseUrl: string): string {
  if (apiBaseUrl.startsWith('https://')) {
    return `wss://${apiBaseUrl.slice('https://'.length)}`;
  }
  if (apiBaseUrl.startsWith('http://')) {
    return `ws://${apiBaseUrl.slice('http://'.length)}`;
  }
  return apiBaseUrl;
}

const apiBaseUrl = readEnv('VITE_API_BASE_URL');

export const config = {
  apiBaseUrl,
  wsBaseUrl: readEnv('VITE_WS_BASE_URL', deriveWsBaseUrl(apiBaseUrl)),
} as const;