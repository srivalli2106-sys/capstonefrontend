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

export const config = {
  apiBaseUrl: readEnv('VITE_API_BASE_URL'),
  wsBaseUrl: readEnv('VITE_WS_BASE_URL', ''),
} as const;