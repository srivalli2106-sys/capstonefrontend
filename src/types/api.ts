/**
 * Shared API types.
 *
 * These types mirror the backend's actual response contracts.
 * Verified against `server/app.py` (Phase 1: only /health and /health/ready).
 */

export type LivenessStatus = 'ok';
export type ReadinessStatus = 'ready' | 'unavailable';

export interface LivenessResponse {
  status: LivenessStatus;
}

export interface ReadinessResponse {
  status: ReadinessStatus;
}