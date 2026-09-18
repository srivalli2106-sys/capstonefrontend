/**
 * Health API.
 *
 * Phase 1 only exposes the two backend health endpoints:
 *   GET /health        → { status: "ok" }                 (200)
 *   GET /health/ready  → { status: "ready" }              (200)
 *                     | { status: "unavailable" }         (503)
 *
 * No authentication is required for these endpoints.
 */

import { http, type HttpRequestOptions } from './http';
import type { LivenessResponse, ReadinessResponse } from '../types/api';

export function getLiveness(opts: HttpRequestOptions = {}) {
  return http.get<LivenessResponse>('/health', opts);
}

export function getReadiness(opts: HttpRequestOptions = {}) {
  return http.get<ReadinessResponse>('/health/ready', opts);
}

export type { LivenessResponse, ReadinessResponse };