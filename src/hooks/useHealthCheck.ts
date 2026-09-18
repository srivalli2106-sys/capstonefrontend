/**
 * useHealthCheck
 *
 * React hook that fetches liveness + readiness on mount and exposes a small,
 * discriminated state for the UI. No retry loops, no caching, no global state.
 */

import { useEffect, useState } from 'react';
import { ApiError } from '../api/http';
import { getLiveness, getReadiness } from '../api/health';
import type { LivenessResponse, ReadinessResponse } from '../types/api';

export type HealthCheckState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ok'; liveness: LivenessResponse; readiness: ReadinessResponse | null; requestId: string | null }
  | { kind: 'unavailable'; message: string; requestId: string | null }
  | { kind: 'error'; message: string; requestId: string | null };

interface UseHealthCheckResult {
  state: HealthCheckState;
  refresh: () => void;
}

export function useHealthCheck(timeoutMs = 8000): UseHealthCheckResult {
  const [state, setState] = useState<HealthCheckState>({ kind: 'idle' });
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    setState({ kind: 'loading' });

    (async () => {
      let liveness: LivenessResponse | null = null;
      let readiness: ReadinessResponse | null = null;
      let requestId: string | null = null;
      let firstError: ApiError | null = null;

      try {
        const live = await getLiveness({ timeoutMs, signal: controller.signal });
        if (cancelled) return;
        liveness = live.data;
        requestId = live.requestId;
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError) {
          firstError = err;
          requestId = err.requestId;
        } else {
          throw err;
        }
      }

      try {
        const ready = await getReadiness({ timeoutMs, signal: controller.signal });
        if (cancelled) return;
        readiness = ready.data;
        if (requestId === null) {
          requestId = ready.requestId;
        }
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError) {
          if (firstError === null) {
            firstError = err;
          }
          if (requestId === null) {
            requestId = err.requestId;
          }
        } else {
          throw err;
        }
      }

      if (cancelled) return;

      if (firstError !== null) {
        const isNetwork = firstError.status === 0;
        setState({
          kind: isNetwork ? 'unavailable' : 'error',
          message: firstError.message,
          requestId,
        });
        return;
      }

      if (liveness === null) {
        setState({
          kind: 'error',
          message: 'Backend returned no liveness data.',
          requestId,
        });
        return;
      }

      setState({
        kind: 'ok',
        liveness,
        readiness,
        requestId,
      });
    })().catch((err: unknown) => {
      if (cancelled) return;
      const message = err instanceof Error ? err.message : 'Unexpected error';
      setState({ kind: 'error', message, requestId: null });
    });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [reloadKey, timeoutMs]);

  return {
    state,
    refresh: () => setReloadKey((k) => k + 1),
  };
}