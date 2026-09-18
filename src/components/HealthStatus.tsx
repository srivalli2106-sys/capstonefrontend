import type { JSX } from 'react';
import { useHealthCheck } from '../hooks/useHealthCheck';
import { config } from '../config/env';

export function HealthStatus(): JSX.Element {
  const { state, refresh } = useHealthCheck();

  let badgeClass = 'health-badge';
  let badgeText = 'Unknown';
  let detail: JSX.Element | null = null;

  switch (state.kind) {
    case 'idle':
    case 'loading':
      badgeClass += ' health-badge--loading';
      badgeText = 'Checking…';
      break;
    case 'ok':
      badgeClass += ' health-badge--ok';
      badgeText = state.readiness?.status === 'ready' ? 'Ready' : 'Backend healthy';
      detail = (
        <ul className="health-status__list">
          <li>
            <span className="health-status__label">Liveness</span>
            <span className="health-status__value">{state.liveness.status}</span>
          </li>
          <li>
            <span className="health-status__label">Readiness</span>
            <span className="health-status__value">
              {state.readiness?.status ?? 'unknown'}
            </span>
          </li>
          {state.requestId !== null && (
            <li className="health-status__meta">
              request_id: <code>{state.requestId}</code>
            </li>
          )}
        </ul>
      );
      break;
    case 'unavailable':
      badgeClass += ' health-badge--unavailable';
      badgeText = 'Backend unavailable';
      detail = (
        <p className="health-status__detail">
          {state.message}
          {state.requestId !== null && (
            <>
              {' '}
              <span className="health-status__meta">
                (request_id: <code>{state.requestId}</code>)
              </span>
            </>
          )}
        </p>
      );
      break;
    case 'error':
      badgeClass += ' health-badge--error';
      badgeText = 'Error';
      detail = (
        <p className="health-status__detail">
          {state.message}
          {state.requestId !== null && (
            <>
              {' '}
              <span className="health-status__meta">
                (request_id: <code>{state.requestId}</code>)
              </span>
            </>
          )}
        </p>
      );
      break;
  }

  return (
    <section className="health-status" aria-label="Backend connectivity status">
      <header className="health-status__header">
        <span className={badgeClass}>{badgeText}</span>
        <button
          type="button"
          className="health-status__refresh"
          onClick={refresh}
          disabled={state.kind === 'loading'}
        >
          Refresh
        </button>
      </header>
      <p className="health-status__api">
        API: <code>{config.apiBaseUrl}</code>
      </p>
      {detail}
    </section>
  );
}