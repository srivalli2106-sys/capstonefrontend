/**
 * ServiceStatus - compact backend connectivity indicator.
 *
 * Public-facing variant that does NOT expose backend URLs. Renders only
 * a short status label ("All systems operational." / "Unable to connect
 * right now.") and a refresh action.
 */

import type { JSX } from 'react';
import { useHealthCheck } from '../hooks/useHealthCheck';

export function ServiceStatus(): JSX.Element {
  const { state, refresh } = useHealthCheck();

  let dotClass = 'service-status__dot';
  let title = 'Service status';
  let message = 'Checking...';
  let isLoading = false;

  switch (state.kind) {
    case 'idle':
    case 'loading':
      dotClass += '';
      title = 'Service status';
      message = 'Checking...';
      isLoading = true;
      break;
    case 'ok':
      dotClass += ' service-status__dot--ok';
      title = 'Service status';
      message = 'All systems operational.';
      break;
    case 'unavailable':
    case 'error':
      dotClass += ' service-status__dot--error';
      title = 'Service status';
      message = 'Unable to connect right now.';
      break;
  }

  return (
    <div className="service-status" role="status" aria-live="polite">
      <div className="service-status__label">
        <span className={dotClass} aria-hidden="true" />
        <span className="service-status__title">{title}</span>
        <span className="service-status__message">{message}</span>
      </div>
      <button
        type="button"
        className="service-status__refresh"
        onClick={refresh}
        disabled={isLoading}
        aria-label="Refresh service status"
      >
        Refresh
      </button>
    </div>
  );
}
