import type { JSX } from 'react';

interface LogoProps {
  size?: number;
  showWordmark?: boolean;
  ariaLabel?: string;
  variant?: 'auto' | 'header' | 'default';
}

/**
 * Logo - the Secure Messaging brand mark.
 *
 * Pure SVG so it scales crisply at any size. Inverts via currentColor so
 * it picks up the surrounding text colour, and accepts an explicit
 * `variant="header"` for the dark navigation bar.
 */
export function Logo({
  size = 28,
  showWordmark = true,
  ariaLabel = 'Secure Messaging',
  variant = 'auto',
}: LogoProps): JSX.Element {
  const innerFill =
    variant === 'header' ? '#0c0a09' : 'var(--color-bg-canvas, #ffffff)';
  const wrapperColor =
    variant === 'header'
      ? 'var(--color-header-text, #fafaf9)'
      : 'var(--color-text-primary, #1c1917)';
  return (
    <span
      className="brand"
      aria-label={ariaLabel}
      style={{ color: wrapperColor }}
    >
      <svg
        className="brand__mark"
        width={size}
        height={size}
        viewBox="0 0 32 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        <rect width="32" height="32" rx="7" fill="currentColor" />
        <path
          d="M16 8.5a4 4 0 0 0-4 4v2.25h-1A1.75 1.75 0 0 0 9.25 16.5v7A1.75 1.75 0 0 0 11 25.25h10a1.75 1.75 0 0 0 1.75-1.75v-7A1.75 1.75 0 0 0 21 14.75h-1V12.5a4 4 0 0 0-4-4Zm-2.25 6.25V12.5a2.25 2.25 0 0 1 4.5 0v2.25h-4.5Z"
          fill={innerFill}
        />
      </svg>
      {showWordmark && <span className="brand__wordmark">Secure Messaging</span>}
    </span>
  );
}
