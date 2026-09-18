/**
 * Centralized, typed HTTP client.
 *
 * Responsibilities (Phase 1):
 *  - Build URLs from the configured API base URL.
 *  - Issue JSON requests and parse JSON responses.
 *  - Apply a per-request timeout via AbortController.
 *  - Surface a typed `ApiError` for non-2xx responses.
 *  - Capture the backend's `X-Request-ID` correlation header.
 *
 * Explicit non-responsibilities (later phases):
 *  - No auth header injection.
 *  - No token refresh.
 *  - No retry loop.
 *  - No global state mutation.
 */

import { config } from '../config/env';

const DEFAULT_TIMEOUT_MS = 10_000;
const REQUEST_ID_HEADER = 'X-Request-ID';

export class ApiError extends Error {
  public readonly status: number;
  public readonly statusText: string;
  public readonly code: string;
  public readonly requestId: string | null;

  constructor(opts: {
    status: number;
    statusText: string;
    code: string;
    message: string;
    requestId: string | null;
  }) {
    super(opts.message);
    this.name = 'ApiError';
    this.status = opts.status;
    this.statusText = opts.statusText;
    this.code = opts.code;
    this.requestId = opts.requestId;
  }
}

export interface ApiSuccess<T> {
  data: T;
  requestId: string | null;
}

export interface HttpRequestOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

function joinUrl(base: string, path: string): string {
  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }
  const normalizedBase = base.endsWith('/') ? base.slice(0, -1) : base;
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${normalizedBase}${normalizedPath}`;
}

function readRequestId(response: Response): string | null {
  const raw = response.headers.get(REQUEST_ID_HEADER);
  if (typeof raw === 'string' && raw.length > 0) {
    return raw;
  }
  return null;
}

interface ParsedErrorBody {
  code: string;
  message: string;
}

async function parseErrorBody(response: Response): Promise<ParsedErrorBody> {
  const fallback: ParsedErrorBody = {
    code: `http_${response.status}`,
    message: response.statusText || 'Request failed',
  };

  let text: string;
  try {
    text = await response.text();
  } catch {
    return fallback;
  }
  if (text.length === 0) {
    return fallback;
  }

  try {
    const parsed: unknown = JSON.parse(text);
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      'error' in parsed &&
      parsed.error !== null &&
      typeof parsed.error === 'object'
    ) {
      const err = parsed.error as { code?: unknown; message?: unknown };
      const code = typeof err.code === 'string' ? err.code : fallback.code;
      const message =
        typeof err.message === 'string' && err.message.length > 0
          ? err.message
          : fallback.message;
      return { code, message };
    }
  } catch {
    return { code: fallback.code, message: text.slice(0, 200) };
  }
  return fallback;
}

function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === 'AbortError';
}

async function request<T>(
  method: 'GET' | 'POST',
  path: string,
  body: unknown,
  opts: HttpRequestOptions,
): Promise<ApiSuccess<T>> {
  const controller = new AbortController();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const external = opts.signal;
  const forwardExternalAbort = (): void => controller.abort();
  if (external) {
    if (external.aborted) {
      clearTimeout(timer);
      throw new ApiError({
        status: 0,
        statusText: 'Aborted',
        code: 'aborted',
        message: 'Request aborted',
        requestId: null,
      });
    }
    external.addEventListener('abort', forwardExternalAbort);
  }

  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  let serializedBody: string | undefined;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    serializedBody = JSON.stringify(body);
  }

  let response: Response;
  try {
    response = await fetch(joinUrl(config.apiBaseUrl, path), {
      method,
      signal: controller.signal,
      headers,
      body: serializedBody,
    });
  } catch (err) {
    clearTimeout(timer);
    if (external) {
      external.removeEventListener('abort', forwardExternalAbort);
    }
    if (isAbortError(err)) {
      throw new ApiError({
        status: 0,
        statusText: 'Aborted',
        code: 'aborted',
        message: 'Request aborted (timeout or caller cancel).',
        requestId: null,
      });
    }
    throw new ApiError({
      status: 0,
      statusText: 'Network Error',
      code: 'network_error',
      message: 'Unable to reach the backend.',
      requestId: null,
    });
  }

  clearTimeout(timer);
  if (external) {
    external.removeEventListener('abort', forwardExternalAbort);
  }

  const requestId = readRequestId(response);

  if (!response.ok) {
    const { code, message } = await parseErrorBody(response);
    throw new ApiError({
      status: response.status,
      statusText: response.statusText,
      code,
      message,
      requestId,
    });
  }

  let data: T;
  try {
    data = (await response.json()) as T;
  } catch {
    throw new ApiError({
      status: response.status,
      statusText: response.statusText,
      code: 'invalid_response',
      message: 'Backend returned a non-JSON response.',
      requestId,
    });
  }

  return { data, requestId };
}

export const http = {
  get<T>(path: string, opts: HttpRequestOptions = {}): Promise<ApiSuccess<T>> {
    return request<T>('GET', path, undefined, opts);
  },
  post<T>(
    path: string,
    body?: unknown,
    opts: HttpRequestOptions = {},
  ): Promise<ApiSuccess<T>> {
    return request<T>('POST', path, body, opts);
  },
} as const;