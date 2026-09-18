import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getKeyBundle,
  getPrekeyStatus,
  uploadKeyBundle,
} from '../src/api/keys';
import {
  KeyBundleError,
  parseRemoteKeyBundle,
} from '../src/crypto/keyBundle';
import {
  buildDevicePublicBundle,
  devicePublicBundleToHex,
} from '../src/crypto/deviceKeys';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';
import type { KeyBundleResponse } from '../src/types/keys';

const API_BASE = 'https://api.example.test';

function block32(start: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = (start + i) % 256;
  return out;
}

// Deterministic bob device used to produce a VALID bundle (SPK sig verifies).
function bobBundle(): { hex: Record<string, string | string[]>; opkPublicHex: string } {
  const authSeed = block32(232);
  const device = {
    ikxPrivate: block32(33),
    spkPrivate: block32(65),
    opkPrivate: block32(97),
  };
  const bundle = buildDevicePublicBundle(authSeed, device);
  const hex = devicePublicBundleToHex(bundle);
  return {
    hex,
    opkPublicHex: (hex.opk_publics as string[])[0],
  };
}

function mockFetchOnce(status: number, body: unknown): ReturnType<typeof vi.fn> {
  const fn = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
  vi.stubGlobal('fetch', fn);
  return fn;
}

function keyBundleResponse(): KeyBundleResponse {
  const { hex, opkPublicHex } = bobBundle();
  return {
    user_id: 'alice',
    ik_public: hex.ik_public as string,
    spk_public: hex.spk_public as string,
    spk_sig: hex.spk_signature as string,
    opk_public: opkPublicHex,
    version: 3,
  };
}

const TOKEN = 'jwt.test.token';

describe('GET /keys/bundle', () => {
  it('sends the Bearer token and parses a valid bundle', async () => {
    const fn = mockFetchOnce(200, keyBundleResponse());

    const { data } = await getKeyBundle('alice', { authToken: TOKEN });

    const [url, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${API_BASE}/keys/bundle/alice`);
    expect((init.headers as Record<string, string>).Authorization).toBe(
      `Bearer ${TOKEN}`,
    );

    const parsed = parseRemoteKeyBundle(data);
    expect(parsed.userId).toBe('alice');
    expect(parsed.ikPublicHex).toBe(keyBundleResponse().ik_public);
    expect(parsed.spkPublicHex).toBe(keyBundleResponse().spk_public);
    expect(parsed.opkPublicHex).toBe(keyBundleResponse().opk_public);
    // The backend contract never carries the X25519 IKX identity; modeled
    // explicitly instead of silently defaulting.
    expect(parsed.ikxPublicHex).toBeNull();
  });

  it('rejects a bundle whose SPK signature does not verify', async () => {
    const bad = keyBundleResponse();
    bad.spk_public = bytesToHex(block32(7)); // random new SPK, stale signature
    mockFetchOnce(200, bad);

    const { data } = await getKeyBundle('alice', { authToken: TOKEN });
    expect(() => parseRemoteKeyBundle(data)).toThrow(KeyBundleError);
    try {
      parseRemoteKeyBundle(data);
    } catch (err) {
      if (err instanceof KeyBundleError) {
        expect(err.code).toBe('invalid_signature');
      }
    }
  });

  it('rejects bundles with malformed hex / wrong lengths', async () => {
    const bad = keyBundleResponse();
    bad.spk_public = 'zz'.repeat(32); // non-hex
    mockFetchOnce(200, bad);
    const { data } = await getKeyBundle('alice', { authToken: TOKEN });
    expect(() => parseRemoteKeyBundle(data)).toThrow(KeyBundleError);

    const short = keyBundleResponse();
    short.spk_sig = bytesToHex(hexToBytes(short.spk_sig).slice(0, 31));
    mockFetchOnce(200, short);
    const { data: data2 } = await getKeyBundle('alice', { authToken: TOKEN });
    let caught2: unknown = null;
    try {
      parseRemoteKeyBundle(data2);
    } catch (err) {
      caught2 = err;
    }
    expect(caught2).toBeInstanceOf(KeyBundleError);
  });

  it('404 surfaces a typed ApiError with the backend code', async () => {
    mockFetchOnce(404, {
      error: { code: 'not_found', message: 'Key bundle not found', request_id: 'r1' },
    });
    await expect(getKeyBundle('ghost', { authToken: TOKEN })).rejects.toMatchObject({
      status: 404,
      code: 'not_found',
    });
  });
});

describe('POST /keys/upload', () => {
  it('sends only PUBLIC key material and the Bearer token', async () => {
    const fn = mockFetchOnce(200, { status: 'ok', user_id: 'alice' });

    const { hex, opkPublicHex } = bobBundle();
    await uploadKeyBundle(
      {
        spk_public: hex.spk_public as string,
        spk_sig: hex.spk_signature as string,
        opk_public: opkPublicHex,
      },
      { authToken: TOKEN },
    );

    const [url, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${API_BASE}/keys/upload`);
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(headers['Content-Type']).toBe('application/json');

    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      'opk_public',
      'spk_public',
      'spk_sig',
    ]);
    expect(typeof body.spk_public).toBe('string');
    expect(typeof body.spk_sig).toBe('string');
    expect(typeof body.opk_public).toBe('string');

    // The wire body must contain NO private scalars.
    const asText = JSON.stringify(body);
    expect(asText).not.toContain(bytesToHex(block32(65))); // spk private
    expect(asText).not.toContain(bytesToHex(block32(33))); // ikx private
    expect(asText).not.toContain(bytesToHex(block32(97))); // opk private
    expect(asText).not.toMatch(/(private|seed|secret)/i);
  });

  it('allows a null opk', async () => {
    const fn = mockFetchOnce(200, { status: 'ok', user_id: 'alice' });
    const { hex } = bobBundle();
    await uploadKeyBundle(
      { spk_public: hex.spk_public as string, spk_sig: hex.spk_signature as string, opk_public: null },
      { authToken: TOKEN },
    );
    const [, init] = fn.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(String(init.body)) as { opk_public: unknown };
    expect(body.opk_public).toBeNull();
  });
});

describe('GET /keys/prekeys', () => {
  it('reports OPK availability', async () => {
    const fn = mockFetchOnce(200, {
      user_id: 'alice',
      opk_available: false,
      version: 3,
    });
    const { data } = await getPrekeyStatus('alice', { authToken: TOKEN });
    const [url] = fn.mock.calls[0] as [string, unknown];
    expect(url).toBe(`${API_BASE}/keys/prekeys/alice`);
    expect(data).toEqual({ user_id: 'alice', opk_available: false, version: 3 });
  });
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});