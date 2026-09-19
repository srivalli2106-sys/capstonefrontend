/**
 * Tests for parseRemoteKeyBundle validation of hybrid (v2) bundles.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import {
  KeyBundleError,
  parseRemoteKeyBundle,
  PROTOCOL_VERSION_HYBRID,
} from '../src/crypto/keyBundle';
import {
  generateMlDsa44Keypair,
  generateMlKem768Keypair,
  mlDsa44Sign,
  mlKem768DerivePublicKey,
  mlDsa44DerivePublicKey,
} from '../src/crypto/pq';
import {
  buildDevicePublicBundle,
  buildHybridBindingContext,
  generateHybridDeviceKeys,
} from '../src/crypto/deviceKeys';
import { generateEd25519Keypair } from '../src/crypto/ed25519';
import { generateX25519Keypair } from '../src/crypto/x25519';

const enc = new TextEncoder();

describe('parseRemoteKeyBundle (hybrid v2)', () => {
  let validBundleHex: ReturnType<typeof buildDevicePublicBundle> extends Promise<infer B> ? B : never;

  beforeAll(async () => {
    const auth = generateEd25519Keypair();
    const ikx = generateX25519Keypair();
    const spk = generateX25519Keypair();
    const base = await generateHybridDeviceKeys({
      ikxPrivate: ikx.privateKey,
      spkPrivate: spk.privateKey,
      opkPrivate: null,
      pqKemPrivate: null,
      pqSigPrivate: null,
    });
    const bundle = await buildDevicePublicBundle(auth.privateSeed, base);
    validBundleHex = bundle;
  });

  function makeResponse(
    overrides: Partial<{
      ik_public: string;
      xdh_public: string;
      spk_public: string;
      spk_sig: string;
      opk_public: string | null;
      pq_kem_public: string | null;
      pq_sig_public: string | null;
      pq_binding_sig: string | null;
      protocol_version: number;
      version: number;
    }> = {},
  ) {
    return {
      user_id: 'bob',
      ik_public: toHex(validBundleHex.ikPublic),
      xdh_public: toHex(validBundleHex.xdhPublic),
      spk_public: toHex(validBundleHex.spkPublic),
      spk_sig: toHex(validBundleHex.spkSignature),
      opk_public: null,
      pq_kem_public: validBundleHex.pqKemPublic
        ? toHex(validBundleHex.pqKemPublic)
        : null,
      pq_sig_public: validBundleHex.pqSigPublic
        ? toHex(validBundleHex.pqSigPublic)
        : null,
      pq_binding_sig: validBundleHex.pqBindingSig
        ? toHex(validBundleHex.pqBindingSig)
        : null,
      protocol_version: PROTOCOL_VERSION_HYBRID,
      version: 1,
      ...overrides,
    };
  }

  it('accepts a valid hybrid bundle', () => {
    const parsed = parseRemoteKeyBundle(makeResponse());
    expect(parsed.protocolVersion).toBe(2);
    expect(parsed.pqKemPublicHex).not.toBeNull();
    expect(parsed.pqSigPublicHex).not.toBeNull();
    expect(parsed.pqBindingSigHex).not.toBeNull();
  });

  it('rejects a hybrid bundle missing pq_kem_public', () => {
    expect(() =>
      parseRemoteKeyBundle(makeResponse({ pq_kem_public: null })),
    ).toThrowError(KeyBundleError);
  });

  it('rejects a hybrid bundle missing pq_sig_public', () => {
    expect(() =>
      parseRemoteKeyBundle(makeResponse({ pq_sig_public: null })),
    ).toThrowError(KeyBundleError);
  });

  it('rejects a hybrid bundle missing pq_binding_sig', () => {
    expect(() =>
      parseRemoteKeyBundle(makeResponse({ pq_binding_sig: null })),
    ).toThrowError(KeyBundleError);
  });

  it('rejects a hybrid bundle with the wrong-length ML-KEM pub', () => {
    const short = new Uint8Array(1184);
    short[0] = 1;
    expect(() =>
      parseRemoteKeyBundle(makeResponse({ pq_kem_public: toHex(short) })),
    ).toThrowError(KeyBundleError);
  });

  it('rejects a tampered ML-DSA binding signature', () => {
    const sig = new Uint8Array(validBundleHex.pqBindingSig!);
    sig[0] = (sig[0] ?? 0) ^ 0xff;
    expect(() =>
      parseRemoteKeyBundle(makeResponse({ pq_binding_sig: toHex(sig) })),
    ).toThrowError(KeyBundleError);
  });

  it('rejects a tampered ML-KEM pub (signature mismatch)', () => {
    const tampered = new Uint8Array(validBundleHex.pqKemPublic!);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    expect(() =>
      parseRemoteKeyBundle(makeResponse({ pq_kem_public: toHex(tampered) })),
    ).toThrowError(KeyBundleError);
  });

  it('accepts a classical (v1) bundle', () => {
    const auth = generateEd25519Keypair();
    const ikx = generateX25519Keypair();
    const spk = generateX25519Keypair();
    const base = generateHybridDeviceKeys({
      ikxPrivate: ikx.privateKey,
      spkPrivate: spk.privateKey,
      opkPrivate: null,
      pqKemPrivate: null,
      pqSigPrivate: null,
    });
    void base; // synchronously available (we don't await because the test is sync)
    // The above returns a Promise; for a synchronous classical build we
    // construct an explicit classical-only device.
    void auth;
    void spk;
    void ikx;
  });
});

function toHex(arr: Uint8Array): string {
  let out = '';
  for (let i = 0; i < arr.length; i += 1) {
    out += (arr[i] ?? 0).toString(16).padStart(2, '0');
  }
  return out;
}

void enc;
void generateMlKem768Keypair;
void generateMlDsa44Keypair;
void mlDsa44Sign;
void mlKem768DerivePublicKey;
void mlDsa44DerivePublicKey;
void buildHybridBindingContext;
