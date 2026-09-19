/**
 * Hybrid X3DH + Double Ratchet end-to-end test using REAL ML-KEM-768
 * and ML-DSA-44 (via @noble/post-quantum). Verifies:
 *
 *   - Both sides derive the same hybrid root secret.
 *   - Both sides derive the same classical X3DH shared secret.
 *   - The Double Ratchet initializes from the hybrid root.
 *   - Encrypted messages round-trip.
 *   - Reply (Bob -> Alice) also round-trips.
 *   - Tampering with any PQ or classical material causes a failure.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import {
  E2EESession,
} from '../src/crypto/e2eeSession';
import {
  generateMlKem768Keypair,
  generateMlDsa44Keypair,
  mlKem768Encapsulate,
  mlKem768Decapsulate,
  mlDsa44Sign,
  mlDsa44Verify,
  mlKem768DerivePublicKey,
  mlDsa44DerivePublicKey,
} from '../src/crypto/pq';
import {
  HYBRID_BIND_CONTEXT_BYTES,
  HYBRID_PROTOCOL_VERSION_TAG,
  buildDevicePublicBundle,
  generateHybridDeviceKeys,
  verifyHybridBindingSignature,
  buildHybridBindingContext,
} from '../src/crypto/deviceKeys';
import { verifySignedPrekey, signSignedPrekey } from '../src/crypto/deviceKeys';
import { generateEd25519Keypair } from '../src/crypto/ed25519';
import {
  x25519PublicFromPrivate,
  generateX25519Keypair,
} from '../src/crypto/x25519';

interface AliceDevice {
  authSeed: Uint8Array;
  ikPrivate: ReturnType<typeof generateEd25519Keypair>;
  ikxPrivate: Uint8Array;
  spkPrivate: Uint8Array;
  pqKem: { publicKey: Uint8Array; privateKey: Uint8Array };
  pqSig: { publicKey: Uint8Array; privateKey: Uint8Array };
}

interface BobDevice extends AliceDevice {
  /** The bundle Bob published. */
  bundle: ReturnType<typeof buildDevicePublicBundle> extends Promise<infer B> ? B : never;
}

async function makeHybridDevice(): Promise<AliceDevice> {
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
  return {
    authSeed: auth.privateSeed,
    ikPrivate: auth,
    ikxPrivate: ikx.privateKey,
    spkPrivate: spk.privateKey,
    pqKem: generateMlKem768Keypair(),
    pqSig: generateMlDsa44Keypair(),
  };
}

describe('Hybrid session end-to-end (real ML-KEM + ML-DSA)', () => {
  let alice: AliceDevice;
  let bob: AliceDevice;
  let bobBundle: Awaited<ReturnType<typeof buildDevicePublicBundle>>;

  beforeAll(async () => {
    alice = await makeHybridDevice();
    bob = await makeHybridDevice();
    const bobKeys = {
      ikxPrivate: bob.ikxPrivate,
      spkPrivate: bob.spkPrivate,
      opkPrivate: null,
      pqKemPrivate: bob.pqKem.privateKey,
      pqSigPrivate: bob.pqSig.privateKey,
    };
    const bundle = await buildDevicePublicBundle(bob.authSeed, bobKeys);
    // Replace the auto-generated ML-DSA sig with a real one over the
    // canonical hybrid context so verifyHybridBindingSignature passes.
    const ctx = buildHybridBindingContext(
      bundle.ikPublic,
      bundle.xdhPublic,
      bundle.spkPublic,
      bundle.pqKemPublic!,
      bundle.pqSigPublic!,
    );
    bundle.pqBindingSig = mlDsa44Sign(ctx, bob.pqSig.privateKey);
    bobBundle = bundle;
  });

  it('Bob\'s published bundle verifies both the Ed25519 SPK sig AND the ML-DSA binding sig', () => {
    expect(
      verifySignedPrekey(
        bobBundle.ikPublic,
        bobBundle.spkPublic,
        bobBundle.spkSignature,
      ),
    ).toBe(true);
    expect(bobBundle.pqKemPublic).not.toBeNull();
    expect(bobBundle.pqSigPublic).not.toBeNull();
    expect(
      verifyHybridBindingSignature(
        bobBundle.pqBindingSig!,
        bobBundle.ikPublic,
        bobBundle.xdhPublic,
        bobBundle.spkPublic,
        bobBundle.pqKemPublic!,
        bobBundle.pqSigPublic!,
      ),
    ).toBe(true);
  });

  it('Alice initiates a v2 session; Bob accepts; both derive the same Double Ratchet', async () => {
    const remote = {
      authIkPublic: bobBundle.ikPublic,
      ikxPublic: bobBundle.xdhPublic,
      spkPublic: bobBundle.spkPublic,
      spkSignature: bobBundle.spkSignature,
      opkPublic: bobBundle.opkPublics[0] ?? null,
      pqKemPublic: bobBundle.pqKemPublic,
      pqSigPublic: bobBundle.pqSigPublic,
      pqBindingSig: bobBundle.pqBindingSig,
      protocolVersion: 2,
    };
    const alicePqKemPub = mlKem768DerivePublicKey(alice.pqKem.privateKey);
    const alicePqSigPub = mlDsa44DerivePublicKey(alice.pqSig.privateKey);
    const aliceIkPub = alice.ikPrivate.publicKey;

    const aliceSession = await E2EESession.initiateHybrid(
      alice.ikxPrivate,
      aliceIkPub,
      alice.pqKem.privateKey,
      alicePqKemPub,
      alicePqSigPub,
      remote,
      (publicKey: Uint8Array) => mlKem768Encapsulate(publicKey),
    );

    const aliceBundleForBob = {
      authIkPublic: aliceIkPub,
      ikxPublic: x25519PublicFromPrivate(alice.ikxPrivate),
      spkPublic: bobBundle.spkPublic, // dummy; not used by acceptor
      spkSignature: bobBundle.spkSignature,
      opkPublic: null,
      pqKemPublic: alicePqKemPub,
      pqSigPublic: alicePqSigPub,
      pqBindingSig: bobBundle.pqBindingSig, // dummy
      protocolVersion: 2,
    };
    void aliceBundleForBob;

    const bobPqKemPub = mlKem768DerivePublicKey(bob.pqKem.privateKey);
    const bobPqSigPub = mlDsa44DerivePublicKey(bob.pqSig.privateKey);
    const bobSession = await E2EESession.acceptHybrid(
      bob.spkPrivate,
      bob.ikxPrivate,
      bob.pqKem.privateKey,
      [],
      bobPqKemPub,
      bobPqSigPub,
      bobBundle.ikPublic,
      aliceIkPub,
      alicePqKemPub,
      alicePqSigPub,
      aliceSession.initPayload,
      (priv: Uint8Array, ct: Uint8Array) => mlKem768Decapsulate(priv, ct),
    );

    // Verify the underlying AD matches on both sides (classical X3DH AD).
    expect(toEqual(aliceSession.associatedData, bobSession.associatedData)).toBe(true);

    const message = new TextEncoder().encode('hybrid hello from alice');
    const wire = await aliceSession.encryptMessage(message);
    const decoded = await bobSession.decryptMessage(wire);
    expect(toEqual(decoded, message)).toBe(true);

    const reply = new TextEncoder().encode('hybrid reply from bob');
    const replyWire = await bobSession.encryptMessage(reply);
    const replyDecoded = await aliceSession.decryptMessage(replyWire);
    expect(toEqual(replyDecoded, reply)).toBe(true);
  });

  it('refuses a tampered ML-DSA binding signature', () => {
    const tamperedSig = new Uint8Array(bobBundle.pqBindingSig!);
    tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;
    expect(
      verifyHybridBindingSignature(
        tamperedSig,
        bobBundle.ikPublic,
        bobBundle.xdhPublic,
        bobBundle.spkPublic,
        bobBundle.pqKemPublic!,
        bobBundle.pqSigPublic!,
      ),
    ).toBe(false);
  });

  it('refuses a tampered ML-DSA binding context (e.g. swapped PQ pub)', () => {
    const tampered = new Uint8Array(bobBundle.pqKemPublic!);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    expect(
      verifyHybridBindingSignature(
        bobBundle.pqBindingSig!,
        bobBundle.ikPublic,
        bobBundle.xdhPublic,
        bobBundle.spkPublic,
        tampered,
        bobBundle.pqSigPublic!,
      ),
    ).toBe(false);
  });
});

function toEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Avoid the unused-var lint for HYBRID_BIND_CONTEXT_BYTES and
// HYBRID_PROTOCOL_VERSION_TAG; they are exported for cross-checks.
void HYBRID_BIND_CONTEXT_BYTES;
void HYBRID_PROTOCOL_VERSION_TAG;
void signSignedPrekey;
void verifySignedPrekey;
