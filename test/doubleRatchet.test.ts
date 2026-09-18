import { describe, expect, it } from 'vitest';
import {
  HEADER_SIZE,
  MAX_SKIP,
  RATCHET_MESSAGE_VERSION,
  DecryptionError,
  DoubleRatchet,
  RatchetError,
  packHeader,
  packMessage,
  unpackHeader,
} from '../src/crypto/doubleRatchet';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';
import { dhX25519, x25519PublicFromPrivate } from '../src/crypto/x25519';
import {
  buildDevicePublicBundle,
  type DeviceKeysPrivate,
} from '../src/crypto/deviceKeys';
import {
  x3dhInitiate as x3dhInitiateModule,
  type RemotePublicBundle,
} from '../src/crypto/x3dh';
import { E2EESession as E2EESessionModule } from '../src/crypto/e2eeSession';
function block32(start: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = (start + i) % 256;
  return out;
}

// Deterministic ephemeral sequence for the tests. MUST produce distinct
// clamped X25519 scalars (noble clamps bits 0-2 to 0 and sets bits 254-255),
// so we encode the counter in bytes 3..6 (the unclamped middle range).
function deterministicKey(i: number): Uint8Array {
  const out = new Uint8Array(32);
  out[3] = i & 0xff;
  out[4] = (i >> 8) & 0xff;
  out[5] = (i >> 16) & 0xff;
  out[6] = (i >> 24) & 0xff;
  // Pre-set the high bits noble will force anyway.
  out[31] = 0xc0;
  return out;
}

let ephemeralCursor = 0;
function ephemeralSource(): Uint8Array {
  const k = deterministicKey(ephemeralCursor);
  ephemeralCursor += 1;
  return k;
}

const AD = new Uint8Array(64).fill(0x42); // 64-byte session AD stand-in

interface Pair {
  alice: DoubleRatchet;
  bob: DoubleRatchet;
}

async function buildPair(seedKey: Uint8Array, maxSkip = 1000): Promise<Pair> {
  // We reuse a single ephemeral source so the tests are deterministic.
  ephemeralCursor = 0;
  const alicePriv = block32(1);
  const bobPriv = block32(33);
  const bobPub = x25519PublicFromPrivate(bobPriv);
  const { newRoot, firstChain } = await (
    await import('../src/crypto/ratchetKdf')
  ).rootChain(seedKey, dhX25519(alicePriv, bobPub));
  const alice = await DoubleRatchet.create({
    rootKey: newRoot,
    startChain: firstChain,
    localDhPrivate: alicePriv,
    remoteDh: bobPub,
    initiator: true,
    options: { randomPrivateKey: ephemeralSource, maxSkip },
  });
  const bob = await DoubleRatchet.create({
    rootKey: newRoot,
    startChain: firstChain,
    localDhPrivate: bobPriv,
    remoteDh: x25519PublicFromPrivate(alicePriv),
    initiator: false,
    options: { randomPrivateKey: ephemeralSource, maxSkip },
  });
  return { alice, bob };
}

describe('DoubleRatchet header', () => {
  it('produces 41-byte header with version=1', () => {
    const header = packHeader({
      version: RATCHET_MESSAGE_VERSION,
      dh: new Uint8Array(32).fill(0x55),
      pn: 7,
      n: 12,
    });
    expect(header.length).toBe(HEADER_SIZE);
    expect(header[0]).toBe(1);
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    expect(view.getUint32(33, false)).toBe(7);
    expect(view.getUint32(37, false)).toBe(12);
    const parsed = unpackHeader(header);
    expect(parsed.version).toBe(1);
    expect(parsed.pn).toBe(7);
    expect(parsed.n).toBe(12);
    expect(bytesToHex(parsed.dh)).toBe(bytesToHex(new Uint8Array(32).fill(0x55)));
  });

  it('rejects wrong-length header', () => {
    expect(() => unpackHeader(new Uint8Array(HEADER_SIZE - 1))).toThrow(RatchetError);
  });

  it('rejects unsupported header version', () => {
    const bad = new Uint8Array(HEADER_SIZE);
    bad[0] = 99;
    expect(() => unpackHeader(bad)).toThrow(/version/);
  });

  it('rejects wrong-length message', () => {
    expect(() => packMessage(
      { version: 1, dh: new Uint8Array(32), pn: 0, n: 0 },
      new Uint8Array(10), // < 16 (16 = AES tag min)
    )).toThrow(RatchetError);
  });
});

describe('DoubleRatchet: initiator -> responder', () => {
  it('the first message round-trips', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const wire = await alice.encryptMessage(new TextEncoder().encode('hello bob'), AD);
    const out = await bob.decryptMessage(wire, AD);
    expect(new TextDecoder().decode(out)).toBe('hello bob');
  });

  it('responder reply decrypts by initiator (DH turn)', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const a1 = await alice.encryptMessage(new TextEncoder().encode('init'), AD);
    await bob.decryptMessage(a1, AD);
    const b1 = await bob.encryptMessage(new TextEncoder().encode('reply'), AD);
    const pt = await alice.decryptMessage(b1, AD);
    expect(new TextDecoder().decode(pt)).toBe('reply');
  });

  it('alternating turns stay in sync', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    for (let i = 0; i < 5; i += 1) {
      const a = await alice.encryptMessage(new TextEncoder().encode(`A${i}`), AD);
      expect(new TextDecoder().decode(await bob.decryptMessage(a, AD))).toBe(`A${i}`);
      const b = await bob.encryptMessage(new TextEncoder().encode(`B${i}`), AD);
      expect(new TextDecoder().decode(await alice.decryptMessage(b, AD))).toBe(`B${i}`);
    }
  });

  it('handles batches before and after ratchet turns', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const batchA: Uint8Array[] = [];
    for (let i = 0; i < 4; i += 1) {
      batchA.push(await alice.encryptMessage(new TextEncoder().encode(`${i}`), AD));
    }
    for (let i = 0; i < batchA.length; i += 1) {
      const out = await bob.decryptMessage(batchA[i] as Uint8Array, AD);
      expect(new TextDecoder().decode(out)).toBe(`${i}`);
    }
    const bReply = await bob.encryptMessage(new TextEncoder().encode('x'), AD);
    expect(new TextDecoder().decode(await alice.decryptMessage(bReply, AD))).toBe('x');

    const batchA2: Uint8Array[] = [];
    for (let i = 0; i < 4; i += 1) {
      batchA2.push(await alice.encryptMessage(new TextEncoder().encode(`${i}`), AD));
    }
    for (let i = 0; i < batchA2.length; i += 1) {
      const out = await bob.decryptMessage(batchA2[i] as Uint8Array, AD);
      expect(new TextDecoder().decode(out)).toBe(`${i}`);
    }
  });
});

describe('DoubleRatchet: out-of-order, replay, tamper', () => {
  it('out-of-order messages decrypt via skip buffer', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const init = await alice.encryptMessage(new TextEncoder().encode('init'), AD);
    await bob.decryptMessage(init, AD);
    const replies: Uint8Array[] = [];
    for (let i = 0; i < 4; i += 1) {
      replies.push(
        await bob.encryptMessage(new TextEncoder().encode(`m${i}`), AD),
      );
    }
    expect(new TextDecoder().decode(await alice.decryptMessage(replies[2] as Uint8Array, AD))).toBe('m2');
    expect(new TextDecoder().decode(await alice.decryptMessage(replies[1] as Uint8Array, AD))).toBe('m1');
    expect(new TextDecoder().decode(await alice.decryptMessage(replies[0] as Uint8Array, AD))).toBe('m0');
    expect(new TextDecoder().decode(await alice.decryptMessage(replies[3] as Uint8Array, AD))).toBe('m3');
  });

  it('rejects replayed (already-decrypted) message', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const wire = await alice.encryptMessage(new TextEncoder().encode('once'), AD);
    expect(new TextDecoder().decode(await bob.decryptMessage(wire, AD))).toBe('once');
    await expect(bob.decryptMessage(wire, AD)).rejects.toMatchObject({ code: 'replayed' });
  });

  it('rejects tampered ciphertext', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const wire = await alice.encryptMessage(new TextEncoder().encode('message'), AD);
    const tampered = new Uint8Array(wire);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;
    await expect(bob.decryptMessage(tampered, AD)).rejects.toMatchObject({ code: 'auth_failed' });
  });

  it('rejects tampered header', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const wire = await alice.encryptMessage(new TextEncoder().encode('message'), AD);
    const parsed = unpackHeader(wire.slice(0, HEADER_SIZE));
    const dh = new Uint8Array(parsed.dh);
    dh[0] = (dh[0] ?? 0) ^ 0x01;
    const forgedHeader = packHeader({ version: 1, dh, pn: parsed.pn, n: parsed.n });
    const forged = new Uint8Array(wire);
    forged.set(forgedHeader, 0);
    await expect(bob.decryptMessage(forged, AD)).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejects wrong associated data', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const wire = await alice.encryptMessage(new TextEncoder().encode('secret'), AD);
    const wrongAd = new Uint8Array(64).fill(0x99);
    await expect(bob.decryptMessage(wire, wrongAd)).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('DoubleRatchet: malformed input', () => {
  it('rejects too-short wire messages', async () => {
    const { bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    await expect(bob.decryptMessage(new Uint8Array(0), AD)).rejects.toBeInstanceOf(RatchetError);
    await expect(bob.decryptMessage(new Uint8Array(HEADER_SIZE + 15), AD)).rejects.toBeInstanceOf(RatchetError);
  });

  it('rejects unsupported message version', async () => {
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const wire = await alice.encryptMessage(new TextEncoder().encode('x'), AD);
    const bad = new Uint8Array(wire);
    bad[0] = 0x63;
    await expect(bob.decryptMessage(bad, AD)).rejects.toThrow(/version/);
  });

  it('rejects message index too far ahead', async () => {
    ephemeralCursor = 0;
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const a1 = await alice.encryptMessage(new TextEncoder().encode('init'), AD);
    await bob.decryptMessage(a1, AD);
    const bReply = await bob.encryptMessage(new TextEncoder().encode('reply'), AD);
    await alice.decryptMessage(bReply, AD);
    // Same DH turn, but n > nr + max_skip.
    const alicePub = alice.localPublic;
    const tooFar = (alice as unknown as { _nr: number })._nr + MAX_SKIP + 1;
    const forged = packMessage(
      { version: 1, dh: alicePub, pn: 0, n: tooFar },
      new Uint8Array(16),
    );
    await expect(bob.decryptMessage(forged, AD)).rejects.toMatchObject({ code: 'too_far_ahead' });
  });

  it('rejects excessive skip on ratchet (pre-skip overflow)', async () => {
    ephemeralCursor = 0;
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const a1 = await alice.encryptMessage(new TextEncoder().encode('init'), AD);
    await bob.decryptMessage(a1, AD);
    const bReply = await bob.encryptMessage(new TextEncoder().encode('reply'), AD);
    await alice.decryptMessage(bReply, AD);
    const fresh = x25519PublicFromPrivate(block32(123));
    const forged = packMessage(
      { version: 1, dh: fresh, pn: 5_000_000, n: 0 },
      new Uint8Array(16),
    );
    await expect(alice.decryptMessage(forged, AD)).rejects.toMatchObject({ code: 'skip_bound' });
  });

  it('rejects skip buffer overflow when max_skip=1', async () => {
    ephemeralCursor = 0;
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e), 1);
    const a1 = await alice.encryptMessage(new TextEncoder().encode('init'), AD);
    await bob.decryptMessage(a1, AD);
    const bReply = await bob.encryptMessage(new TextEncoder().encode('reply'), AD);
    await alice.decryptMessage(bReply, AD);
    // Hand-set up so the next pre-skip overflows. The skipKey format is
    // hex(remote || u32BE(index)) so we mirror that for the dummy entry.
    const aliceState = alice as unknown as {
      _nr: number;
      _skipped: Map<string, Uint8Array>;
    };
    aliceState._nr = 5;
    const dummyKey = '00'.repeat(32) + '00000006';
    aliceState._skipped.set(dummyKey, new Uint8Array(32));
    const fresh = x25519PublicFromPrivate(block32(99));
    const forged = packMessage(
      { version: 1, dh: fresh, pn: 6, n: 0 },
      new Uint8Array(16),
    );
    await expect(alice.decryptMessage(forged, AD)).rejects.toMatchObject({ code: 'skip_buffer_exhausted' });
  });

  it('rejects send without a remote ratchet key', async () => {
    ephemeralCursor = 0;
    const seedKey = new Uint8Array(32).fill(0x5e);
    const alicePriv = block32(1);
    const bobPriv = block32(33);
    const bobPub = x25519PublicFromPrivate(bobPriv);
    const { newRoot, firstChain } = await (
      await import('../src/crypto/ratchetKdf')
    ).rootChain(seedKey, dhX25519(alicePriv, bobPub));
    const orphan = await DoubleRatchet.create({
      rootKey: newRoot,
      startChain: firstChain,
      localDhPrivate: alicePriv,
      remoteDh: null as unknown as Uint8Array,
      initiator: false,
      options: { randomPrivateKey: ephemeralSource },
    });
    await expect(orphan.encryptMessage(new Uint8Array(1), AD)).rejects.toMatchObject({ code: 'no_remote' });
  });
});

describe('DoubleRatchet: state export/import', () => {
  it('preserves conversation state across import', async () => {
    ephemeralCursor = 0;
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const out1 = await alice.encryptMessage(new TextEncoder().encode('first'), AD);
    expect(new TextDecoder().decode(await bob.decryptMessage(out1, AD))).toBe('first');

    const out2 = await alice.encryptMessage(new TextEncoder().encode('second'), AD);
    const aliceExported = alice.exportState();
    const bobExported = bob.exportState();

    const alice2 = DoubleRatchet.fromStateBytes(aliceExported);
    const bob2 = DoubleRatchet.fromStateBytes(bobExported);

    expect(new TextDecoder().decode(await bob2.decryptMessage(out2, AD))).toBe('second');
    const reply = await bob2.encryptMessage(new TextEncoder().encode('back'), AD);
    expect(new TextDecoder().decode(await alice2.decryptMessage(reply, AD))).toBe('back');

    // Original instances remain independently usable.
    const after = await bob.encryptMessage(new TextEncoder().encode('still-live'), AD);
    expect(new TextDecoder().decode(await alice.decryptMessage(after, AD))).toBe('still-live');
  });

  it('preserves skipped keys across export/import', async () => {
    ephemeralCursor = 0;
    const { alice, bob } = await buildPair(new Uint8Array(32).fill(0x5e));
    const init = await alice.encryptMessage(new TextEncoder().encode('init'), AD);
    await bob.decryptMessage(init, AD);
    const replies: Uint8Array[] = [];
    for (let i = 0; i < 4; i += 1) {
      replies.push(
        await bob.encryptMessage(new TextEncoder().encode(`${i}`), AD),
      );
    }
    // Receive out of order: 2 first → 0/1/3 are skipped.
    expect(new TextDecoder().decode(await alice.decryptMessage(replies[2] as Uint8Array, AD))).toBe('2');

    const alice2 = DoubleRatchet.fromStateBytes(alice.exportState());
    const bob2 = DoubleRatchet.fromStateBytes(bob.exportState());

    expect(new TextDecoder().decode(await alice2.decryptMessage(replies[0] as Uint8Array, AD))).toBe('0');
    expect(new TextDecoder().decode(await alice2.decryptMessage(replies[1] as Uint8Array, AD))).toBe('1');
    expect(new TextDecoder().decode(await alice2.decryptMessage(replies[3] as Uint8Array, AD))).toBe('3');
    const postRestore = await bob2.encryptMessage(new TextEncoder().encode('post-restore'), AD);
    expect(new TextDecoder().decode(await alice2.decryptMessage(postRestore, AD))).toBe('post-restore');
  });

  it('rejects malformed state bytes', () => {
    expect(() => DoubleRatchet.fromStateBytes(new Uint8Array(10))).toThrow(/malformed/);
    // Wrong version (valid header but version != 1).
    const aliceStub = block32(1);
    const bobStub = block32(33);
    const validHeader = new Uint8Array(115);
    validHeader[0] = 0; // wrong version
    validHeader.set(aliceStub, 34); // local_priv
    validHeader.set(x25519PublicFromPrivate(bobStub), 66); // remote_dh
    validHeader.set(new Uint8Array(32), 2); // rk
    expect(() => DoubleRatchet.fromStateBytes(validHeader)).toThrow(/version/);
  });

  it('wipes secret-bearing buffers', async () => {
    ephemeralCursor = 0;
    const { alice } = await buildPair(new Uint8Array(32).fill(0x5e));
    await alice.encryptMessage(new Uint8Array(16), AD);
    expect(alice.isWiped).toBe(false);
    alice.wipe();
    expect(alice.isWiped).toBe(true);
    await expect(alice.encryptMessage(new Uint8Array(1), AD)).rejects.toThrow();
  });
});

describe('DoubleRatchet: deterministic byte vectors (full pinned exchange)', () => {
  it('matches the Python reference pinned output', async () => {
    ephemeralCursor = 0;
    // Deterministic inputs.
    const IKX_A_PRIV = block32(1);
    const EK_A_PRIV = block32(129);
    const IKX_B_PRIV = block32(33);
    const SPK_B_PRIV = block32(65);
    const OPK_B_PRIV = block32(97);
    const AUTH_SEED_A = block32(200);
    const AUTH_SEED_B = block32(232);

    // Bob's SPK signature is built by the deviceKeys module using the fixed
    // auth seed; reuse the Phase 5 helper.
    const { buildDevicePublicBundle } = await import('../src/crypto/deviceKeys');
    const bobDevice = { ikxPrivate: IKX_B_PRIV, spkPrivate: SPK_B_PRIV, opkPrivate: OPK_B_PRIV };
    const aliceDevice = { ikxPrivate: IKX_A_PRIV, spkPrivate: block32(229), opkPrivate: null };
    const alicePub = (await import('../src/crypto/ed25519')).publicKeyFromPrivateSeed(AUTH_SEED_A);
    const bobBundle = buildDevicePublicBundle(AUTH_SEED_B, bobDevice);
    const aliceBundle = buildDevicePublicBundle(AUTH_SEED_A, aliceDevice);

    const remote: RemotePublicBundle = {
      authIkPublic: alicePub, // intentionally the WRONG auth so we know the ratchet key path is correct
      ikxPublic: x25519PublicFromPrivate(IKX_B_PRIV),
      spkPublic: bobBundle.spkPublic,
      spkSignature: bobBundle.spkSignature,
      opkPublic: bobBundle.opkPublics[0] as Uint8Array,
    };
    // Use the correct bobBundle.authIk for signature verification.
    remote.authIkPublic = bobBundle.ikPublic;

    const init = await x3dhInitiateModule(IKX_A_PRIV, remote, {
      ephemeralPrivateKey: EK_A_PRIV,
    });
    expect(bytesToHex(init.sharedSecret)).toBe(
      '3e14176e1b52478848696c849fdec4ed229cbe9c8b676b418b44c417361820b1',
    );
    expect(bytesToHex(init.associatedData)).toBe(
      '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c' +
        '5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b',
    );
    expect(bytesToHex(init.initPayload)).toBe(
      '0107a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c' +
        '883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c7700',
    );

    // Inject the exact ephemeral key the Python vector script used
    // (`bytes(161..193)`); the monkey-patched Python `generate()` returned
    // the same value for every call (both bob's first send AND alice's
    // DH-ratchet). Mirror that here so the pinned outputs match.
    const BOB_REPLY_PRIV = block32(161);
    const deterministicRng = (): Uint8Array => BOB_REPLY_PRIV;

    const aliceSession = await E2EESessionModule.initiate(IKX_A_PRIV, remote, {
      ephemeralPrivateKey: EK_A_PRIV,
      randomPrivateKey: deterministicRng,
    });
    const bobSession = await E2EESessionModule.accept(
      SPK_B_PRIV,
      IKX_B_PRIV,
      x25519PublicFromPrivate(IKX_B_PRIV),
      [OPK_B_PRIV],
      init.initPayload,
      { randomPrivateKey: deterministicRng },
    );

    const wire1 = await aliceSession.encryptMessage(new TextEncoder().encode('hello bob'), new Uint8Array(0));
    expect(bytesToHex(wire1.slice(1, 33))).toBe(
      '883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c77',
    );
    expect(new DataView(wire1.buffer, wire1.byteOffset + 33, 4).getUint32(0, false)).toBe(0);
    expect(new DataView(wire1.buffer, wire1.byteOffset + 37, 4).getUint32(0, false)).toBe(0);
    expect(bytesToHex(wire1.slice(HEADER_SIZE))).toBe(
      '4ec91919675c9b0f1cb7be86f5ff15ff742770c042fce0e847',
    );

    const pt1 = await bobSession.decryptMessage(wire1, new Uint8Array(0));
    expect(new TextDecoder().decode(pt1)).toBe('hello bob');

    // Bob's reply uses the injected deterministic ephemeral (counter=0).
    const wire2 = await bobSession.encryptMessage(new TextEncoder().encode('hi alice'), new Uint8Array(0));
    expect(bytesToHex(wire2.slice(1, 33))).toBe(
      'ad438bfae31f6c093d61d4339255ea798092c9fadd07b97827f4b0ae9dee7c1c',
    );
    expect(bytesToHex(wire2.slice(HEADER_SIZE))).toBe(
      'f20c74f534fb837712d9e0360ed5f519768f106aa6bdc848',
    );

    const pt2 = await aliceSession.decryptMessage(wire2, new Uint8Array(0));
    expect(new TextDecoder().decode(pt2)).toBe('hi alice');

    // The third exchange uses an OS-random ephemeral for alice's DH ratchet
    // (the Python reference does not monkey-patch that step), so the wire
    // header/ciphertext cannot be pinned — but the protocol still must
    // round-trip correctly.
    const wire3 = await aliceSession.encryptMessage(new TextEncoder().encode('how are you?'), new Uint8Array(0));
    expect(wire3.length).toBeGreaterThan(HEADER_SIZE + 16);
    const pt3 = await bobSession.decryptMessage(wire3, new Uint8Array(0));
    expect(new TextDecoder().decode(pt3)).toBe('how are you?');
    void aliceBundle;
  });
});
