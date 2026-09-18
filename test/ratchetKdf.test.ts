import { describe, expect, it } from 'vitest';
import {
  chainStep,
  deriveMessageKey,
  rootChain,
  DR_KDF_INFO,
} from '../src/crypto/ratchetKdf';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';

// All vectors come from the Python reference (protocol.kdf + protocol.ratchet)
// via a deterministic generator using bytes(range(...)) inputs.
const VECTORS = {
  rootInfo: 'secure-messaging-dr-root-v1',
  chainInfo: 'secure-messaging-dr-chain-v1',
  messageInfo: 'secure-messaging-dr-message-v1',

  // root_chain(rk=bytes(1..32), dh=bytes(101..132))
  rootKey: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
  dhOut: '65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384',
  newRoot: 'ac9cbcf60176dd9d18f0f3b75323368871bc80287fe0e8467e86a778be90f1ce',
  firstChain: '5207af9320dc7b5989c66097121d4f4102f83b95fe6793f61eac7269098051ce',

  // chain_step(ck=bytes(201..232))
  chainKey: 'c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8',
  nextChain: '25367826d96147a54e04fd48e9eeb0f303384f11384e7627077f3f5e63d4e581',
  messageKey: '4089f701fdcff216346068299a24f8f949b1158545d475c4f6735dd7cf79cde6',

  // derive_message_key(mk=bytes(33..64), index=0)
  mkInput: '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
  mkIndex0Key: 'f6d6d6c12cd3c18899c389d9916885d5eff99f3730ec44ce07a33ab60d8dbba4',
  mkIndex0Nonce: '8e01049ded3e2ab2aabefa7b',
  // derive_message_key(mk=bytes(33..64), index=1)
  mkIndex1Key: 'acd207b3494618ee0ed8a132c81f6e3ab4eddd6ffaa14e9deaa8ca9d55df1cb4',
  mkIndex1Nonce: '4d35f1ae9be108f19f9e5ee5',
} as const;

describe('DR KDF info strings', () => {
  it('matches the backend reference verbatim', () => {
    expect(DR_KDF_INFO.ROOT_INFO).toBe(VECTORS.rootInfo);
    expect(DR_KDF_INFO.CHAIN_INFO).toBe(VECTORS.chainInfo);
    expect(DR_KDF_INFO.MESSAGE_INFO).toBe(VECTORS.messageInfo);
  });
});

describe('rootChain', () => {
  it('matches the backend pinned output', async () => {
    const rk = hexToBytes(VECTORS.rootKey);
    const dh = hexToBytes(VECTORS.dhOut);
    const out = await rootChain(rk, dh);
    expect(bytesToHex(out.newRoot)).toBe(VECTORS.newRoot);
    expect(bytesToHex(out.firstChain)).toBe(VECTORS.firstChain);
  });
});

describe('chainStep', () => {
  it('matches the backend pinned output', async () => {
    const ck = hexToBytes(VECTORS.chainKey);
    const out = await chainStep(ck);
    expect(bytesToHex(out.nextChain)).toBe(VECTORS.nextChain);
    expect(bytesToHex(out.messageKey)).toBe(VECTORS.messageKey);
  });
});

describe('deriveMessageKey', () => {
  it('matches pinned outputs for index 0 and 1', async () => {
    const mk = hexToBytes(VECTORS.mkInput);
    const a = await deriveMessageKey(mk, 0);
    expect(bytesToHex(a.aesKey)).toBe(VECTORS.mkIndex0Key);
    expect(bytesToHex(a.nonce)).toBe(VECTORS.mkIndex0Nonce);
    const b = await deriveMessageKey(mk, 1);
    expect(bytesToHex(b.aesKey)).toBe(VECTORS.mkIndex1Key);
    expect(bytesToHex(b.nonce)).toBe(VECTORS.mkIndex1Nonce);
  });

  it('binds the index into the info (different indexes produce different nonces)', async () => {
    const mk = hexToBytes(VECTORS.mkInput);
    const a = await deriveMessageKey(mk, 0);
    const b = await deriveMessageKey(mk, 1);
    expect(bytesToHex(a.aesKey)).not.toBe(bytesToHex(b.aesKey));
    expect(bytesToHex(a.nonce)).not.toBe(bytesToHex(b.nonce));
  });

  it('rejects negative indexes', async () => {
    await expect(deriveMessageKey(new Uint8Array(32), -1)).rejects.toThrow();
  });
});
