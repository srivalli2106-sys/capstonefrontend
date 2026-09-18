import { describe, expect, it } from 'vitest';
import { isValidMessageId, newMessageId } from '../src/realtime/messageId';

describe('ULID-style message ids', () => {
  it('produces 26-character Crockford base32 ids', () => {
    const id = newMessageId();
    expect(id.length).toBe(26);
    expect(isValidMessageId(id)).toBe(true);
    expect(id).toMatch(/^[0-9A-Z]{26}$/);
  });

  it('the timestamp prefix is monotonically non-decreasing', () => {
    const ids = Array.from({ length: 5 }, () => newMessageId());
    for (let i = 1; i < ids.length; i += 1) {
      const prev = ids[i - 1]!.slice(0, 10);
      const curr = ids[i]!.slice(0, 10);
      expect(curr >= prev).toBe(true);
    }
  });

  it('produces distinct ids (random suffix entropy)', () => {
    const set = new Set<string>();
    for (let i = 0; i < 100; i += 1) set.add(newMessageId());
    expect(set.size).toBe(100);
  });

  it('rejects malformed ids', () => {
    expect(isValidMessageId('short')).toBe(false);
    expect(isValidMessageId('x'.repeat(27))).toBe(false);
    // 'I', 'L', 'O', 'U' are not part of Crockford base32.
    expect(isValidMessageId('ILOU' + '0'.repeat(22))).toBe(false);
    expect(isValidMessageId('0123456789ABCDEFGHJKMNPQRSTVWXY')).toBe(false);
  });
});
