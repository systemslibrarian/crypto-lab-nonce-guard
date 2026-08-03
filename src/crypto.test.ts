import { describe, it, expect } from 'vitest';
import {
  generateKey,
  generateNonce,
  encryptSIV,
  encryptGCMNoble,
  xorBytes,
  textToBytes,
  runForbiddenAttack,
  LEVEL2_MAX_CT_BYTES,
} from './crypto.ts';

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

describe('AES-GCM nonce reuse: the confidentiality break is real', () => {
  it('C₁ ⊕ C₂ == P₁ ⊕ P₂ when the nonce is reused (equal-length messages)', () => {
    for (let i = 0; i < 20; i++) {
      const key = generateKey();
      const nonce = generateNonce();
      const p1 = textToBytes('Transfer $1000 to Alice.');
      const p2 = textToBytes('Transfer $9000 Mallory..'); // same length
      expect(p1.length).toBe(p2.length);

      const c1 = encryptGCMNoble(key, nonce, p1).ciphertext;
      const c2 = encryptGCMNoble(key, nonce, p2).ciphertext; // SAME nonce

      // The attacker's recovered value equals the true plaintext XOR.
      expect(hex(xorBytes(c1, c2))).toBe(hex(xorBytes(p1, p2)));
    }
  });

  it('unique nonces defeat the XOR: C₁ ⊕ C₂ ≠ P₁ ⊕ P₂', () => {
    const key = generateKey();
    const p1 = textToBytes('Transfer $1000 to Alice.');
    const p2 = textToBytes('Transfer $9000 Mallory..');
    const c1 = encryptGCMNoble(key, generateNonce(), p1).ciphertext;
    const c2 = encryptGCMNoble(key, generateNonce(), p2).ciphertext;
    expect(hex(xorBytes(c1, c2))).not.toBe(hex(xorBytes(p1, p2)));
  });
});

describe('AES-GCM-SIV nonce misuse resistance', () => {
  it('distinct plaintexts under a reused nonce produce DIFFERENT ciphertexts', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const c1 = encryptSIV(key, nonce, textToBytes('attack at dawn')).ciphertext;
    const c2 = encryptSIV(key, nonce, textToBytes('attack at dusk')).ciphertext;
    expect(hex(c1)).not.toBe(hex(c2));
  });

  it('does NOT leak the plaintext XOR the way GCM does', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const p1 = textToBytes('attack at dawn!!');
    const p2 = textToBytes('attack at dusk!!'); // same length
    const c1 = encryptSIV(key, nonce, p1).ciphertext;
    const c2 = encryptSIV(key, nonce, p2).ciphertext;
    // Ciphertext XOR must NOT equal plaintext XOR (SIV keystream is not reused).
    expect(hex(xorBytes(c1, c2))).not.toBe(hex(xorBytes(p1, p2)));
  });

  it('identical plaintexts under a reused nonce collide (the only leak)', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const pt = textToBytes('the same message');
    const c1 = encryptSIV(key, nonce, pt);
    const c2 = encryptSIV(key, nonce, pt);
    expect(hex(c1.ciphertext)).toBe(hex(c2.ciphertext));
    expect(hex(c1.tag)).toBe(hex(c2.tag));
  });

  it('reusing a nonce across distinct plaintexts yields distinct tags', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const t1 = encryptSIV(key, nonce, textToBytes('message one!!')).tag;
    const t2 = encryptSIV(key, nonce, textToBytes('message two!!')).tag;
    expect(hex(t1)).not.toBe(hex(t2));
  });
});

describe('runForbiddenAttack integration (drives the interactive demo)', () => {
  /** Encrypt both messages under one reused (key, nonce), as the demo does. */
  function observe(key: Uint8Array, nonce: Uint8Array, m1: string, m2: string) {
    const p1 = textToBytes(m1);
    const e1 = encryptGCMNoble(key, nonce, p1);
    const e2 = encryptGCMNoble(key, nonce, textToBytes(m2));
    return { p1, e1, e2 };
  }

  it('recovers H from the learner-supplied messages and lands an accepted forgery', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const { p1, e1, e2 } = observe(
      key,
      nonce,
      'Transfer $1000 to Alice',
      'Wire nine thousand dollars to Mallory instead, quickly',
    );
    const r = runForbiddenAttack(key, nonce, e1.ciphertext, e1.tag, e2.ciphertext, e2.tag, p1);
    expect(r.failure).toBeUndefined();
    // Degree is ceil(len/16)+1 for the longer message: 54 bytes -> 4 blocks -> 5.
    expect(r.equationDegree).toBe(5);
    expect(r.candidateCount).toBeGreaterThanOrEqual(1);
    expect(r.verificationQueries).toBeGreaterThanOrEqual(1);
    expect(r.verificationQueries).toBeLessThanOrEqual(r.candidateCount);
    expect(r.recovered).toBe(true);
    expect(hex(r.recoveredH!)).toBe(hex(r.trueH));
    expect(r.forgeryAccepted).toBe(true);
    // The forged blob decrypts, under the real key, to the attacker's payload.
    expect(hex(r.forgedDecryption!)).toBe(hex(r.forgedPlaintext));
  });

  it('works for messages of unequal length, which the closed-form solver cannot do', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const { p1, e1, e2 } = observe(key, nonce, 'short', 'a considerably longer second message');
    expect(e1.ciphertext.length).not.toBe(e2.ciphertext.length);
    const r = runForbiddenAttack(key, nonce, e1.ciphertext, e1.tag, e2.ciphertext, e2.tag, p1);
    expect(r.recovered).toBe(true);
    expect(r.forgeryAccepted).toBe(true);
  });

  it('reports no-information — not a bogus key — when both messages are identical', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const { p1, e1, e2 } = observe(key, nonce, 'same text', 'same text');
    const r = runForbiddenAttack(key, nonce, e1.ciphertext, e1.tag, e2.ciphertext, e2.tag, p1);
    expect(r.failure).toBe('no-information');
    expect(r.recovered).toBe(false);
    expect(r.forgeryAccepted).toBe(false);
    expect(r.recoveredH).toBeNull();
  });

  it('declines messages past the in-browser root-search budget', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const long = 'x'.repeat(LEVEL2_MAX_CT_BYTES + 1);
    const { p1, e1, e2 } = observe(key, nonce, long, `${long}y`);
    const r = runForbiddenAttack(key, nonce, e1.ciphertext, e1.tag, e2.ciphertext, e2.tag, p1);
    expect(r.failure).toBe('too-long');
    expect(r.forgeryAccepted).toBe(false);
  });
});
