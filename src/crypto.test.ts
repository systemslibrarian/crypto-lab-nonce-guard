import { describe, it, expect } from 'vitest';
import {
  generateKey,
  generateNonce,
  encryptSIV,
  encryptGCMNoble,
  xorBytes,
  textToBytes,
  runForbiddenAttack,
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
  it('recovers H and lands an accepted forgery for the demo key/nonce', () => {
    const key = generateKey();
    const nonce = generateNonce();
    const r = runForbiddenAttack(key, nonce);
    expect(r.recovered).toBe(true);
    expect(hex(r.recoveredH)).toBe(hex(r.trueH));
    expect(r.forgeryAccepted).toBe(true);
  });
});
