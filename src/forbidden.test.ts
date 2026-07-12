import { describe, it, expect } from 'vitest';
import { gcm, unsafe } from '@noble/ciphers/aes.js';
import { recoverGhashKey, forgeTag, ghashH } from './forbidden.ts';
import { bytesToField, fieldToBytes } from './gf128.ts';

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** True GHASH key H = AES-256(key, 0¹²⁸) (NIST SP 800-38D §6.3). */
function trueH(key: Uint8Array): Uint8Array {
  const block = new Uint8Array(16);
  unsafe.encryptBlock(unsafe.expandKeyLE(key), block);
  return block;
}

function gcmEncrypt(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array) {
  const out = gcm(key, nonce).encrypt(pt);
  return { ct: out.slice(0, out.length - 16), tag: out.slice(out.length - 16) };
}

describe("Joux's forbidden attack recovers the GHASH key H", () => {
  it('recovered H exactly equals the true H over random keys/nonces', () => {
    for (let i = 0; i < 30; i++) {
      const key = randBytes(32);
      const nonce = randBytes(12);
      const p1 = randBytes(16);
      let p2 = randBytes(16);
      if (hex(p1) === hex(p2)) p2 = randBytes(16);

      const e1 = gcmEncrypt(key, nonce, p1);
      const e2 = gcmEncrypt(key, nonce, p2);

      // Attack sees ONLY (ciphertext, tag) pairs.
      const { H } = recoverGhashKey(e1.ct, e1.tag, e2.ct, e2.tag);
      expect(hex(H)).toBe(hex(trueH(key)));
    }
  });

  it('needs a real nonce collision: unique nonces do NOT recover H', () => {
    const key = randBytes(32);
    const e1 = gcmEncrypt(key, randBytes(12), randBytes(16));
    const e2 = gcmEncrypt(key, randBytes(12), randBytes(16));
    // Different nonces -> different masks; the solver returns a wrong H.
    const { H } = recoverGhashKey(e1.ct, e1.tag, e2.ct, e2.tag);
    expect(hex(H)).not.toBe(hex(trueH(key)));
  });

  it('rejects identical ciphertexts (no information)', () => {
    const key = randBytes(32);
    const nonce = randBytes(12);
    const pt = randBytes(16);
    const e = gcmEncrypt(key, nonce, pt);
    expect(() => recoverGhashKey(e.ct, e.tag, e.ct, e.tag)).toThrow();
  });

  it('rejects unequal-length ciphertexts', () => {
    const key = randBytes(32);
    const nonce = randBytes(12);
    const a = gcmEncrypt(key, nonce, randBytes(16));
    const b = gcmEncrypt(key, nonce, randBytes(8));
    expect(() => recoverGhashKey(a.ct, a.tag, b.ct, b.tag)).toThrow();
  });
});

describe('Forged tags are accepted by the REAL AES-GCM primitive', () => {
  it('forges a valid (ciphertext, tag) for an attacker-chosen message', () => {
    for (let i = 0; i < 20; i++) {
      const key = randBytes(32);
      const nonce = randBytes(12);
      const e1 = gcmEncrypt(key, nonce, randBytes(16));
      const e2 = gcmEncrypt(key, nonce, randBytes(16));
      const recovered = recoverGhashKey(e1.ct, e1.tag, e2.ct, e2.tag);

      // Choose an arbitrary-length forged plaintext, build genuine ciphertext.
      const forgedPt = new TextEncoder().encode('attacker chose this #' + i);
      const ks = gcmEncrypt(key, nonce, new Uint8Array(forgedPt.length)).ct; // E(0)
      const forgedCt = forgedPt.map((x, j) => x ^ ks[j]);
      const forgedTag = forgeTag(recovered, forgedCt);

      const blob = new Uint8Array(forgedCt.length + 16);
      blob.set(forgedCt, 0);
      blob.set(forgedTag, forgedCt.length);

      // The real decryptor must ACCEPT and return the attacker's plaintext.
      const dec = gcm(key, nonce).decrypt(blob);
      expect(hex(dec)).toBe(hex(forgedPt));
    }
  });

  it('a wrong (non-recovered) tag is rejected — the break is real, not trivial', () => {
    const key = randBytes(32);
    const nonce = randBytes(12);
    const forgedCt = new TextEncoder().encode('sixteen byte data');
    const bogusTag = randBytes(16);
    const blob = new Uint8Array(forgedCt.length + 16);
    blob.set(forgedCt, 0);
    blob.set(bogusTag, forgedCt.length);
    expect(() => gcm(key, nonce).decrypt(blob)).toThrow();
  });
});

describe('ghashH sanity', () => {
  it('is a genuine polynomial in H: mask cancels across two same-nonce tags', () => {
    const key = randBytes(32);
    const nonce = randBytes(12);
    const e1 = gcmEncrypt(key, nonce, randBytes(16));
    const e2 = gcmEncrypt(key, nonce, randBytes(16));
    const H = bytesToField(trueH(key));
    const dTag = bytesToField(e1.tag) ^ bytesToField(e2.tag);
    const dGhash = ghashH(H, e1.ct) ^ ghashH(H, e2.ct);
    // T₁ ⊕ T₂ must equal GHASH_H(C₁) ⊕ GHASH_H(C₂) (masks identical).
    expect(hex(fieldToBytes(dTag))).toBe(hex(fieldToBytes(dGhash)));
  });
});
