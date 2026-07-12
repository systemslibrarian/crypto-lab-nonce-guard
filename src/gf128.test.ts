import { describe, it, expect } from 'vitest';
import { ghash } from '@noble/ciphers/_polyval.js';
import {
  ONE,
  bytesToField,
  fieldToBytes,
  gmul,
  gpow,
  ginv,
  gsqrt,
} from './gf128.ts';
import { ghashH } from './forbidden.ts';

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

describe('GF(2^128) field arithmetic (GHASH convention)', () => {
  it('bytesToField / fieldToBytes round-trip', () => {
    for (let i = 0; i < 50; i++) {
      const b = randBytes(16);
      expect(hex(fieldToBytes(bytesToField(b)))).toBe(hex(b));
    }
  });

  it('ONE is the multiplicative identity', () => {
    for (let i = 0; i < 50; i++) {
      const x = bytesToField(randBytes(16));
      expect(gmul(x, ONE)).toBe(x);
      expect(gmul(ONE, x)).toBe(x);
    }
  });

  it('multiplication is commutative', () => {
    for (let i = 0; i < 50; i++) {
      const a = bytesToField(randBytes(16));
      const b = bytesToField(randBytes(16));
      expect(gmul(a, b)).toBe(gmul(b, a));
    }
  });

  it('multiplication is associative and distributive over XOR', () => {
    for (let i = 0; i < 30; i++) {
      const a = bytesToField(randBytes(16));
      const b = bytesToField(randBytes(16));
      const c = bytesToField(randBytes(16));
      expect(gmul(gmul(a, b), c)).toBe(gmul(a, gmul(b, c)));
      expect(gmul(a, b ^ c)).toBe(gmul(a, b) ^ gmul(a, c));
    }
  });

  it('inverse: x · x⁻¹ = 1 for nonzero x', () => {
    for (let i = 0; i < 30; i++) {
      let x = bytesToField(randBytes(16));
      if (x === 0n) x = ONE;
      expect(gmul(x, ginv(x))).toBe(ONE);
    }
  });

  it('sqrt is the unique inverse of squaring', () => {
    for (let i = 0; i < 30; i++) {
      const x = bytesToField(randBytes(16));
      expect(gsqrt(gmul(x, x))).toBe(x);
      expect(gmul(gsqrt(x), gsqrt(x))).toBe(x);
    }
  });

  it('gpow matches repeated multiplication', () => {
    const x = bytesToField(randBytes(16));
    let acc = ONE;
    for (let e = 0; e <= 20; e++) {
      expect(gpow(x, BigInt(e))).toBe(acc);
      acc = gmul(acc, x);
    }
  });
});

describe('GHASH KAT: our field math matches @noble/ciphers reference', () => {
  it('ghashH equals noble ghash over empty AAD for random keys/lengths', () => {
    for (let i = 0; i < 40; i++) {
      const H = randBytes(16);
      const ctLen = 1 + Math.floor(Math.random() * 64);
      const ct = randBytes(ctLen);

      // Reference: feed noble ghash the standard GHASH input
      // (padded ciphertext ‖ 64-bit aadLen ‖ 64-bit ctLen).
      const padC = (16 - (ct.length % 16)) % 16;
      const input = new Uint8Array(ct.length + padC + 16);
      input.set(ct, 0);
      new DataView(input.buffer).setBigUint64(
        input.length - 8,
        BigInt(ct.length) * 8n,
        false,
      );
      const reference = ghash(input, H);

      const ours = fieldToBytes(ghashH(bytesToField(H), ct));
      expect(hex(ours)).toBe(hex(reference));
    }
  });
});
