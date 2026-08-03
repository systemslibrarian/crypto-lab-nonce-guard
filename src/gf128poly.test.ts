import { describe, it, expect } from 'vitest';
import { gmul, ONE, bytesToField } from './gf128.ts';
import {
  polyAdd,
  polyDeg,
  polyDivMod,
  polyGcd,
  polyMul,
  polyRoots,
  polySqrMod,
  type Poly,
} from './gf128poly.ts';
import { ghashH, ghashPoly, forbiddenKeyEquation } from './forbidden.ts';

/** Evaluate p at x by Horner's rule, in GF(2¹²⁸). */
function evalPoly(p: Poly, x: bigint): bigint {
  let acc = 0n;
  for (let i = p.length - 1; i >= 0; i--) acc = gmul(acc, x) ^ (p[i] ?? 0n);
  return acc;
}

function randElt(): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 16n) | BigInt(Math.floor(Math.random() * 0x10000));
  return v;
}

describe('GF(2¹²⁸) polynomial arithmetic', () => {
  it('multiplication and division are inverse: (a·b)/b = a with zero remainder', () => {
    for (let t = 0; t < 20; t++) {
      const a: Poly = [randElt(), randElt(), randElt()];
      const b: Poly = [randElt(), ONE];
      const { q, r } = polyDivMod(polyMul(a, b), b);
      expect(r.length).toBe(0);
      expect(q.map(String)).toEqual(a.map(String));
    }
  });

  it('gcd of two products shares the common factor', () => {
    const f: Poly = [randElt(), ONE];
    const g: Poly = [randElt(), ONE];
    const h: Poly = [randElt(), ONE];
    const d = polyGcd(polyMul(f, g), polyMul(f, h));
    expect(polyDeg(d)).toBe(1);
    // Monic linear gcd: its root must be the shared factor's root.
    expect(evalPoly(polyMul(f, g), d[0])).toBe(0n);
    expect(evalPoly(polyMul(f, h), d[0])).toBe(0n);
  });

  it('squaring mod m matches multiplying by itself mod m', () => {
    const m: Poly = [randElt(), randElt(), randElt(), ONE];
    const p: Poly = [randElt(), randElt()];
    const viaSqr = polySqrMod(p, m);
    const viaMul = polyDivMod(polyMul(p, p), m).r;
    expect(viaSqr.map(String)).toEqual(viaMul.map(String));
  });
});

describe('root finding over GF(2¹²⁸)', () => {
  it('finds every planted root of a product of distinct linear factors', () => {
    for (let t = 0; t < 5; t++) {
      const planted = [randElt(), randElt(), randElt(), randElt()];
      let f: Poly = [ONE];
      for (const r of planted) f = polyMul(f, [r, ONE]);
      const found = polyRoots(f);
      expect(found.length).toBe(planted.length);
      for (const r of planted) expect(found).toContain(r);
      for (const r of found) expect(evalPoly(f, r)).toBe(0n);
    }
  });

  it('never returns a value that is not actually a root', () => {
    // Random quadratics: some split over GF(2¹²⁸) and some do not, so this
    // pins soundness (no spurious roots) rather than a fixed root count.
    for (let t = 0; t < 10; t++) {
      const f: Poly = [randElt(), randElt(), ONE];
      for (const r of polyRoots(f)) {
        expect(evalPoly(f, r)).toBe(0n);
      }
    }
  });

  it('throws rather than guessing when handed the zero polynomial', () => {
    expect(() => polyRoots([])).toThrow();
  });
});

describe('the GHASH polynomial is the same function ghashH evaluates', () => {
  it('agrees with ghashH at random H for many ciphertext lengths', () => {
    for (const len of [0, 1, 15, 16, 17, 48, 100]) {
      const ct = new Uint8Array(len).map(() => Math.floor(Math.random() * 256));
      const H = randElt();
      expect(evalPoly(ghashPoly(ct), H)).toBe(ghashH(H, ct));
    }
  });

  it('the key equation really vanishes at the true H', () => {
    // Construct a consistent pair by hand: pick H and a mask, define tags.
    const H = randElt();
    const mask = randElt();
    const ct1 = new Uint8Array(37).map(() => Math.floor(Math.random() * 256));
    const ct2 = new Uint8Array(20).map(() => Math.floor(Math.random() * 256));
    const tag1 = toBytes(ghashH(H, ct1) ^ mask);
    const tag2 = toBytes(ghashH(H, ct2) ^ mask);
    const f = forbiddenKeyEquation(ct1, tag1, ct2, tag2);
    expect(evalPoly(f, H)).toBe(0n);
    expect(polyRoots(f)).toContain(H);
  });
});

function toBytes(v: bigint): Uint8Array {
  const b = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

// polyAdd sanity: XOR is its own inverse.
describe('polyAdd', () => {
  it('is its own inverse', () => {
    const a: Poly = [randElt(), randElt()];
    const b: Poly = [randElt(), randElt(), randElt()];
    expect(polyAdd(polyAdd(a, b), b).map(String)).toEqual(a.map(String));
  });
});

// Guard against a silently wrong field mapping in ghashPoly's length block.
describe('ghashPoly length block', () => {
  it('places the bit-length block at degree 1', () => {
    const ct = new Uint8Array(0);
    const p = ghashPoly(ct);
    const lenBlock = new Uint8Array(16);
    expect(p[1]).toBe(bytesToField(lenBlock));
  });
});
