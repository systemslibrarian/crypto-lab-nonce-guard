/**
 * Polynomials over GF(2¹²⁸) — enough of them to actually SOLVE the forbidden
 * attack's key equation instead of restricting the demo to the one case that
 * has a closed form.
 *
 * Joux's attack on nonce-reusing AES-GCM produces
 *
 *     T₁ ⊕ T₂ = GHASH_H(C₁) ⊕ GHASH_H(C₂)
 *
 * and GHASH_H(C) is a polynomial in H whose coefficients are the ciphertext
 * blocks. For two single-block, equal-length ciphertexts that polynomial
 * degenerates to a single H² term and H falls out of one square root (see
 * `forbidden.ts`). For messages of any other shape the equation is a genuine
 * degree-(n+1) polynomial and H is one of its roots — so recovering H from a
 * learner's OWN two messages means factoring a polynomial over GF(2¹²⁸).
 *
 * This module does that with the standard textbook algorithm:
 *
 *   1. gcd(f, x^(2¹²⁸) − x) keeps exactly the product of f's distinct roots in
 *      the field (every field element satisfies x^(2¹²⁸) = x).
 *   2. Equal-degree splitting in characteristic 2 uses the trace map
 *      Tr(y) = y + y² + y⁴ + … + y^(2¹²⁷), which lands in {0, 1}; for a random
 *      a, gcd(Tr(a·x) mod g, g) splits g with probability ≈ ½ per attempt.
 *
 * Coefficient convention: `p[i]` is the coefficient of x^i, each a field
 * element in the GHASH bit convention of `gf128.ts`. The zero polynomial is the
 * empty array.
 */

import { gmul, ginv, ONE } from './gf128.ts';

export type Poly = bigint[];

/** Drop leading (highest-degree) zero coefficients. */
export function polyTrim(p: Poly): Poly {
  let n = p.length;
  while (n > 0 && p[n - 1] === 0n) n--;
  return p.slice(0, n);
}

/** Degree, or -1 for the zero polynomial. */
export function polyDeg(p: Poly): number {
  return polyTrim(p).length - 1;
}

/** Addition is XOR coefficient-wise (characteristic 2). */
export function polyAdd(a: Poly, b: Poly): Poly {
  const n = Math.max(a.length, b.length);
  const r: Poly = new Array(n).fill(0n);
  for (let i = 0; i < n; i++) r[i] = (a[i] ?? 0n) ^ (b[i] ?? 0n);
  return polyTrim(r);
}

export function polyMul(a: Poly, b: Poly): Poly {
  const A = polyTrim(a);
  const B = polyTrim(b);
  if (A.length === 0 || B.length === 0) return [];
  const r: Poly = new Array(A.length + B.length - 1).fill(0n);
  for (let i = 0; i < A.length; i++) {
    if (A[i] === 0n) continue;
    for (let j = 0; j < B.length; j++) {
      if (B[j] === 0n) continue;
      r[i + j] ^= gmul(A[i], B[j]);
    }
  }
  return polyTrim(r);
}

/** Scale every coefficient so the leading one is 1. */
export function polyMonic(p: Poly): Poly {
  const P = polyTrim(p);
  if (P.length === 0) return P;
  const lc = P[P.length - 1];
  if (lc === ONE) return P;
  const inv = ginv(lc);
  return P.map((c) => (c === 0n ? 0n : gmul(c, inv)));
}

/** Long division: returns quotient and remainder of `a` by monic-able `m`. */
export function polyDivMod(a: Poly, m: Poly): { q: Poly; r: Poly } {
  const M = polyMonic(m);
  if (M.length === 0) throw new Error('gf128poly: division by the zero polynomial');
  const dm = M.length - 1;
  const r = polyTrim(a).slice();
  const q: Poly = new Array(Math.max(0, r.length - dm)).fill(0n);
  for (let i = r.length - 1; i >= dm; i--) {
    const c = r[i];
    if (c === 0n) continue;
    q[i - dm] = c;
    for (let j = 0; j <= dm; j++) {
      if (M[j] === 0n) continue;
      r[i - dm + j] ^= gmul(c, M[j]);
    }
  }
  // The caller's divisor may not have been monic; scale the quotient back.
  const lc = polyTrim(m)[polyTrim(m).length - 1];
  const qq = lc === ONE ? q : q.map((c) => (c === 0n ? 0n : gmul(c, ginv(lc))));
  return { q: polyTrim(qq), r: polyTrim(r) };
}

export function polyMod(a: Poly, m: Poly): Poly {
  return polyDivMod(a, m).r;
}

/** Monic gcd. */
export function polyGcd(a: Poly, b: Poly): Poly {
  let x = polyTrim(a);
  let y = polyTrim(b);
  while (y.length > 0) {
    const r = polyMod(x, y);
    x = y;
    y = r;
  }
  return polyMonic(x);
}

/**
 * Square modulo `m`. In characteristic 2 squaring is additive, so squaring a
 * polynomial just squares each coefficient and doubles its exponent — no
 * cross terms.
 */
export function polySqrMod(p: Poly, m: Poly): Poly {
  const P = polyTrim(p);
  if (P.length === 0) return [];
  const r: Poly = new Array(2 * P.length - 1).fill(0n);
  for (let i = 0; i < P.length; i++) {
    r[2 * i] = P[i] === 0n ? 0n : gmul(P[i], P[i]);
  }
  return polyMod(r, m);
}

/** x^(2¹²⁸) mod m, by 128 repeated squarings of x. */
export function polyXPowFieldSize(m: Poly): Poly {
  let r: Poly = polyMod([0n, ONE], m); // x mod m
  for (let i = 0; i < 128; i++) r = polySqrMod(r, m);
  return r;
}

/** The absolute trace map Tr(u) = u + u² + u⁴ + … + u^(2¹²⁷), taken mod m. */
function polyTraceMod(u: Poly, m: Poly): Poly {
  let acc = polyMod(u, m);
  let cur = acc;
  for (let i = 0; i < 127; i++) {
    cur = polySqrMod(cur, m);
    acc = polyAdd(acc, cur);
  }
  return acc;
}

function randomFieldElement(rand: () => number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v = (v << 16n) | BigInt(Math.floor(rand() * 0x10000));
  }
  return v;
}

/**
 * Split a monic, squarefree polynomial whose irreducible factors are all
 * linear, returning its roots. Characteristic-2 Cantor–Zassenhaus: for random
 * a, gcd(Tr(a·x), g) is a proper factor about half the time.
 */
function splitLinear(g: Poly, rand: () => number, out: bigint[], budget = 200): void {
  const G = polyMonic(g);
  const d = G.length - 1;
  if (d <= 0) return;
  if (d === 1) {
    // monic x + c  ⇒  root = c
    out.push(G[0]);
    return;
  }
  for (let attempt = 0; attempt < budget; attempt++) {
    const a = randomFieldElement(rand);
    if (a === 0n) continue;
    const t = polyTraceMod([0n, a], G);
    const h = polyGcd(t, G);
    const dh = h.length - 1;
    if (dh > 0 && dh < d) {
      splitLinear(h, rand, out, budget);
      splitLinear(polyDivMod(G, h).q, rand, out, budget);
      return;
    }
  }
  throw new Error('gf128poly: root splitting exhausted its attempt budget');
}

/**
 * Every root of `f` that lies in GF(2¹²⁸), sorted, with no duplicates.
 * Returns an empty array when `f` has no roots in the field, and throws on the
 * zero polynomial (which every element satisfies — the caller must handle that
 * degenerate case, because it means the attack learned nothing).
 */
export function polyRoots(f: Poly, rand: () => number = Math.random): bigint[] {
  const F = polyTrim(f);
  if (F.length === 0) throw new Error('gf128poly: the zero polynomial has no finite root set');
  const M = polyMonic(F);
  if (M.length === 1) return []; // nonzero constant
  // gcd(f, x^(2¹²⁸) − x) = product of the distinct linear factors of f.
  const xq = polyXPowFieldSize(M);
  const g = polyGcd(polyAdd(xq, [0n, ONE]), M);
  if (g.length <= 1) return [];
  const out: bigint[] = [];
  splitLinear(g, rand, out);
  const uniq = Array.from(new Set(out));
  uniq.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return uniq;
}
