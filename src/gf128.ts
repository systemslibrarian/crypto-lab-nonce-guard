/**
 * Arithmetic in GF(2¹²⁸) with the GHASH field polynomial from NIST SP 800-38D:
 *
 *     x¹²⁸ + x⁷ + x² + x + 1
 *
 * Blocks are interpreted in GHASH's "bit-reflected big-endian" convention:
 * byte 0's most-significant bit is the coefficient processed first. Concretely,
 * a 16-byte block maps to a 128-bit BigInt via big-endian byte order, bit 127
 * (0x80 of byte 0) is the multiplicative identity's set bit.
 *
 * This is a from-scratch, dependency-free implementation so the nonce-reuse
 * "forbidden attack" demo genuinely computes on the same field GHASH uses. The
 * unit tests cross-check `ghashHex` against @noble/ciphers' GHASH so the field
 * arithmetic is verified against an independent reference (see gf128.test.ts).
 */

const MASK = (1n << 128n) - 1n;
// Reduction term: x⁷ + x² + x + 1 = 0xe1, placed at the top byte because we
// reduce while shifting the running product toward the low end (LSB-out).
const R = 0xe1n << 120n;
/** Multiplicative identity (the block 0x8000…0000). */
export const ONE = 1n << 127n;

export function bytesToField(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function fieldToBytes(v: bigint): Uint8Array {
  const b = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

/** Field addition is XOR. */
export function gadd(a: bigint, b: bigint): bigint {
  return (a ^ b) & MASK;
}

/** Carry-less multiply modulo the GHASH polynomial. */
export function gmul(x: bigint, y: bigint): bigint {
  let z = 0n;
  let v = x;
  for (let i = 127; i >= 0; i--) {
    if ((y >> BigInt(i)) & 1n) z ^= v;
    const lsb = v & 1n;
    v >>= 1n;
    if (lsb) v ^= R;
  }
  return z & MASK;
}

/** Square-and-multiply exponentiation (exponent is a plain BigInt). */
export function gpow(x: bigint, e: bigint): bigint {
  let r = ONE;
  let b = x;
  while (e > 0n) {
    if (e & 1n) r = gmul(r, b);
    b = gmul(b, b);
    e >>= 1n;
  }
  return r;
}

/** Multiplicative inverse via Fermat: x^(2¹²⁸ − 2). */
export function ginv(x: bigint): bigint {
  return gpow(x, (1n << 128n) - 2n);
}

/**
 * Unique square root. Squaring is the Frobenius automorphism (a bijection) in
 * characteristic 2, so every element has exactly one square root: x^(2¹²⁷).
 */
export function gsqrt(x: bigint): bigint {
  return gpow(x, 1n << 127n);
}
