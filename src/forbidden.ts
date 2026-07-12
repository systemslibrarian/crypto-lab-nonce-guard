/**
 * Joux's "forbidden attack" against AES-GCM under nonce reuse — a REAL,
 * end-to-end integrity break, not a prose assertion.
 *
 * Background. For a 96-bit nonce, the AES-GCM tag is
 *
 *     T = GHASH_H(AAD, C) ⊕ E_K(J0),   H = E_K(0¹²⁸),   J0 = nonce ‖ 0³¹1
 *
 * The mask E_K(J0) depends only on (key, nonce), and GHASH_H is a polynomial in
 * the single unknown H over GF(2¹²⁸). If two messages are encrypted under the
 * SAME (key, nonce) the masks are identical and cancel:
 *
 *     T₁ ⊕ T₂ = GHASH_H(A₁,C₁) ⊕ GHASH_H(A₂,C₂)
 *
 * a polynomial equation whose roots reveal H. We specialise to two single-block
 * ciphertexts of EQUAL length with empty AAD. Then GHASH reduces to
 *
 *     GHASH_H(C) = (C · H²) ⊕ (L · H)          (L = the length block)
 *
 * and the length term also cancels, leaving a term linear in H²:
 *
 *     T₁ ⊕ T₂ = (C₁ ⊕ C₂) · H²
 *
 * which is solved directly — no probabilistic root-finding — via
 *
 *     H = sqrt( (T₁ ⊕ T₂) · (C₁ ⊕ C₂)⁻¹ )
 *
 * Recovering H also recovers the mask from any known (C, T) pair,
 * E_K(J0) = T ⊕ GHASH_H(C), after which we can forge a valid tag for an
 * ATTACKER-CHOSEN ciphertext of arbitrary length. The forgery is proven by
 * having the real AES-GCM primitive accept it (see forbidden.test.ts).
 */

import { bytesToField, fieldToBytes, gmul, ginv, gsqrt } from './gf128.ts';

/**
 * GHASH_H over empty AAD and ciphertext `ct` (any length), returning the raw
 * polynomial value BEFORE the mask is applied. This is the standard GHASH:
 * absorb each 16-byte block, then absorb the length block (aadLen‖ctLen in
 * bits, each a 64-bit big-endian integer).
 */
export function ghashH(H: bigint, ct: Uint8Array): bigint {
  const nblk = Math.ceil(ct.length / 16);
  let y = 0n;
  for (let i = 0; i < nblk; i++) {
    const blk = new Uint8Array(16);
    blk.set(ct.subarray(i * 16, Math.min((i + 1) * 16, ct.length)));
    y = gmul(y ^ bytesToField(blk), H);
  }
  const lenBlock = new Uint8Array(16);
  new DataView(lenBlock.buffer).setBigUint64(8, BigInt(ct.length) * 8n, false);
  y = gmul(y ^ bytesToField(lenBlock), H);
  return y;
}

export interface RecoveredKey {
  /** The recovered GHASH authentication key H (16 bytes). */
  H: Uint8Array;
  /** The recovered per-nonce mask E_K(J0) (16 bytes). */
  mask: Uint8Array;
}

/**
 * Recover the GHASH key H and the AES-GCM mask from two single-block,
 * equal-length (key, nonce)-colliding ciphertext/tag pairs (empty AAD).
 *
 * Requires ct1.length === ct2.length and both ≤ 16 bytes (single block).
 */
export function recoverGhashKey(
  ct1: Uint8Array,
  tag1: Uint8Array,
  ct2: Uint8Array,
  tag2: Uint8Array,
): RecoveredKey {
  if (ct1.length !== ct2.length) {
    throw new Error('forbidden attack: ciphertexts must be equal length');
  }
  if (ct1.length === 0 || ct1.length > 16) {
    throw new Error('forbidden attack: this toy solver needs a single block (1–16 bytes)');
  }
  // Pad each single block to 16 bytes exactly as GHASH does.
  const b1 = new Uint8Array(16);
  b1.set(ct1);
  const b2 = new Uint8Array(16);
  b2.set(ct2);

  const dC = bytesToField(b1) ^ bytesToField(b2); // C₁ ⊕ C₂
  const dT = bytesToField(tag1) ^ bytesToField(tag2); // T₁ ⊕ T₂ = dC · H²
  if (dC === 0n) {
    throw new Error('forbidden attack: ciphertexts are identical; need distinct plaintexts');
  }
  const H2 = gmul(dT, ginv(dC)); // = H²
  const H = gsqrt(H2); // unique square root in GF(2¹²⁸)

  // Recover the mask E_K(J0) = T ⊕ GHASH_H(C) from the first known pair.
  const mask = bytesToField(tag1) ^ ghashH(H, ct1);

  return { H: fieldToBytes(H), mask: fieldToBytes(mask) };
}

/**
 * Forge a valid AES-GCM tag for an attacker-chosen ciphertext under the reused
 * nonce, given the recovered H and mask. The forged tag equals what the real
 * key would have produced, so real AES-GCM verification accepts it.
 */
export function forgeTag(
  recovered: RecoveredKey,
  forgedCiphertext: Uint8Array,
): Uint8Array {
  const H = bytesToField(recovered.H);
  const mask = bytesToField(recovered.mask);
  return fieldToBytes(ghashH(H, forgedCiphertext) ^ mask);
}
