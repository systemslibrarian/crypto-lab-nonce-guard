import { gcm, gcmsiv, unsafe } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import {
  forgeTag,
  maskFromCandidate,
  recoverGhashCandidates,
} from './forbidden.ts';

export { randomBytes };

const encoder = new TextEncoder();

export function generateNonce(): Uint8Array {
  return randomBytes(12);
}

export function generateKey(): Uint8Array {
  return randomBytes(32);
}

export async function encryptGCM(
  key: CryptoKey,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  const iv = new Uint8Array(nonce.buffer.slice(nonce.byteOffset, nonce.byteOffset + nonce.byteLength)) as Uint8Array<ArrayBuffer>;
  const pt = new Uint8Array(plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength)) as Uint8Array<ArrayBuffer>;
  const result = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    pt,
  );
  const buf = new Uint8Array(result);
  // Web Crypto appends the 16-byte tag to the end
  return {
    ciphertext: buf.slice(0, buf.length - 16),
    tag: buf.slice(buf.length - 16),
  };
}

export async function importGCMKey(rawKey: Uint8Array): Promise<CryptoKey> {
  const keyBuf = new Uint8Array(rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength)) as Uint8Array<ArrayBuffer>;
  return crypto.subtle.importKey('raw', keyBuf, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
}

export function encryptSIV(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const ct = gcmsiv(key, nonce).encrypt(plaintext);
  // @noble/ciphers appends the 16-byte tag to the end
  return {
    ciphertext: ct.slice(0, ct.length - 16),
    tag: ct.slice(ct.length - 16),
  };
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

export function toHex(bytes: Uint8Array, maxBytes = 0): string {
  const arr = maxBytes > 0 && bytes.length > maxBytes
    ? bytes.slice(0, maxBytes)
    : bytes;
  const hex = Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return maxBytes > 0 && bytes.length > maxBytes ? hex + '…' : hex;
}

export function xorToReadable(xored: Uint8Array): string {
  return Array.from(xored)
    .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·'))
    .join('');
}

export function textToBytes(text: string): Uint8Array {
  return encoder.encode(text);
}

export function getSIVTagForDemo(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const ct = gcmsiv(key, nonce).encrypt(plaintext);
  return ct.slice(ct.length - 16);
}

/**
 * The tag-as-IV story of AES-GCM-SIV, made observable. Returns the SIV tag, the
 * AES-CTR initial counter block derived from it (RFC 8452 §4: copy the tag, then
 * SET the most-significant bit of the last byte), and the first 16-byte block of
 * ciphertext produced under that IV.
 *
 * These are the real values @noble/ciphers computes — the tag and ciphertext are
 * taken straight from a genuine AES-GCM-SIV encryption; the IV is derived from
 * the tag by the exact spec rule. Nothing here is faked: it lets a learner watch
 * plaintext -> tag -> IV -> ciphertext move together, which is the whole point of
 * the synthetic-IV construction.
 */
export function getSIVTagIVForDemo(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): { tag: Uint8Array; iv: Uint8Array; ct1: Uint8Array } {
  const full = gcmsiv(key, nonce).encrypt(plaintext);
  const tag = full.slice(full.length - 16);
  const ciphertext = full.slice(0, full.length - 16);
  // RFC 8452 §4: initial CTR block = tag with MSB of the last byte set to 1.
  const iv = tag.slice();
  iv[15] |= 0x80;
  const ct1 = ciphertext.slice(0, Math.min(16, ciphertext.length));
  return { tag, iv, ct1 };
}

// ── Level-2 integrity break: Joux's forbidden attack (real) ──

/** Encrypt with AES-256-GCM (noble), returning ciphertext and 128-bit tag. */
export function encryptGCMNoble(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const ct = gcm(key, nonce).encrypt(plaintext);
  return { ciphertext: ct.slice(0, ct.length - 16), tag: ct.slice(ct.length - 16) };
}

/**
 * Upper bound on the ciphertext length the in-browser root search will take on.
 * The key equation has degree ceil(len/16)+1, and factoring it over GF(2¹²⁸)
 * costs roughly quadratically in that degree; 512 bytes (degree 33) lands
 * around 1.5 s on a laptop, 1 KiB is already ~9 s. The cap is a runtime budget,
 * not a limit of the attack, and the page says so.
 */
export const LEVEL2_MAX_CT_BYTES = 512;

export type IntegrityFailure =
  /** Both ciphertexts are the same, so T₁ ⊕ T₂ = 0 and the equation is 0 = 0. */
  | 'no-information'
  /** Roots exist but none of them forged a tag the receiver accepted. */
  | 'no-candidate-verified'
  /** The equation had no root in GF(2¹²⁸) (cannot happen for a genuine pair). */
  | 'no-roots'
  /** Messages longer than the in-browser root-search budget. */
  | 'too-long'
  /** Nothing to forge with: the known plaintext is empty. */
  | 'no-keystream';

export interface IntegrityBreakResult {
  /** Degree of the key equation that was actually built and factored. */
  equationDegree: number;
  /** How many H values in GF(2¹²⁸) satisfy that equation. */
  candidateCount: number;
  /** How many forged tags the receiver had to check before one was accepted. */
  verificationQueries: number;
  /** The GHASH key recovered purely from the two (ciphertext, tag) pairs. */
  recoveredH: Uint8Array | null;
  /** The true H = E_K(0¹²⁸), computed independently, to prove the recovery is exact. */
  trueH: Uint8Array;
  recovered: boolean;
  /** A plaintext the attacker never legitimately encrypted. */
  forgedPlaintext: Uint8Array;
  forgedCiphertext: Uint8Array;
  forgedTag: Uint8Array | null;
  /** Whether the REAL AES-GCM primitive accepted the forged (ciphertext, tag). */
  forgeryAccepted: boolean;
  /** What real AES-GCM decryption returned for the forged blob, when accepted. */
  forgedDecryption: Uint8Array | null;
  failure?: IntegrityFailure;
}

/** The attacker's chosen payload, truncated to the keystream they can derive. */
const FORGED_TEMPLATE = 'PWNED: nonce reuse forged this tag ................................';

/**
 * Carry out Joux's forbidden attack against the learner's OWN two messages.
 *
 * The only inputs the attack consumes are the four values an eavesdropper sees
 * — `ct1`, `tag1`, `ct2`, `tag2` — plus knowledge of the first plaintext, the
 * standard known-plaintext assumption that keystream reuse already hands over
 * in Level 1. Concretely:
 *
 *   1. Build the key equation GHASH_H(C₁) ⊕ GHASH_H(C₂) ⊕ (T₁ ⊕ T₂) = 0 as a
 *      polynomial in the unknown H, of degree ceil(len/16)+1.
 *   2. Factor it over GF(2¹²⁸) for every candidate H (`recoverGhashCandidates`).
 *   3. Recover the keystream as C₁ ⊕ P₁ and encrypt a chosen payload with it.
 *   4. For each candidate H, derive the per-nonce mask from (C₁, T₁), forge a
 *      tag, and hand the blob to the REAL AES-GCM decryptor. One accepted
 *      verification query settles which candidate was the real H.
 *
 * `key` is used for exactly two things, neither of them part of the attack:
 * computing the ground-truth H for display, and standing in for the receiver
 * who checks the forged tags. The recovery itself never sees it.
 */
export function runForbiddenAttack(
  key: Uint8Array,
  nonce: Uint8Array,
  ct1: Uint8Array,
  tag1: Uint8Array,
  ct2: Uint8Array,
  tag2: Uint8Array,
  knownPlaintext1: Uint8Array,
): IntegrityBreakResult {
  const trueH = trueGhashKey(key);
  const base: IntegrityBreakResult = {
    equationDegree: 0,
    candidateCount: 0,
    verificationQueries: 0,
    recoveredH: null,
    trueH,
    recovered: false,
    forgedPlaintext: new Uint8Array(0),
    forgedCiphertext: new Uint8Array(0),
    forgedTag: null,
    forgeryAccepted: false,
    forgedDecryption: null,
  };

  if (ct1.length > LEVEL2_MAX_CT_BYTES || ct2.length > LEVEL2_MAX_CT_BYTES) {
    return { ...base, failure: 'too-long' };
  }

  const solved = recoverGhashCandidates(ct1, tag1, ct2, tag2);
  if (solved.failure) {
    return { ...base, equationDegree: solved.degree, failure: solved.failure };
  }

  // The keystream the attacker can derive without the key: C₁ ⊕ P₁.
  const keystream = xorBytes(ct1, knownPlaintext1);
  if (keystream.length === 0) {
    return {
      ...base,
      equationDegree: solved.degree,
      candidateCount: solved.candidates.length,
      failure: 'no-keystream',
    };
  }

  const payload = textToBytes(FORGED_TEMPLATE).slice(0, keystream.length);
  const forgedPlaintext = payload;
  const forgedCiphertext = xorBytes(forgedPlaintext, keystream);

  // One verification query per candidate until the receiver accepts one. With
  // a single candidate this is one query; with several it is at most that many.
  let queries = 0;
  for (const H of solved.candidates) {
    const mask = maskFromCandidate(H, ct1, tag1);
    const forgedTag = forgeTag({ H, mask }, forgedCiphertext);
    const blob = new Uint8Array(forgedCiphertext.length + 16);
    blob.set(forgedCiphertext, 0);
    blob.set(forgedTag, forgedCiphertext.length);
    queries++;
    try {
      const opened = gcm(key, nonce).decrypt(blob);
      return {
        equationDegree: solved.degree,
        candidateCount: solved.candidates.length,
        verificationQueries: queries,
        recoveredH: H,
        trueH,
        recovered: bytesEqual(H, trueH),
        forgedPlaintext,
        forgedCiphertext,
        forgedTag,
        forgeryAccepted: true,
        forgedDecryption: opened,
      };
    } catch {
      // Wrong candidate — the receiver rejected the tag. Try the next root.
    }
  }

  return {
    ...base,
    equationDegree: solved.degree,
    candidateCount: solved.candidates.length,
    verificationQueries: queries,
    forgedPlaintext,
    forgedCiphertext,
    failure: 'no-candidate-verified',
  };
}

/**
 * Independent ground truth for the recovered key: the true GHASH authentication
 * key is H = AES-256(key, 0¹²⁸) by definition (NIST SP 800-38D §6.3). Computing
 * it directly from the key lets the demo prove the forbidden-attack recovery —
 * which uses ONLY ciphertexts and tags — landed on exactly the right value.
 */
function trueGhashKey(key: Uint8Array): Uint8Array {
  const block = new Uint8Array(16);
  const rk = unsafe.expandKeyLE(key);
  unsafe.encryptBlock(rk, block);
  return block;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
