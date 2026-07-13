import { gcm, gcmsiv, unsafe } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { recoverGhashKey, forgeTag, type RecoveredKey } from './forbidden.ts';

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

export interface IntegrityBreakResult {
  /** Two probe plaintexts (single 16-byte block) encrypted under the reused nonce. */
  probe1: Uint8Array;
  probe2: Uint8Array;
  tag1: Uint8Array;
  tag2: Uint8Array;
  /** The GHASH key recovered purely from the two (ciphertext, tag) pairs. */
  recoveredH: Uint8Array;
  /** The true H = E_K(0¹²⁸), computed independently, to prove the recovery is exact. */
  trueH: Uint8Array;
  recovered: boolean;
  /** A plaintext the attacker never legitimately encrypted. */
  forgedPlaintext: Uint8Array;
  forgedCiphertext: Uint8Array;
  forgedTag: Uint8Array;
  /** Whether the REAL AES-GCM primitive accepted the forged (ciphertext, tag). */
  forgeryAccepted: boolean;
}

/**
 * Actually carry out Joux's forbidden attack on the demo's (key, nonce): encrypt
 * two single-block probes under the reused nonce, recover the GHASH key H from
 * only their (ciphertext, tag) pairs, then forge a valid tag for an
 * attacker-chosen ciphertext and prove real AES-GCM accepts it.
 *
 * Uses fixed 16-byte probes because the closed-form solver targets the
 * single-block case; the key and nonce are the demo's own reused pair.
 */
export function runForbiddenAttack(
  key: Uint8Array,
  nonce: Uint8Array,
): IntegrityBreakResult {
  const probe1 = textToBytes('forbidden-atk-01'); // 16 bytes, one block
  const probe2 = textToBytes('forbidden-atk-02');

  const e1 = encryptGCMNoble(key, nonce, probe1);
  const e2 = encryptGCMNoble(key, nonce, probe2);

  // Attacker sees only ciphertexts and tags — recovers H and the mask.
  const recovered: RecoveredKey = recoverGhashKey(
    e1.ciphertext,
    e1.tag,
    e2.ciphertext,
    e2.tag,
  );

  // Independent ground truth for display: true H = E_K(0¹²⁸) obtained by
  // encrypting an all-zero block (GCM tag of empty message uses this H).
  const trueH = trueGhashKey(key);
  const recoveredOk = bytesEqual(recovered.H, trueH);

  // Forge a valid tag for a message the attacker chose but never encrypted.
  // Under the reused nonce the keystream is fixed, so a genuine ciphertext for
  // any chosen plaintext is P ⊕ E_K(0). Combined with the forged tag from the
  // recovered mask, this is a complete (ciphertext, tag) forgery.
  const forgedPlaintext = textToBytes('PWNED: nonce reuse forged this tag');
  const keystream = encryptGCMNoble(key, nonce, new Uint8Array(forgedPlaintext.length)).ciphertext;
  const forgedCiphertext = xorBytes(forgedPlaintext, keystream);
  const forgedTag = forgeTag(recovered, forgedCiphertext);

  // Prove it: hand the forged (ciphertext ‖ tag) to the REAL AES-GCM decryptor.
  const blob = new Uint8Array(forgedCiphertext.length + 16);
  blob.set(forgedCiphertext, 0);
  blob.set(forgedTag, forgedCiphertext.length);
  let forgeryAccepted = false;
  try {
    gcm(key, nonce).decrypt(blob);
    forgeryAccepted = true;
  } catch {
    forgeryAccepted = false;
  }

  return {
    probe1,
    probe2,
    tag1: e1.tag,
    tag2: e2.tag,
    recoveredH: recovered.H,
    trueH,
    recovered: recoveredOk,
    forgedPlaintext,
    forgedCiphertext,
    forgedTag,
    forgeryAccepted,
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
