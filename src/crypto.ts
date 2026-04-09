import { gcmsiv } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';

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
