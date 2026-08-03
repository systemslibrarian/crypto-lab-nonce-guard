# crypto-lab-nonce-guard

[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)
[![Deploy to GitHub Pages](https://github.com/systemslibrarian/crypto-lab-nonce-guard/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-nonce-guard/actions/workflows/pages.yml)

## What It Is

crypto-lab-nonce-guard is a browser-based comparison of AES-GCM (NIST SP 800-38D) and AES-GCM-SIV (RFC 8452) focused on nonce misuse resistance. Both are authenticated encryption schemes producing a ciphertext and authentication tag. AES-GCM requires strict nonce uniqueness — reusing a nonce allows an attacker to recover the XOR of two plaintexts and algebraically recover the GHASH authentication key, enabling tag forgery. AES-GCM-SIV uses a synthetic IV derived from the plaintext, so nonce reuse degrades only to leaking whether two plaintexts were identical — the keystream is never reused and the authentication key is never exposed. The security model is symmetric AEAD with a 256-bit key.

## When to Use It

- **Use AES-GCM when nonce uniqueness is strictly guaranteed** (sequential counter, single encryptor) and FIPS compliance is required — it is faster and universally supported.
- **Use AES-GCM-SIV in distributed systems** where multiple encryptors may accidentally generate the same nonce, accepting the two-pass throughput cost (approaching ~2× on long messages) and the loss of FIPS approval.
- **Use AES-GCM-SIV for key wrapping and key storage** where the same key encrypts many short messages and nonce coordination is operationally difficult.
- **Do not use AES-GCM-SIV for streaming encryption** — it requires buffering the full plaintext before starting.
- **Do not use either scheme for password hashing** — they are not memory-hard and provide no protection against offline brute force of short secrets.
- **Do NOT treat this as production code** — it is a teaching demo that deliberately performs nonce-reuse attacks to illustrate the failure modes.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/)**

Enter two messages and toggle nonce reuse on. Click "Encrypt Both" to encrypt under both AES-GCM and AES-GCM-SIV with the same key and nonce. Click "Run Attack" to execute both failure levels against AES-GCM:

- **Level 1 (confidentiality):** the XOR recovery attack exposes `P1 ⊕ P2` directly from the two ciphertexts.
- **Level 2 (integrity):** Joux's forbidden attack is actually carried out **on your own two messages**. The solver sees only `C1, T1, C2, T2`, builds the key equation `GHASH_H(C1) ⊕ GHASH_H(C2) ⊕ (T1 ⊕ T2) = 0` — a degree-`n+1` polynomial in the unknown `H` over GF(2¹²⁸), one term per 16-byte block plus the length block — and **factors it**: gcd with `x^(2¹²⁸) − x` to isolate the roots in the field, then characteristic-2 Cantor–Zassenhaus trace splitting to separate them. Each candidate root is then used to forge a tag, and the real AES-GCM decryptor decides which one was the key. The recovered `H` is shown next to the true `H = AES-256(key, 0¹²⁸)` so you can see they match exactly, and the forged blob's decryption is printed to show the receiver really opens the attacker's chosen payload.
  - Two honest limits, both reachable by typing: two **identical** messages make the equation `0 = 0` and nothing is learned; a message over **512 bytes** is declined because the in-browser root search is quadratic in the degree. The cap is this page's runtime budget, not a limit of the attack.

AES-GCM-SIV, under the same reused nonce, reveals nothing beyond whether the two messages were identical.

The page is ordered so you **break the scheme before you meet the math**: click first, then read why it happened. Every "why it cancels" step is shown as a two-stage animation (watch the shared keystream/mask fade out), never asserted as prose.

## Exhibits

1. **A — What is a Nonce?** The one rule (unique per key), the 96-bit nonce shown as 12 live hex bytes, and an on-ramp that sends you to break it before any theory.
2. **B — See It Break (Live Attack Demo).** Encrypt two messages under both schemes with a reused nonce, then run the attack. Level 1 recovers `P1 ⊕ P2`; Level 2 recovers `H` and forges a tag the real AES-GCM decryptor accepts, with recovered `H` shown next to the independently computed ground truth. An attacker-capability box frames what you started with (two ciphertexts + tags) versus what you now hold (the auth key).
3. **C — Why It Breaks.** The algebra behind what you just witnessed, with two **cancellation animations**: Level 1 shows the shared keystream fading out of `C1 ⊕ C2` to leave `P1 ⊕ P2`; Level 2 shows the shared mask fading out of `tag1 ⊕ tag2` to leave a pure equation in `H`. Heavy terms (GHASH, mask, GF(2¹²⁸)) get a one-line intuition gloss. An honest note states the two scope limits of the in-browser solver: the known-plaintext assumption behind the forged ciphertext, and the 512-byte cap on the root search.
4. **D — SIV: Safe by Design.** The RFC 8452 synthetic-IV construction, why AES-encrypting the POLYVAL result kills the tag-cancellation trick, and an **interactive tag-as-IV panel**: type a message and watch plaintext → SIV tag → derived AES-CTR IV → first ciphertext block all change together. A "send the same message twice" vs "change one byte" toggle lets you produce the identical-plaintext leak (and its absence) yourself.
5. **E — When to Use Which.** Side-by-side comparison table, three decision scenarios, and an honest list of AES-GCM-SIV's limitations (no FIPS approval, no online encryption, two passes).

The field arithmetic, GHASH, key-recovery, and forgery are covered by unit tests (`npm test`): the GF(2¹²⁸) implementation is cross-checked against `@noble/ciphers`' GHASH, and the attack tests assert `H` is recovered exactly and that a forged tag is accepted by the real primitive while a random tag is rejected.

## What Can Go Wrong

- **Nonce reuse in AES-GCM:** reusing any (key, nonce) pair allows an attacker with two ciphertexts to recover `P1 ⊕ P2` and, via Joux's "forbidden attack," solve a polynomial equation over GF(2¹²⁸) for candidate GHASH keys H — enabling tag forgery under that nonce.
- **Random nonce collision:** with randomly generated 96-bit nonces, NIST SP 800-38D §8.3 caps AES-GCM at 2³² invocations per key — the limit that holds the probability of a repeated IV at or below the 2⁻³² bound required by §8, and deliberately far stricter than the ~2⁴⁸ birthday bound of a 96-bit space. Rotate keys well before this limit.
- **Missing AAD binding:** failing to include the correct Additional Authenticated Data allows an attacker to swap AAD contexts (e.g., replay an old ciphertext in a new session).
- **AES-GCM-SIV identical plaintext leak:** nonce reuse with identical plaintexts produces identical ciphertexts, leaking that the same message was sent twice — relevant in low-entropy message spaces.
- **Truncated tags:** AES-GCM allows tags shorter than 128 bits. Tags below 96 bits are vulnerable to forgery by online guessing. Always use 128-bit tags.

## Real-World Usage

- **TLS 1.3 (RFC 8446 §9.1):** AES-128-GCM (`TLS_AES_128_GCM_SHA256`) is the mandatory-to-implement cipher suite and AES-256-GCM (`TLS_AES_256_GCM_SHA384`) is SHOULD-implement, with nonce derived from a counter XORed with a per-record mask to guarantee uniqueness.
- **QUIC (RFC 9001):** uses AES-GCM with packet number as nonce; Google's QUIC experiments evaluated AES-GCM-SIV for contexts where packet number coordination was complex.
- **Google Tink:** offers AES-GCM-SIV (`AES128_GCM_SIV`, `AES256_GCM_SIV`) as a supported AEAD key type, documenting that it fails less catastrophically than AES-GCM when nonce limits are exceeded — it may only leak that two messages are equal. It is also one of the accepted DEK types for KMS envelope encryption, though Tink recommends `AES128_GCM` for most uses.
- **WireGuard:** uses ChaCha20-Poly1305 rather than AES-GCM, partly to avoid nonce management complexity on devices without AES-NI.
- **AWS Encryption SDK:** uses AES-GCM with a message ID as part of the nonce, combined with a key commitment scheme to prevent multi-key attacks.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-nonce-guard
cd crypto-lab-nonce-guard
npm install
npm run dev
```

## Related Demos

- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — ECB, CBC, CTR, and GCM modes side by side.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — ARX stream cipher with its own nonce-reuse demo.
- [crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — HMAC, Poly1305, and GHASH authentication compared.
- [crypto-lab-ascon](https://systemslibrarian.github.io/crypto-lab-ascon/) — standardized lightweight AEAD for constrained devices.
- [crypto-lab-padding-oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/) — another AEAD/mode misuse attack (CBC padding oracle).

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
