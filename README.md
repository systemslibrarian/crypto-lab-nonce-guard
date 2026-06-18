[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)
[![Deploy to GitHub Pages](https://github.com/systemslibrarian/crypto-lab-nonce-guard/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-nonce-guard/actions/workflows/pages.yml)

# crypto-lab-nonce-guard

## 1. What It Is

crypto-lab-nonce-guard is a browser-based comparison of AES-GCM (NIST SP 800-38D) and AES-GCM-SIV (RFC 8452) focused on nonce misuse resistance. Both are authenticated encryption schemes producing a ciphertext and authentication tag. AES-GCM requires strict nonce uniqueness — reusing a nonce allows an attacker to recover the XOR of two plaintexts and algebraically recover the GHASH authentication key, enabling tag forgery. AES-GCM-SIV uses a synthetic IV derived from the plaintext, so nonce reuse degrades only to leaking whether two plaintexts were identical — the keystream is never reused and the authentication key is never exposed. The security model is symmetric AEAD with a 256-bit key.

## 2. When to Use It

- **Use AES-GCM when nonce uniqueness is strictly guaranteed** (sequential counter, single encryptor) and FIPS compliance is required — it is faster and universally supported.
- **Use AES-GCM-SIV in distributed systems** where multiple encryptors may accidentally generate the same nonce, accepting the two-pass throughput cost (approaching ~2× on long messages) and the loss of FIPS approval.
- **Use AES-GCM-SIV for key wrapping and key storage** where the same key encrypts many short messages and nonce coordination is operationally difficult.
- **Do not use AES-GCM-SIV for streaming encryption** — it requires buffering the full plaintext before starting.
- **Do not use either scheme for password hashing** — they are not memory-hard and provide no protection against offline brute force of short secrets.

## 3. Live Demo

[https://systemslibrarian.github.io/crypto-lab-nonce-guard/](https://systemslibrarian.github.io/crypto-lab-nonce-guard/)

Enter two messages and toggle nonce reuse on. Click "Encrypt Both" to encrypt under both AES-GCM and AES-GCM-SIV with the same key and nonce. Click "Run Attack" to execute the XOR recovery attack — watch AES-GCM expose the XOR of both plaintexts while AES-GCM-SIV reveals nothing beyond whether the messages were identical.

## 4. What Can Go Wrong

- **Nonce reuse in AES-GCM:** reusing any (key, nonce) pair allows an attacker with two ciphertexts to recover `P1 ⊕ P2` and, via Joux's "forbidden attack," solve a polynomial equation over GF(2¹²⁸) for candidate GHASH keys H — enabling tag forgery under that nonce.
- **Random nonce collision:** using random 96-bit nonces with AES-GCM risks collision after ~2³² messages per key (birthday bound). Rotate keys well before this limit.
- **Missing AAD binding:** failing to include the correct Additional Authenticated Data allows an attacker to swap AAD contexts (e.g., replay an old ciphertext in a new session).
- **AES-GCM-SIV identical plaintext leak:** nonce reuse with identical plaintexts produces identical ciphertexts, leaking that the same message was sent twice — relevant in low-entropy message spaces.
- **Truncated tags:** AES-GCM allows tags shorter than 128 bits. Tags below 96 bits are vulnerable to forgery by online guessing. Always use 128-bit tags.

## 5. Real-World Usage

- **TLS 1.3 (RFC 8446):** AES-256-GCM is a mandatory-to-implement cipher suite, with nonce derived from a counter XORed with a per-record mask to guarantee uniqueness.
- **QUIC (RFC 9001):** uses AES-GCM with packet number as nonce; Google's QUIC experiments evaluated AES-GCM-SIV for contexts where packet number coordination was complex.
- **Google Tink:** uses AES-GCM-SIV for key wrapping in its key management library, citing nonce misuse resistance as the primary motivation.
- **WireGuard:** uses ChaCha20-Poly1305 rather than AES-GCM, partly to avoid nonce management complexity on devices without AES-NI.
- **AWS Encryption SDK:** uses AES-GCM with a message ID as part of the nonce, combined with a key commitment scheme to prevent multi-key attacks.

---

**Cross-links:**
- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — ECB, CBC, CTR, GCM modes
- [ChaCha20 Stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — ARX stream cipher with nonce reuse demo
- [MAC Race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — HMAC, Poly1305, GHASH comparison
- [crypto-lab home](https://systemslibrarian.github.io/crypto-lab/)

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
