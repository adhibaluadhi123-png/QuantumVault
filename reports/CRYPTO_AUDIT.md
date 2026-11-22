# QuantumVault – Mid-Project Cryptography Audit

**Date:** 22 November 2026

## 1. Objective

Demonstrate post-quantum recipient-based file encryption using
ML-KEM-768 and authenticated AES-256-GCM encryption.

## 2. Cryptographic Architecture

1. The C cryptographic engine uses liboqs ML-KEM-768.
2. ML-KEM encapsulation establishes a shared secret for the recipient.
3. HKDF-SHA256 derives a 256-bit encryption key.
4. AES-256-GCM encrypts the actual file contents.
5. The QVAULT02 container authenticates its header as additional
   authenticated data.
6. The recipient's private key is required to recover the shared secret
   and decrypt the file.

**Important:** ML-KEM is a key-encapsulation mechanism, not a bulk
file-encryption algorithm. AES-256-GCM performs the actual file encryption.

## 3. Implementation

- C engine: `rust-ffi/c-engine/crypto.c`
- C API: `rust-ffi/c-engine/crypto.h`
- Rust FFI: `rust-ffi/src/ffi.rs`
- Safe ML-KEM API: `rust-ffi/src/safe.rs`
- Recipient encryption: `rust-ffi/src/recipient_encryption.rs`
- Audit demonstration: `rust-ffi/src/bin/crypto_audit.rs`
- C hybrid encryption demonstration: `pqc-demo/hybrid_crypto_demo.c`
- C disk round-trip demonstration: `pqc-demo/hybrid_disk_roundtrip.c`

## 4. Audit Test Results

| Test | Result |
|---|---|
| ML-KEM-768 keypair generation | PASS |
| AES-256-GCM file encryption | PASS |
| QVAULT02 header validation | PASS |
| Original plaintext absence check | PASS |
| Wrong recipient rejection | PASS |
| Correct recipient decryption | PASS |
| Original and recovered file comparison | PASS |

The wrong recipient test returned `AuthenticationFailed` and did not
create a plaintext output file.

The correct recipient successfully decrypted the file, and the recovered
contents matched the original file exactly.

## 5. OpenSSL Compatibility Observation

Environment: OpenSSL 3.0.2.

The installed OpenSSL version lists AES-256-GCM as an available cipher.
However, the `openssl enc` command returned:

`enc: AEAD ciphers not supported`

Therefore, the OpenSSL `enc` CLI could not perform this AES-GCM
decryption test. This is a CLI AEAD-support limitation, not proof by
itself of cryptographic security.

The QVAULT02 format is a custom container containing an ML-KEM
encapsulation, salt, nonce, and authenticated AES-GCM ciphertext.
Decryption requires the recipient's ML-KEM private key and
the corresponding derived AES key.

## 6. Latest Evidence Files

Latest successful Rust cryptography audit run: **22 November 2026, 14:00**

- `reports/crypto-audit/audit_input_7009.txt`
- `reports/crypto-audit/audit_encrypted_7009.qv`
- `reports/crypto-audit/audit_recovered_7009.txt`

The encrypted output begins with the `QVAULT02` format identifier.
The original confidential plaintext was not found in the encrypted
container during the audit test.

The wrong-recipient test failed as expected, while the correct recipient
successfully recovered the original file.

## 7. Conclusion

The recipient-based hybrid encryption workflow passed the implemented
functional audit tests. Correct-recipient recovery, wrong-recipient
rejection, and original/recovered file equality were demonstrated.

This report records functional test evidence; it is not a claim of
formal cryptographic certification or independent security review.
