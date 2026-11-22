# QuantumVault – Mid-Project Review

**Date:** 22 November 2026

## 1. Project Overview

QuantumVault demonstrates post-quantum recipient-based file encryption
and an encrypted virtual filesystem.

Technologies:
- C and liboqs
- ML-KEM-768
- HKDF-SHA256
- AES-256-GCM
- Rust and C FFI
- FUSE filesystem

## 2. C Hybrid Cryptography

Implementation:
- `pqc-demo/hybrid_crypto_demo.c`
- `pqc-demo/hybrid_disk_roundtrip.c`

Verified:
- ML-KEM-768 keypair generation and encapsulation.
- Shared-secret agreement.
- HKDF-SHA256 key derivation.
- AES-256-GCM encryption and decryption.
- File encryption using the hybrid design.
- Wrong-key rejection through GCM authentication.
- Successful recipient decryption.
- Original and recovered file contents match.

## 3. Disk Round-Trip Verification

The C disk round-trip test was compiled and executed successfully.

Verified:
- Encrypted container written to disk.
- Container reopened and ciphertext read from disk.
- Recipient decryption using disk-read data.
- Original and recovered data match.
- Wrong key rejected after disk read.

Final test result:

`DISK ROUND-TRIP TEST PASSED.`

Evidence:
- `c_disk_roundtrip.qv`
- `c_disk_recovered.txt`

## 4. Rust/C Cryptographic Integration

The existing Rust/C implementation uses:
- C liboqs engine for ML-KEM operations.
- Rust FFI for C interoperability.
- HKDF-SHA256 for key derivation.
- AES-256-GCM for file encryption and decryption.
- Recipient-based key handling.

Latest Rust cryptography audit:
- ML-KEM-768 recipient keypair generation: PASS.
- AES-256-GCM file encryption: PASS.
- QVAULT02 header validation: PASS.
- Plaintext absence check: PASS.
- Wrong recipient rejected with AuthenticationFailed: PASS.
- Correct recipient decryption: PASS.
- Original and recovered file comparison: PASS.

Final result:

`CRYPTO AUDIT PASSED.`

Latest evidence:
- `reports/crypto-audit/audit_input_7009.txt`
- `reports/crypto-audit/audit_encrypted_7009.qv`
- `reports/crypto-audit/audit_recovered_7009.txt`

Detailed report:

`reports/CRYPTO_AUDIT.md`

The standalone C demonstration container and existing Rust/C storage
format are separate implementations.

## 5. Encrypted Filesystem Integration

FUSE mount point:

`/tmp/quantumvault_mount`

Encrypted storage:

`~/.local/share/quantumvault`

Verified:
- FUSE filesystem mounted successfully.
- Existing encrypted files loaded.
- File read through the virtual filesystem.
- New file created through the mount.
- File contents read back successfully.
- Corresponding encrypted `.qv` file created.
- Plaintext search in the tested encrypted file did not find the original content.

Test file:

`review_hello_world.txt`

Read-back content:

`Hello World`

Plaintext verification:

`PASS: Hello World plaintext not found in encrypted storage.`

### Filesystem Restart and Persistence Test

The FUSE filesystem was unmounted after its process stopped and then
started again using the existing QuantumVault key.

Verified:
- Stale mount was removed successfully.
- Existing encrypted storage loaded with 4 encrypted files.
- Previously created `review_hello_world.txt` remained accessible.
- File contents were successfully read after restart.
- Plaintext was not found in the corresponding encrypted `.qv` file.

Persistence result: PASS.

## 6. Rust Test and Build Results

Command: `cargo test`

Result:
- 3 tests passed.
- 0 failed.
- No separate unit tests were present in the filesystem and PQC demo binaries.

Command: `cargo build --bins`

Result: Successful.

The three unit tests are FFI arithmetic tests; cryptographic behavior
was separately verified through the C and Rust audit demonstrations.

## 7. Security Observations

- AES-256-GCM authenticates encrypted content.
- Wrong-key rejection was demonstrated.
- Original and recovered file contents matched.
- Plaintext absence was checked in the tested encrypted storage files.
- Filesystem data remained accessible after a restart.

These results demonstrate implemented functionality, not formal
certification or an independent security audit.

The OpenSSL `enc` command's AEAD limitation is documented in
`reports/CRYPTO_AUDIT.md`. That CLI limitation is not itself proof of security.

## 8. Remaining Work

- Final source-code and repository review.
- Prepare the final review demonstration.
- Confirm any remaining project requirements with the team.

## 9. Current Status

The C hybrid encryption disk round-trip test, Rust recipient-based
cryptography audit, FUSE filesystem operations, filesystem persistence
test, Rust tests, and Rust binary build have passed.

Final repository review and project review preparation remain.

## 10. Verified Cryptographic Build Architecture

The active ML-KEM-768 C engine is located at:

`rust-ffi/c-engine/crypto.c`

The Rust FFI layer is located at:

- `rust-ffi/src/ffi.rs`
- `rust-ffi/src/safe.rs`

The C engine is compiled through `rust-ffi/build.rs`, and the filesystem
crate depends on the root `rust-ffi` crate.

The file `filesystem/pqc-engine/c-engine/crypto.c` was compared with
the active C engine using `diff`. Both files were identical at the
time of verification.

However, `filesystem/pqc-engine/` currently has no demonstrated build
integration with the filesystem crate. It is retained as a separate
copy pending cleanup review.
