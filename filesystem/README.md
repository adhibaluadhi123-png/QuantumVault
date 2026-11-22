
# QuantumVault – Post-Quantum Encrypted Filesystem

## 1. Project Overview

QuantumVault is a post-quantum encrypted filesystem prototype that combines Rust, C, FUSE, and cryptographic libraries.

It demonstrates recipient-based file encryption using ML-KEM-768 and AES-256-GCM, along with transparent encryption and decryption through a mounted virtual filesystem.

## 2. System Architecture

The project consists of:

- C cryptographic engine using liboqs.
- Rust–C Foreign Function Interface (FFI).
- ML-KEM-768 for post-quantum key encapsulation.
- HKDF-SHA256 for symmetric key derivation.
- AES-256-GCM for authenticated file encryption.
- Rust FUSE application for filesystem integration.

The active cryptographic engine is located in `../rust-ffi/c-engine/crypto.c`.

The filesystem application uses the Rust `rust-ffi` crate through its Cargo dependency.

## 3. Rust–C FFI Integration

The C cryptographic engine exposes ML-KEM-768 operations to Rust.

The Rust integration includes:

- `rust-ffi/src/ffi.rs`
- `rust-ffi/src/safe.rs`
- `rust-ffi/src/recipient_encryption.rs`
- `rust-ffi/build.rs`

The `cc` build dependency compiles the C source, and Rust accesses the exported cryptographic functions through FFI.

## 4. Post-Quantum Hybrid Encryption

QuantumVault uses hybrid encryption:

1. ML-KEM-768 generates a shared secret using recipient public-key encapsulation.
2. HKDF-SHA256 derives an AES-256 encryption key.
3. AES-256-GCM encrypts file contents.
4. The encrypted data is stored in a QVAULT02 container.
5. The recipient uses their private key to recover the shared secret and decrypt the file.

ML-KEM-768 is used for key encapsulation, not direct bulk file encryption.

## 5. Encrypted Filesystem Integration

The filesystem application uses Rust FUSE to expose a virtual mounted directory.

Mount point:

`/tmp/quantumvault_mount`

Encrypted storage directory:

`~/.local/share/quantumvault/files/`

Implemented functionality includes:

- Mounting the virtual filesystem.
- Creating and reading files through the mount point.
- Encrypting file contents before storage.
- Decrypting file contents when accessed.
- Persisting encrypted files across filesystem restarts.

## 6. Verification Results

The following functionality has been tested:

| Test | Result |
|---|---|
| ML-KEM-768 key generation | PASS |
| Shared-secret agreement | PASS |
| HKDF-SHA256 key derivation | PASS |
| AES-256-GCM encryption/decryption | PASS |
| Wrong-recipient rejection | PASS |
| Correct-recipient decryption | PASS |
| QVAULT02 container validation | PASS |
| Plaintext absence in encrypted storage | PASS |
| C disk round-trip encryption/decryption | PASS |
| FUSE file creation and reading | PASS |
| FUSE restart and persistence | PASS |

The Rust cryptographic audit and standalone C disk round-trip tests provide additional verification.

## 7. Build and Execution

Build the Rust cryptographic library:

```bash
cd ~/QuantumVault/rust-ffi
cargo build
```

Run the cryptographic audit:

```bash
cargo run --bin crypto_audit
```

Build the filesystem:

```bash
cd ~/QuantumVault/filesystem
cargo build --bins
```

Run the filesystem:

```bash
cargo run --bin filesystem
```

The application prompts for the QuantumVault passphrase and mounts the encrypted filesystem.

## 8. Security Notes and Limitations

- ML-KEM-768 provides post-quantum key encapsulation.
- AES-256-GCM provides authenticated encryption.
- Private keys should not be stored in plaintext.
- Cryptographic tests demonstrate functional behavior, not formal security certification.
- Independent security review and broader automated testing remain future work.

## 9. Project Status

The core cryptographic integration and encrypted filesystem functionality have been implemented and tested.

**Status:** Working prototype – Mid-Project Review.


