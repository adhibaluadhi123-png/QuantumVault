# QuantumVault - Reviewer Demo Guide

## Project Overview
QuantumVault is a post-quantum secure file storage project using Rust, C, and hybrid cryptography.

## Cryptographic Workflow
1. ML-KEM-768 establishes a shared secret.
2. HKDF-SHA256 derives an AES-256 key.
3. AES-256-GCM encrypts and authenticates file data.
4. The intended recipient can decrypt the encrypted file.

## Build Verification
Run: `cd ~/QuantumVault/filesystem && cargo build --bins`

## C Hybrid Encryption Demo
Run: `./pqc-demo/hybrid_crypto_demo`

## Disk Round-Trip Demo
Run: `./pqc-demo/hybrid_disk_roundtrip`

## Encrypted Filesystem
The FUSE-based filesystem provides a mounted view of files while storing encrypted data in the application storage directory.

## Security Checks
- AES-GCM authentication rejects incorrect keys or modified ciphertext.
- Recipient decryption is checked.
- Encrypted storage should not expose the original plaintext.
- Private keys should not be included in encrypted evidence files.

## Limitations
This project is a prototype and is not a formally certified production cryptographic system.
## FUSE Practical Demonstration

1. Start filesystem: `cd ~/QuantumVault/filesystem && cargo run --bin filesystem`
2. Verify mount: `mountpoint /tmp/quantumvault_mount`
3. Create sample file: `echo "QuantumVault reviewer demo file." > ~/reviewer_demo.txt`
4. Copy file into FUSE: `cp ~/reviewer_demo.txt /tmp/quantumvault_mount/reviewer_demo.txt`
5. Read through FUSE: `cat /tmp/quantumvault_mount/reviewer_demo.txt`
6. Inspect backend: `ls -lh ~/.local/share/quantumvault/files/`

## Practical Validation

- FUSE filesystem startup and mount verified.
- File creation and reading through mounted directory verified.
- Corresponding encrypted `.qv` backend container observed.
- Standalone C hybrid encryption demonstration passed.
- Rust-C FFI tests previously passed.

Note: FUSE file storage and standalone C encryption are separate demonstrations. End-to-end decryption of a FUSE-stored file requires separate validation.
