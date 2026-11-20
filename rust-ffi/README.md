# QuantumVault - Rust/C FFI Integration

## 1. Overview

This module connects the Rust application with the C-based post-quantum cryptography engine using Foreign Function Interface (FFI).

It provides Rust declarations and safe wrappers for calling C functions implemented with Open Quantum Safe (liboqs).

The current implementation integrates ML-KEM-768, a standardized post-quantum key encapsulation mechanism.

## 2. Architecture

Rust Application
       |
       v
Safe Rust Wrappers (src/safe.rs)
       |
       v
FFI Declarations (src/ffi.rs)
       |
       v
C Crypto Interface (c-engine/crypto.h)
       |
       v
C Implementation (c-engine/crypto.c)
       |
       v
Open Quantum Safe (liboqs)

## 3. Project Files

| File | Purpose |
|------|---------|
| src/lib.rs | Rust library entry point |
| src/ffi.rs | C function declarations for Rust |
| src/safe.rs | Safe Rust wrappers and error handling |
| c-engine/crypto.h | C crypto interface |
| c-engine/crypto.c | C implementation using liboqs |
| build.rs | Compiles C code and links libraries |
| Cargo.toml | Rust package and build dependencies |

## 4. Implemented ML-KEM-768 Operations

- Buffer size retrieval
- Public and secret keypair generation
- Shared-secret encapsulation
- Shared-secret decapsulation
- Sensitive memory cleanup

## 5. Rust Safe Wrappers

The src/safe.rs module provides:

- mlkem768_get_sizes()
- mlkem768_keypair()
- mlkem768_encapsulate()
- mlkem768_decapsulate()
- safe_add()
- xor_buffer()

The CryptoError enum handles null pointers, invalid lengths, unavailable libraries, failed operations and unknown status codes.

Secret key and shared-secret buffers are stored in SecretBytes. Its Drop implementation calls the C cleanup function when the value is dropped.

This is a basic cleanup mechanism and does not guarantee that every possible copy of sensitive data is erased.

## 6. ML-KEM-768 Buffer Sizes

| Parameter | Size |
|-----------|------:|
| Public key | 1184 bytes |
| Secret key | 2400 bytes |
| Ciphertext | 1088 bytes |
| Shared secret | 32 bytes |

## 7. Build Requirements

- Ubuntu Linux
- Rust and Cargo
- GCC and C compiler toolchain
- Open Quantum Safe liboqs 0.16.0
- ML-KEM-768 enabled in liboqs

The current build configuration links liboqs from /usr/local/lib.

## 8. Build and Test

Run commands from the rust-ffi directory.

Build:

    cargo build

Run tests:

    cargo test

Check formatting:

    cargo fmt -- --check

Run Clippy:

    cargo clippy --all-targets

## 9. Integration Test Coverage

The test suite verifies:

1. C function calls through Rust.
2. C buffer processing.
3. Empty buffer handling.
4. Null pointer error mapping.
5. Unknown error mapping.
6. Buffer boundary safety.
7. ML-KEM-768 buffer sizes.
8. Keypair generation.
9. Encapsulation and decapsulation.
10. Shared-secret equality.
11. Invalid public-key length handling.

Latest verified result:

**10 tests passed, 0 failed.**

## 10. Security Notes

- Rust wrappers check C operation status codes.
- C functions validate buffer lengths.
- Secret buffers are cleared through liboqs cleanup functionality when dropped.
- Raw pointers require valid buffers and correct lifetimes.
- The current cleanup implementation is not a complete production-grade key-management solution.

## 11. Current Scope and Limitations

This module establishes the Rust-to-C bridge for ML-KEM-768.

ML-KEM establishes a shared secret; it does not directly encrypt files or arbitrary messages.

Actual file encryption requires a symmetric authenticated encryption algorithm such as AES-256-GCM and integration with the filesystem module.

Filesystem hooks, complete file encryption/decryption, persistent key management and CLI development are outside the current scope of this FFI module.

## 12. Module Responsibility

**Member 2 - Rust/C FFI Integration**

Responsibilities covered:

- Rust project and FFI setup.
- C function declarations in Rust.
- ML-KEM-768 C interface integration.
- Safe Rust wrappers.
- Error handling.
- Buffer management.
- Basic sensitive-memory cleanup.
- Rust-to-C integration testing.
