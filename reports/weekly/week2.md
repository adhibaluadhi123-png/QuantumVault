# QuantumVault – Week 2 Progress Report

**Role:** Member 2 – Rust/C FFI Integration
**Project:** QuantumVault – Post-Quantum Cryptography Local Filesystem

## 1. Objective

The objective of Week 2 was to integrate the ML-KEM-768 C cryptographic functions with Rust through Foreign Function Interface (FFI) and provide safer Rust interfaces for cryptographic operations.

## 2. Work Completed

### 2.1 Rust FFI Declarations
- Added Rust declarations for the C ML-KEM-768 functions.
- Connected Rust declarations with the C crypto interface.
- Added functions for retrieving cryptographic buffer sizes.
- Added declarations for keypair generation, encapsulation and decapsulation.

### 2.2 C Crypto Engine Integration
- Integrated the C wrapper with Open Quantum Safe liboqs.
- Connected ML-KEM-768 keypair generation to Rust.
- Connected shared-secret encapsulation to Rust.
- Connected shared-secret decapsulation to Rust.
- Configured Cargo to compile the C source and link liboqs and its dependencies.

### 2.3 Safe Rust Wrappers
Implemented Rust-friendly wrapper functions:

- `mlkem768_get_sizes()`
- `mlkem768_keypair()`
- `mlkem768_encapsulate()`
- `mlkem768_decapsulate()`

These wrappers allocate buffers and provide Rust Result-based error handling.

### 2.4 Error Handling and Buffer Validation
- Implemented the `CryptoError` enum.
- Added mapping for null pointer, invalid length, unavailable library and operation failure errors.
- Added unknown status code handling.
- Validated buffer sizes in the C crypto functions.
- Added tests for invalid input and buffer boundary handling.

### 2.5 Sensitive Memory Cleanup
- Implemented a `SecretBytes` wrapper.
- Added a Drop implementation to call the C memory cleanup function.
- Integrated liboqs memory cleansing functionality for sensitive buffers.

This provides basic cleanup when secret buffers are dropped. It is not a complete production-grade key-management solution.

## 3. Testing and Verification

Executed the Rust test suite using:

`cargo test`

Verified:
1. C function calls through Rust.
2. C buffer processing.
3. Empty buffer handling.
4. Null pointer error mapping.
5. Unknown error mapping.
6. Buffer boundary safety.
7. ML-KEM-768 buffer sizes.
8. Keypair generation.
9. Encapsulation and decapsulation.
10. Shared-secret equality verification.
11. Invalid public-key length handling.

**Test Result: 10 passed, 0 failed.**

Additional verification:
- `cargo fmt -- --check` – Passed.
- `cargo clippy --all-targets` – Passed.
- `git diff --check` – Passed.

## 4. Technical Results

The verified ML-KEM-768 buffer sizes are:

| Parameter | Size |
|-----------|------|
| Public key | 1184 bytes |
| Secret key | 2400 bytes |
| Ciphertext | 1088 bytes |
| Shared secret | 32 bytes |

The Rust integration successfully generated a keypair, encapsulated a shared secret and recovered the same shared secret through decapsulation.

## 5. Documentation and Version Control

- Created technical documentation for the Rust/C FFI module.
- Documented architecture, implemented functions, testing and security limitations.
- Committed and pushed the implementation to the `tanisha` GitHub branch.
- Added the Week 2 integration work to the project history.

## 6. Learning Outcomes

- Improved understanding of Rust unsafe FFI boundaries.
- Learned how to connect C cryptographic functions with Rust.
- Understood safe buffer handling and error conversion.
- Learned the importance of sensitive-memory cleanup.
- Verified the ML-KEM-768 key encapsulation workflow through Rust.

## 7. Current Scope and Limitations

The Rust/C FFI bridge for ML-KEM-768 is implemented and tested.

ML-KEM establishes a shared secret; it does not directly encrypt files.

Actual file encryption requires a symmetric authenticated encryption algorithm such as AES-256-GCM and integration with the filesystem module.

Complete filesystem encryption/decryption, persistent key management and CLI integration are not claimed as completed by this FFI module.

## 8. Week 2 Outcome

The Rust/C FFI integration for ML-KEM-768 was successfully implemented and verified with 10 passing tests.

The module now provides Rust declarations, safe wrappers, error handling, buffer validation and basic sensitive-memory cleanup.

## 9. Next Steps

- Verify compatibility with the final team crypto-engine interface.
- Perform integration testing with the filesystem module when available.
- Support any required API adjustments during team integration.
