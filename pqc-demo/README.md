# QuantumVault - ML-KEM-768 C Demonstration

## Overview
Demonstrates ML-KEM-768 using Open Quantum Safe liboqs 0.16.0.

## Implemented Operations
1. Keypair generation
2. Encapsulation
3. Decapsulation
4. Shared secret comparison
5. Secret buffer cleanup

## Compilation
    gcc mlkem_demo.c -o mlkem_demo $(PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --cflags --static --libs liboqs)

## Execution
    ./mlkem_demo

## Test Results
- Keypair Generation: SUCCESS
- Encapsulation: SUCCESS
- Decapsulation: SUCCESS
- Shared Secret Verification: SUCCESS

**Result: ML-KEM-768 TEST PASSED**

## Important Note
ML-KEM establishes a shared secret; it does not directly encrypt messages.
A symmetric authenticated encryption algorithm such as AES-GCM is needed for file encryption.
