# Day 6 – Rust–C FFI Integration

## 1. Objective

The objective of Day 6 was to understand and implement basic communication between Rust and C using the Foreign Function Interface (FFI).

## 2. C Engine Development

Created the following files:

- `c-engine/crypto.c`
- `c-engine/crypto.h`

Implemented a basic C function:

```c
int add_numbers(int a, int b) {
    return a + b;
}
```

This function was developed as an FFI practice exercise.

## 3. Cargo Build Configuration

Added the `cc` crate as a build dependency in `Cargo.toml`.

Created `build.rs` to compile the C source file and link the resulting library with the Rust project.

## 4. Rust–C FFI Implementation

Created `src/bin/ffi_demo.rs`.

Declared the C function using:

```rust
unsafe extern "C" {
    fn add_numbers(a: i32, b: i32) -> i32;
}
```

Called the C function from Rust:

```rust
let result = unsafe {
    add_numbers(10, 20)
};
```

## 5. Execution Result

Command:

```bash
cargo run --bin ffi_demo
```

Output:

```text
Result from C function: 30
```

This confirmed successful communication between Rust and C.

## 6. Unit Testing

Implemented three Rust unit tests:

1. `test_c_add_numbers`
2. `test_negative_numbers`
3. `test_zero_values`

Command:

```bash
cargo test --bin ffi_demo
```

Result:

- Total tests: 3
- Passed: 3
- Failed: 0

## 7. Build Verification

The following commands executed successfully:

```bash
cargo check
cargo build
cargo test
```

## 8. Day 6 Outcome

- Understood the basics of Rust–C FFI.
- Configured C compilation through Cargo.
- Successfully called a C function from Rust.
- Verified function results through automated unit tests.
- Established a foundation for future integration with the cryptographic engine.

**Status:** Basic Rust–C FFI integration completed.

**Next Step:** Study and integrate the actual cryptographic engine API developed by Member 2.

**Note:** The `add_numbers()` function is an FFI demonstration, not a cryptographic function. Post-quantum encryption has not yet been implemented.
