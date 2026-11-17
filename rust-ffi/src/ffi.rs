use std::ffi::c_int;
use std::os::raw::c_uchar;

// C function declarations for Rust-C FFI integration.
//
// General safety contract:
// - C functions must follow the declared ABI and signatures.
// - crypto_xor_buffer must access only the provided len bytes.
// - It must not retain the pointer after returning.
// - For len == 0, it must not dereference the pointer.

unsafe extern "C" {
    /// Adds two signed integers using the C engine.
    ///
    /// # Safety
    /// The C implementation must follow the declared ABI and signature.
    pub fn crypto_add(a: i32, b: i32) -> i32;

    /// Applies XOR to a mutable byte buffer using the C engine.
    ///
    /// # Safety
    /// - If len is greater than zero, data must point to a valid writable buffer.
    /// - The buffer must contain at least len bytes.
    /// - The C function must not access bytes outside the buffer.
    /// - The pointer must not be retained after the function returns.
    /// - If len is zero, the pointer must not be dereferenced.
    pub fn crypto_xor_buffer(data: *mut c_uchar, len: usize, key: c_uchar) -> c_int;
}
