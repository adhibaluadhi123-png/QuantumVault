use std::ffi::c_int;
use std::os::raw::c_uchar;

// C function declarations for Rust-C FFI integration.
//
// Safety contract:
// - C functions must follow the declared ABI and signatures.
// - crypto_xor_buffer must access only the provided len bytes.
// - It must not retain the pointer after returning.
// - For len == 0, it must not dereference the pointer.

unsafe extern "C" {
    pub fn crypto_add(a: i32, b: i32) -> i32;

    pub fn crypto_xor_buffer(data: *mut c_uchar, len: usize, key: c_uchar) -> c_int;
}
