use std::ffi::c_int;

// Rust declarations for the C crypto engine.
//
// Safety requirements:
// - All pointers must refer to valid buffers of the supplied lengths.
// - Output buffers must be writable.
// - Input buffers must remain valid for the duration of the call.
// - C must not retain any supplied pointer after returning.

unsafe extern "C" {
    /// Adds two signed integers using C.
    pub fn crypto_add(a: i32, b: i32) -> i32;

    /// Applies XOR to a mutable byte buffer.
    pub fn crypto_xor_buffer(data: *mut u8, len: usize, key: u8) -> c_int;

    /// Retrieves the required ML-KEM-768 buffer sizes.
    pub fn crypto_mlkem768_get_sizes(
        public_key_len: *mut usize,
        secret_key_len: *mut usize,
        ciphertext_len: *mut usize,
        shared_secret_len: *mut usize,
    ) -> c_int;

    /// Generates an ML-KEM-768 public and secret keypair.
    pub fn crypto_mlkem768_keypair(
        public_key: *mut u8,
        public_key_len: usize,
        secret_key: *mut u8,
        secret_key_len: usize,
    ) -> c_int;

    /// Encapsulates a shared secret using an ML-KEM-768 public key.
    pub fn crypto_mlkem768_encapsulate(
        ciphertext: *mut u8,
        ciphertext_len: usize,
        shared_secret: *mut u8,
        shared_secret_len: usize,
        public_key: *const u8,
        public_key_len: usize,
    ) -> c_int;

    /// Recovers the shared secret using an ML-KEM-768 secret key.
    pub fn crypto_mlkem768_decapsulate(
        shared_secret: *mut u8,
        shared_secret_len: usize,
        ciphertext: *const u8,
        ciphertext_len: usize,
        secret_key: *const u8,
        secret_key_len: usize,
    ) -> c_int;

    /// Clears sensitive memory through liboqs.
    pub fn crypto_secure_cleanse(data: *mut u8, len: usize);
}
