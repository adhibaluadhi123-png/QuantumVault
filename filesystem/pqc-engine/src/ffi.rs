use std::ffi::{c_int, c_uchar};

unsafe extern "C" {
    pub fn crypto_mlkem768_get_sizes(
        public_key_len: *mut usize,
        secret_key_len: *mut usize,
        ciphertext_len: *mut usize,
        shared_secret_len: *mut usize,
    ) -> c_int;

    pub fn crypto_mlkem768_keypair(
        public_key: *mut c_uchar,
        public_key_len: usize,
        secret_key: *mut c_uchar,
        secret_key_len: usize,
    ) -> c_int;

    pub fn crypto_mlkem768_encapsulate(
        ciphertext: *mut c_uchar,
        ciphertext_len: usize,
        shared_secret: *mut c_uchar,
        shared_secret_len: usize,
        public_key: *const c_uchar,
        public_key_len: usize,
    ) -> c_int;

    pub fn crypto_mlkem768_decapsulate(
        shared_secret: *mut c_uchar,
        shared_secret_len: usize,
        ciphertext: *const c_uchar,
        ciphertext_len: usize,
        secret_key: *const c_uchar,
        secret_key_len: usize,
    ) -> c_int;

    pub fn crypto_secure_cleanse(
        data: *mut c_uchar,
        len: usize,
    );
}
