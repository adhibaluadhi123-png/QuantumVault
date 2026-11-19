use crate::ffi;

/// Errors returned by the C crypto engine.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    NullPointer,
    InvalidLength,
    LibraryUnavailable,
    OperationFailed,
    UnknownStatus(i32),
}

/// Converts C status codes into Rust errors.
fn check_status(status: i32) -> Result<(), CryptoError> {
    match status {
        0 => Ok(()),
        -1 => Err(CryptoError::NullPointer),
        -2 => Err(CryptoError::InvalidLength),
        -3 => Err(CryptoError::LibraryUnavailable),
        -4 => Err(CryptoError::OperationFailed),
        other => Err(CryptoError::UnknownStatus(other)),
    }
}

/// Holds sensitive bytes and clears them when dropped.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Provides read-only access to the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        unsafe {
            ffi::crypto_secure_cleanse(self.0.as_mut_ptr(), self.0.len());
        }
    }
}

/// An ML-KEM-768 public and secret keypair.
pub struct MlKem768KeyPair {
    pub public_key: Vec<u8>,
    secret_key: SecretBytes,
}

/// The ciphertext and shared secret produced by encapsulation.
pub struct MlKem768Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: SecretBytes,
}

/// Returns the ML-KEM-768 buffer sizes.
pub fn mlkem768_get_sizes() -> Result<(usize, usize, usize, usize), CryptoError> {
    let mut public_key_len = 0;
    let mut secret_key_len = 0;
    let mut ciphertext_len = 0;
    let mut shared_secret_len = 0;

    let status = unsafe {
        ffi::crypto_mlkem768_get_sizes(
            &mut public_key_len,
            &mut secret_key_len,
            &mut ciphertext_len,
            &mut shared_secret_len,
        )
    };

    check_status(status)?;

    Ok((
        public_key_len,
        secret_key_len,
        ciphertext_len,
        shared_secret_len,
    ))
}

/// Generates an ML-KEM-768 keypair.
pub fn mlkem768_keypair() -> Result<MlKem768KeyPair, CryptoError> {
    let (public_key_len, secret_key_len, _, _) = mlkem768_get_sizes()?;

    let mut public_key = vec![0u8; public_key_len];
    let mut secret_key = SecretBytes(vec![0u8; secret_key_len]);

    let status = unsafe {
        ffi::crypto_mlkem768_keypair(
            public_key.as_mut_ptr(),
            public_key.len(),
            secret_key.0.as_mut_ptr(),
            secret_key.0.len(),
        )
    };

    check_status(status)?;

    Ok(MlKem768KeyPair {
        public_key,
        secret_key,
    })
}

/// Creates a ciphertext and shared secret using a public key.
pub fn mlkem768_encapsulate(public_key: &[u8]) -> Result<MlKem768Encapsulation, CryptoError> {
    let (_, _, ciphertext_len, shared_secret_len) = mlkem768_get_sizes()?;

    let mut ciphertext = vec![0u8; ciphertext_len];
    let mut shared_secret = SecretBytes(vec![0u8; shared_secret_len]);

    let status = unsafe {
        ffi::crypto_mlkem768_encapsulate(
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            shared_secret.0.as_mut_ptr(),
            shared_secret.0.len(),
            public_key.as_ptr(),
            public_key.len(),
        )
    };

    check_status(status)?;

    Ok(MlKem768Encapsulation {
        ciphertext,
        shared_secret,
    })
}

/// Recovers the shared secret using the keypair's secret key.
pub fn mlkem768_decapsulate(
    ciphertext: &[u8],
    keypair: &MlKem768KeyPair,
) -> Result<SecretBytes, CryptoError> {
    let (_, _, _, shared_secret_len) = mlkem768_get_sizes()?;

    let mut shared_secret = SecretBytes(vec![0u8; shared_secret_len]);

    let status = unsafe {
        ffi::crypto_mlkem768_decapsulate(
            shared_secret.0.as_mut_ptr(),
            shared_secret.0.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            keypair.secret_key.0.as_ptr(),
            keypair.secret_key.0.len(),
        )
    };

    check_status(status)?;

    Ok(shared_secret)
}

/// Safely calls the C crypto_add function.
pub fn safe_add(a: i32, b: i32) -> i32 {
    unsafe { ffi::crypto_add(a, b) }
}

/// Applies XOR to a mutable byte buffer using C.
pub fn xor_buffer(data: &mut [u8], key: u8) -> Result<(), CryptoError> {
    let status = unsafe { ffi::crypto_xor_buffer(data.as_mut_ptr(), data.len(), key) };

    check_status(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_function_through_rust() {
        assert_eq!(safe_add(10, 20), 30);
        assert_eq!(safe_add(-5, 2), -3);
        assert_eq!(safe_add(0, 0), 0);
    }

    #[test]
    fn test_c_buffer_processing() {
        let mut data = [0x10, 0x20, 0x30];

        let result = xor_buffer(&mut data, 0xFF);

        assert_eq!(result, Ok(()));
        assert_eq!(data, [0xEF, 0xDF, 0xCF]);
    }

    #[test]
    fn test_empty_buffer() {
        let mut data: [u8; 0] = [];

        let result = xor_buffer(&mut data, 0xFF);

        assert_eq!(result, Ok(()));
        assert_eq!(data.len(), 0);
    }

    #[test]
    fn test_null_pointer_error_mapping() {
        let status = unsafe { ffi::crypto_xor_buffer(std::ptr::null_mut(), 1, 0xFF) };

        assert_eq!(check_status(status), Err(CryptoError::NullPointer));
    }

    #[test]
    fn test_unknown_error_mapping() {
        assert_eq!(check_status(-5), Err(CryptoError::UnknownStatus(-5)));
    }

    #[test]
    fn test_buffer_boundary_safety() {
        let mut data = [0x10, 0x20, 0x30, 0x40];

        let result = xor_buffer(&mut data[..2], 0xFF);

        assert_eq!(result, Ok(()));
        assert_eq!(data, [0xEF, 0xDF, 0x30, 0x40]);
    }

    #[test]
    fn test_mlkem768_buffer_sizes() {
        let sizes = mlkem768_get_sizes().unwrap();

        assert_eq!(sizes, (1184, 2400, 1088, 32));
    }

    #[test]
    fn test_mlkem768_keypair_encapsulation_and_decapsulation() {
        let keypair = mlkem768_keypair().unwrap();

        assert_eq!(keypair.public_key.len(), 1184);

        let encapsulation = mlkem768_encapsulate(&keypair.public_key).unwrap();

        assert_eq!(encapsulation.ciphertext.len(), 1088);
        assert_eq!(encapsulation.shared_secret.as_bytes().len(), 32);

        let recovered_secret = mlkem768_decapsulate(&encapsulation.ciphertext, &keypair).unwrap();

        assert_eq!(
            encapsulation.shared_secret.as_bytes(),
            recovered_secret.as_bytes()
        );
    }

    #[test]
    fn test_mlkem768_rejects_invalid_public_key_length() {
        let result = mlkem768_encapsulate(&[]);

        assert!(matches!(result, Err(CryptoError::InvalidLength)));
    }
}
