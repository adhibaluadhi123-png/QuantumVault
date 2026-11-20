use crate::ffi;

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    NullPointer,
    InvalidLength,
    LibraryUnavailable,
    OperationFailed,
    UnknownStatus(i32),
}

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

// Stores sensitive bytes and cleanses them when dropped.
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        unsafe {
            ffi::crypto_secure_cleanse(
                self.bytes.as_mut_ptr(),
                self.bytes.len(),
            );
        }
    }
}

pub struct MlKem768KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: SecretBytes,
}

pub struct MlKem768Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: SecretBytes,
}

// Retrieve ML-KEM-768 buffer sizes.
pub fn mlkem768_get_sizes() -> Result<(usize, usize, usize, usize), CryptoError> {
    let (mut pk, mut sk, mut ct, mut ss) = (0, 0, 0, 0);

    let status = unsafe {
        ffi::crypto_mlkem768_get_sizes(
            &mut pk,
            &mut sk,
            &mut ct,
            &mut ss,
        )
    };

    check_status(status)?;
    Ok((pk, sk, ct, ss))
}

// Generate an ML-KEM-768 key pair.
pub fn mlkem768_keypair() -> Result<MlKem768KeyPair, CryptoError> {
    let (pk_len, sk_len, _, _) = mlkem768_get_sizes()?;

    let mut public_key = vec![0; pk_len];
    let mut secret_key = SecretBytes::new(sk_len);

    let status = unsafe {
        ffi::crypto_mlkem768_keypair(
            public_key.as_mut_ptr(),
            pk_len,
            secret_key.as_mut_ptr(),
            sk_len,
        )
    };

    check_status(status)?;

    Ok(MlKem768KeyPair {
        public_key,
        secret_key,
    })
}

// Encapsulate using the recipient's public key.
pub fn mlkem768_encapsulate(
    public_key: &[u8],
) -> Result<MlKem768Encapsulation, CryptoError> {
    let (pk_len, _, ct_len, ss_len) = mlkem768_get_sizes()?;

    if public_key.len() != pk_len {
        return Err(CryptoError::InvalidLength);
    }

    let mut ciphertext = vec![0; ct_len];
    let mut shared_secret = SecretBytes::new(ss_len);

    let status = unsafe {
        ffi::crypto_mlkem768_encapsulate(
            ciphertext.as_mut_ptr(),
            ct_len,
            shared_secret.as_mut_ptr(),
            ss_len,
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

// Decapsulate using the recipient's secret key.
pub fn mlkem768_decapsulate(
    ciphertext: &[u8],
    secret_key: &SecretBytes,
) -> Result<SecretBytes, CryptoError> {
    let (_, sk_len, ct_len, ss_len) = mlkem768_get_sizes()?;

    if ciphertext.len() != ct_len || secret_key.len() != sk_len {
        return Err(CryptoError::InvalidLength);
    }

    let mut shared_secret = SecretBytes::new(ss_len);

    let status = unsafe {
        ffi::crypto_mlkem768_decapsulate(
            shared_secret.as_mut_ptr(),
            ss_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
            secret_key.as_slice().as_ptr(),
            secret_key.len(),
        )
    };

    check_status(status)?;

    Ok(shared_secret)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem768_sizes() {
        let sizes = mlkem768_get_sizes().unwrap();

        assert_eq!(sizes, (1184, 2400, 1088, 32));
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = mlkem768_keypair().unwrap();

        assert_eq!(keypair.public_key.len(), 1184);
        assert_eq!(keypair.secret_key.len(), 2400);
    }

    #[test]
    fn test_encapsulation_and_decapsulation() {
        let keypair = mlkem768_keypair().unwrap();

        let encapsulation =
            mlkem768_encapsulate(&keypair.public_key).unwrap();

        let recovered_secret = mlkem768_decapsulate(
            &encapsulation.ciphertext,
            &keypair.secret_key,
        )
        .unwrap();

        assert_eq!(
            encapsulation.shared_secret.as_slice(),
            recovered_secret.as_slice()
        );
    }

    #[test]
    fn test_invalid_public_key_length() {
        let result = mlkem768_encapsulate(&[0u8; 10]);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidLength)));
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let keypair = mlkem768_keypair().unwrap();

        let result =
            mlkem768_decapsulate(&[0u8; 10], &keypair.secret_key);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidLength)));
    }
}
