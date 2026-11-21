use crate::safe::{CryptoError, MlKem768KeyPair, mlkem768_get_sizes};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

const PRIVATE_MAGIC: &[u8; 8] = b"QVKEY001";
const KEYPAIR_MAGIC: &[u8; 8] = b"QVKEY002";
const VERSION: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 1 + SALT_LEN + NONCE_LEN;

const KEY_LEN: usize = 32;

// Argon2id parameters: 19 MiB memory, 2 iterations, 1 lane.
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyManagementError {
    EmptyPassphrase,
    EmptyPrivateKey,
    RandomnessFailed,
    InvalidFormat,
    InvalidKeyPair,
    KeyDerivationFailed,
    EncryptionFailed,
    AuthenticationFailed,
    CryptoOperationFailed,
    FileOperationFailed,
    OutputAlreadyExists,
}

impl From<CryptoError> for KeyManagementError {
    fn from(_: CryptoError) -> Self {
        Self::CryptoOperationFailed
    }
}

/// Derives an AES-256 key from a passphrase and salt using Argon2id.
fn derive_passphrase_key(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, KeyManagementError> {
    if passphrase.is_empty() {
        return Err(KeyManagementError::EmptyPassphrase);
    }

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|_| KeyManagementError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);

    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| KeyManagementError::KeyDerivationFailed)?;

    Ok(key)
}

/// Generates a fresh salt and nonce.
fn generate_salt_and_nonce() -> Result<([u8; SALT_LEN], [u8; NONCE_LEN]), KeyManagementError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];

    getrandom::getrandom(&mut salt).map_err(|_| KeyManagementError::RandomnessFailed)?;

    getrandom::getrandom(&mut nonce).map_err(|_| KeyManagementError::RandomnessFailed)?;

    Ok((salt, nonce))
}

/// Encrypts data using AES-256-GCM with authenticated header data.
fn encrypt_payload(
    plaintext: &[u8],
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    header: &[u8],
) -> Result<Vec<u8>, KeyManagementError> {
    let key = derive_passphrase_key(passphrase, salt)?;

    let cipher =
        Aes256Gcm::new_from_slice(&key[..]).map_err(|_| KeyManagementError::EncryptionFailed)?;

    let payload = Payload {
        msg: plaintext,
        aad: header,
    };

    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| KeyManagementError::EncryptionFailed)
}

/// Authenticates and decrypts data using AES-256-GCM.
fn decrypt_payload(
    encrypted: &[u8],
    passphrase: &[u8],
    salt: &[u8],
    nonce: &[u8],
    header: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyManagementError> {
    let key = derive_passphrase_key(passphrase, salt)?;

    let cipher =
        Aes256Gcm::new_from_slice(&key[..]).map_err(|_| KeyManagementError::EncryptionFailed)?;

    let payload = Payload {
        msg: encrypted,
        aad: header,
    };

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| KeyManagementError::AuthenticationFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypts private-key bytes using a passphrase.
///
/// Container format:
/// Magic | Version | Salt | Nonce | Encrypted private key + GCM tag
pub fn protect_private_key(
    private_key: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, KeyManagementError> {
    if private_key.is_empty() {
        return Err(KeyManagementError::EmptyPrivateKey);
    }

    if passphrase.is_empty() {
        return Err(KeyManagementError::EmptyPassphrase);
    }

    let (salt, nonce) = generate_salt_and_nonce()?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(PRIVATE_MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let encrypted = encrypt_payload(private_key, passphrase, &salt, &nonce, &header)?;

    let mut output = header;
    output.extend_from_slice(&encrypted);

    Ok(output)
}

/// Authenticates and decrypts a protected private-key container.
pub fn unprotect_private_key(
    container: &[u8],
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyManagementError> {
    if passphrase.is_empty() {
        return Err(KeyManagementError::EmptyPassphrase);
    }

    if container.len() < HEADER_LEN + TAG_LEN {
        return Err(KeyManagementError::InvalidFormat);
    }

    if &container[..8] != PRIVATE_MAGIC || container[8] != VERSION {
        return Err(KeyManagementError::InvalidFormat);
    }

    let salt_start = 9;
    let salt_end = salt_start + SALT_LEN;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LEN;

    let salt = &container[salt_start..salt_end];
    let nonce = &container[nonce_start..nonce_end];
    let header = &container[..HEADER_LEN];
    let encrypted = &container[HEADER_LEN..];

    decrypt_payload(encrypted, passphrase, salt, nonce, header)
}

/// Encrypts an actual ML-KEM-768 keypair.
///
/// The public key is authenticated as part of the header.
/// The secret key is encrypted as the payload.
pub fn protect_keypair(
    keypair: &MlKem768KeyPair,
    passphrase: &[u8],
) -> Result<Vec<u8>, KeyManagementError> {
    if passphrase.is_empty() {
        return Err(KeyManagementError::EmptyPassphrase);
    }

    let (public_len, secret_len, _, _) = mlkem768_get_sizes()?;

    if keypair.public_key.len() != public_len || keypair.secret_key_bytes().len() != secret_len {
        return Err(KeyManagementError::InvalidKeyPair);
    }

    let (salt, nonce) = generate_salt_and_nonce()?;

    let mut header = Vec::new();
    header.extend_from_slice(KEYPAIR_MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&keypair.public_key);

    let encrypted = encrypt_payload(
        keypair.secret_key_bytes(),
        passphrase,
        &salt,
        &nonce,
        &header,
    )?;

    let mut output = header;
    output.extend_from_slice(&encrypted);

    Ok(output)
}

/// Restores an ML-KEM-768 keypair from an authenticated container.
pub fn unprotect_keypair(
    container: &[u8],
    passphrase: &[u8],
) -> Result<MlKem768KeyPair, KeyManagementError> {
    if passphrase.is_empty() {
        return Err(KeyManagementError::EmptyPassphrase);
    }

    let (public_len, secret_len, _, _) = mlkem768_get_sizes()?;

    let keypair_header_len = HEADER_LEN + public_len;
    let expected_len = keypair_header_len + secret_len + TAG_LEN;

    if container.len() != expected_len {
        return Err(KeyManagementError::InvalidFormat);
    }

    if &container[..8] != KEYPAIR_MAGIC || container[8] != VERSION {
        return Err(KeyManagementError::InvalidFormat);
    }

    let salt_start = 9;
    let salt_end = salt_start + SALT_LEN;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LEN;

    let salt = &container[salt_start..salt_end];
    let nonce = &container[nonce_start..nonce_end];

    let public_key = &container[HEADER_LEN..keypair_header_len];
    let header = &container[..keypair_header_len];
    let encrypted_secret = &container[keypair_header_len..];

    let secret_key = decrypt_payload(encrypted_secret, passphrase, salt, nonce, header)?;

    if secret_key.len() != secret_len {
        return Err(KeyManagementError::InvalidKeyPair);
    }

    MlKem768KeyPair::from_parts(public_key.to_vec(), secret_key.to_vec())
        .map_err(|_| KeyManagementError::InvalidKeyPair)
}

/// Writes encrypted data without overwriting an existing file.
fn write_new_file(data: &[u8], output_path: impl AsRef<Path>) -> Result<(), KeyManagementError> {
    let path = output_path.as_ref();

    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(KeyManagementError::OutputAlreadyExists);
        }
        Err(_) => return Err(KeyManagementError::FileOperationFailed),
    };

    if file.write_all(data).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(KeyManagementError::FileOperationFailed);
    }

    Ok(())
}

/// Saves protected private-key data.
pub fn protect_private_key_file(
    private_key: &[u8],
    passphrase: &[u8],
    output_path: impl AsRef<Path>,
) -> Result<(), KeyManagementError> {
    let container = protect_private_key(private_key, passphrase)?;
    write_new_file(&container, output_path)
}

/// Reads and unlocks a protected private-key file.
pub fn unprotect_private_key_file(
    input_path: impl AsRef<Path>,
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyManagementError> {
    let container = fs::read(input_path).map_err(|_| KeyManagementError::FileOperationFailed)?;

    unprotect_private_key(&container, passphrase)
}

/// Saves a passphrase-protected ML-KEM-768 keypair.
pub fn protect_keypair_file(
    keypair: &MlKem768KeyPair,
    passphrase: &[u8],
    output_path: impl AsRef<Path>,
) -> Result<(), KeyManagementError> {
    let container = protect_keypair(keypair, passphrase)?;
    write_new_file(&container, output_path)
}

/// Loads and unlocks an ML-KEM-768 keypair from a file.
pub fn unprotect_keypair_file(
    input_path: impl AsRef<Path>,
    passphrase: &[u8],
) -> Result<MlKem768KeyPair, KeyManagementError> {
    let container = fs::read(input_path).map_err(|_| KeyManagementError::FileOperationFailed)?;

    unprotect_keypair(&container, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safe::{mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keypair};

    #[test]
    fn private_key_protection_roundtrip() {
        let private_key = vec![42u8; 2400];
        let passphrase = b"test-passphrase";

        let protected = protect_private_key(&private_key, passphrase).unwrap();

        let recovered = unprotect_private_key(&protected, passphrase).unwrap();

        assert_eq!(&recovered[..], &private_key[..]);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let private_key = vec![7u8; 2400];

        let protected = protect_private_key(&private_key, b"correct-passphrase").unwrap();

        let result = unprotect_private_key(&protected, b"wrong-passphrase");

        assert_eq!(result, Err(KeyManagementError::AuthenticationFailed));
    }

    #[test]
    fn modified_container_is_rejected() {
        let private_key = vec![9u8; 2400];

        let mut protected = protect_private_key(&private_key, b"test-passphrase").unwrap();

        let last_index = protected.len() - 1;
        protected[last_index] ^= 1;

        assert_eq!(
            unprotect_private_key(&protected, b"test-passphrase"),
            Err(KeyManagementError::AuthenticationFailed)
        );
    }

    #[test]
    fn invalid_container_is_rejected() {
        assert_eq!(
            unprotect_private_key(b"invalid", b"test-passphrase"),
            Err(KeyManagementError::InvalidFormat)
        );
    }

    #[test]
    fn empty_passphrase_is_rejected() {
        assert_eq!(
            protect_private_key(b"private-key", b""),
            Err(KeyManagementError::EmptyPassphrase)
        );
    }

    #[test]
    fn empty_private_key_is_rejected() {
        assert_eq!(
            protect_private_key(b"", b"test-passphrase"),
            Err(KeyManagementError::EmptyPrivateKey)
        );
    }

    #[test]
    fn each_protection_uses_a_fresh_container() {
        let private_key = vec![11u8; 2400];
        let passphrase = b"test-passphrase";

        let first = protect_private_key(&private_key, passphrase).unwrap();

        let second = protect_private_key(&private_key, passphrase).unwrap();

        assert_ne!(first, second);

        assert_eq!(
            &unprotect_private_key(&first, passphrase).unwrap()[..],
            &private_key[..]
        );
    }

    #[test]
    fn mlkem_keypair_protection_roundtrip() {
        let original = mlkem768_keypair().unwrap();

        let protected = protect_keypair(&original, b"strong-test-passphrase").unwrap();

        let restored = unprotect_keypair(&protected, b"strong-test-passphrase").unwrap();

        let encapsulation = mlkem768_encapsulate(&restored.public_key).unwrap();

        let recovered = mlkem768_decapsulate(&encapsulation.ciphertext, &restored).unwrap();

        assert_eq!(encapsulation.shared_secret.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn mlkem_keypair_wrong_passphrase_is_rejected() {
        let original = mlkem768_keypair().unwrap();

        let protected = protect_keypair(&original, b"correct-passphrase").unwrap();

        assert_eq!(
            unprotect_keypair(&protected, b"wrong-passphrase").err(),
            Some(KeyManagementError::AuthenticationFailed)
        );
    }

    #[test]
    fn mlkem_keypair_tampering_is_rejected() {
        let original = mlkem768_keypair().unwrap();

        let mut protected = protect_keypair(&original, b"test-passphrase").unwrap();

        let last_index = protected.len() - 1;
        protected[last_index] ^= 1;

        assert_eq!(
            unprotect_keypair(&protected, b"test-passphrase").err(),
            Some(KeyManagementError::AuthenticationFailed)
        );
    }
}
