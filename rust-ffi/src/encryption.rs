use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"QVAULT01";
const VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 1 + SALT_LEN + NONCE_LEN;

const HKDF_INFO: &[u8] = b"QuantumVault AES-256-GCM file encryption v1";

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionError {
    InvalidSharedSecretLength,
    RandomnessFailed,
    InvalidFormat,
    KeyDerivationFailed,
    EncryptionFailed,
    AuthenticationFailed,
    FileOperationFailed,
    OutputAlreadyExists,
}

fn derive_key(shared_secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, EncryptionError> {
    if shared_secret.len() != 32 {
        return Err(EncryptionError::InvalidSharedSecretLength);
    }

    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);

    hkdf.expand(HKDF_INFO, key.as_mut())
        .map_err(|_| EncryptionError::KeyDerivationFailed)?;

    Ok(key)
}

/// Encrypts data using a 32-byte ML-KEM shared secret.
pub fn encrypt(plaintext: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if shared_secret.len() != 32 {
        return Err(EncryptionError::InvalidSharedSecretLength);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];

    getrandom::getrandom(&mut salt).map_err(|_| EncryptionError::RandomnessFailed)?;

    getrandom::getrandom(&mut nonce).map_err(|_| EncryptionError::RandomnessFailed)?;

    let key = derive_key(shared_secret, &salt)?;

    let cipher =
        Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| EncryptionError::EncryptionFailed)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let payload = Payload {
        msg: plaintext,
        aad: &header,
    };

    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    let mut output = header;
    output.extend_from_slice(&encrypted);

    Ok(output)
}

/// Decrypts and authenticates a QuantumVault encrypted container.
pub fn decrypt(container: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if shared_secret.len() != 32 {
        return Err(EncryptionError::InvalidSharedSecretLength);
    }

    if container.len() < HEADER_LEN + TAG_LEN {
        return Err(EncryptionError::InvalidFormat);
    }

    if &container[..8] != MAGIC || container[8] != VERSION {
        return Err(EncryptionError::InvalidFormat);
    }

    let salt = &container[9..9 + SALT_LEN];
    let nonce_start = 9 + SALT_LEN;
    let nonce_end = nonce_start + NONCE_LEN;

    let nonce = &container[nonce_start..nonce_end];
    let encrypted = &container[HEADER_LEN..];
    let header = &container[..HEADER_LEN];

    let key = derive_key(shared_secret, salt)?;

    let cipher =
        Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| EncryptionError::EncryptionFailed)?;

    let payload = Payload {
        msg: encrypted,
        aad: header,
    };

    cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| EncryptionError::AuthenticationFailed)
}

/// Creates a new output file without overwriting an existing file.
fn write_new_file(output_path: &Path, data: &[u8]) -> Result<(), EncryptionError> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(EncryptionError::OutputAlreadyExists);
        }
        Err(_) => return Err(EncryptionError::FileOperationFailed),
    };

    if file.write_all(data).is_err() {
        drop(file);
        let _ = fs::remove_file(output_path);
        return Err(EncryptionError::FileOperationFailed);
    }

    if file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(output_path);
        return Err(EncryptionError::FileOperationFailed);
    }

    Ok(())
}

/// Reads a plaintext file, encrypts it, and saves a new encrypted container.
///
/// Existing output files are never overwritten.
pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    shared_secret: &[u8],
) -> Result<(), EncryptionError> {
    let plaintext = fs::read(input_path).map_err(|_| EncryptionError::FileOperationFailed)?;

    let encrypted = encrypt(&plaintext, shared_secret)?;

    write_new_file(output_path.as_ref(), &encrypted)
}

/// Reads an encrypted container, authenticates and decrypts it,
/// then saves the plaintext to a new output file.
///
/// No output file is created if authentication fails.
/// Existing output files are never overwritten.
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    shared_secret: &[u8],
) -> Result<(), EncryptionError> {
    let container = fs::read(input_path).map_err(|_| EncryptionError::FileOperationFailed)?;

    let plaintext = decrypt(&container, shared_secret)?;

    write_new_file(output_path.as_ref(), &plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_path(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

        std::env::temp_dir().join(format!(
            "quantumvault_{}_{}_{}",
            std::process::id(),
            id,
            name
        ))
    }

    fn cleanup(paths: &[&Path]) {
        for path in paths {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn encryption_decryption_roundtrip() {
        let secret = [42u8; 32];
        let plaintext = b"QuantumVault confidential file";

        let encrypted = encrypt(plaintext, &secret).unwrap();
        let decrypted = decrypt(&encrypted, &secret).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_file_roundtrip() {
        let secret = [7u8; 32];
        let encrypted = encrypt(b"", &secret).unwrap();
        let decrypted = decrypt(&encrypted, &secret).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let secret = [42u8; 32];
        let wrong_secret = [99u8; 32];
        let encrypted = encrypt(b"secret data", &secret).unwrap();

        assert_eq!(
            decrypt(&encrypted, &wrong_secret),
            Err(EncryptionError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        let secret = [42u8; 32];
        let mut encrypted = encrypt(b"important data", &secret).unwrap();

        let last_index = encrypted.len() - 1;
        encrypted[last_index] ^= 0x01;

        assert_eq!(
            decrypt(&encrypted, &secret),
            Err(EncryptionError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_header_is_rejected() {
        let secret = [42u8; 32];
        let mut encrypted = encrypt(b"important data", &secret).unwrap();

        encrypted[9] ^= 0x01;

        assert_eq!(
            decrypt(&encrypted, &secret),
            Err(EncryptionError::AuthenticationFailed)
        );
    }

    #[test]
    fn invalid_container_is_rejected() {
        let secret = [42u8; 32];

        assert_eq!(
            decrypt(b"invalid", &secret),
            Err(EncryptionError::InvalidFormat)
        );
    }

    #[test]
    fn invalid_shared_secret_length_is_rejected() {
        let short_secret = [1u8; 16];

        assert_eq!(
            encrypt(b"data", &short_secret),
            Err(EncryptionError::InvalidSharedSecretLength)
        );

        assert_eq!(
            decrypt(b"invalid", &short_secret),
            Err(EncryptionError::InvalidSharedSecretLength)
        );
    }

    #[test]
    fn each_encryption_uses_a_fresh_container() {
        let secret = [42u8; 32];
        let plaintext = b"same plaintext";

        let first = encrypt(plaintext, &secret).unwrap();
        let second = encrypt(plaintext, &secret).unwrap();

        assert_ne!(first, second);
        assert_eq!(decrypt(&first, &secret).unwrap(), plaintext);
        assert_eq!(decrypt(&second, &secret).unwrap(), plaintext);
    }

    #[test]
    fn file_encryption_decryption_roundtrip() {
        let input = test_path("original.txt");
        let encrypted = test_path("encrypted.qv");
        let decrypted = test_path("decrypted.txt");

        let secret = [42u8; 32];
        let original = b"QuantumVault persistent encrypted storage test";

        fs::write(&input, original).unwrap();

        let result = encrypt_file(&input, &encrypted, &secret);
        assert_eq!(result, Ok(()));

        let result = decrypt_file(&encrypted, &decrypted, &secret);
        assert_eq!(result, Ok(()));

        assert_eq!(fs::read(&decrypted).unwrap(), original);

        cleanup(&[&input, &encrypted, &decrypted]);
    }

    #[test]
    fn wrong_key_does_not_create_plaintext_output() {
        let input = test_path("wrong_key_input.qv");
        let output = test_path("wrong_key_output.txt");

        let secret = [42u8; 32];
        let wrong_secret = [99u8; 32];

        let encrypted = encrypt(b"confidential data", &secret).unwrap();
        fs::write(&input, encrypted).unwrap();

        let result = decrypt_file(&input, &output, &wrong_secret);

        assert_eq!(result, Err(EncryptionError::AuthenticationFailed));
        assert!(!output.exists());

        cleanup(&[&input, &output]);
    }

    #[test]
    fn existing_output_is_not_overwritten() {
        let input = test_path("no_overwrite_input.txt");
        let output = test_path("no_overwrite_output.qv");

        let secret = [42u8; 32];

        fs::write(&input, b"original input").unwrap();
        fs::write(&output, b"existing output").unwrap();

        let result = encrypt_file(&input, &output, &secret);

        assert_eq!(result, Err(EncryptionError::OutputAlreadyExists));
        assert_eq!(fs::read(&output).unwrap(), b"existing output");

        cleanup(&[&input, &output]);
    }
}
