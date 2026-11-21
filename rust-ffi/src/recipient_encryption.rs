use crate::safe::{
    CryptoError, MlKem768KeyPair, mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_get_sizes,
};

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

const MAGIC: &[u8; 8] = b"QVAULT02";
const VERSION: u8 = 1;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const LENGTH_FIELD_LEN: usize = 4;

const BASE_HEADER_LEN: usize = 8 + 1 + SALT_LEN + NONCE_LEN + LENGTH_FIELD_LEN;

const HKDF_INFO: &[u8] = b"QuantumVault recipient encryption QVAULT02";

#[derive(Debug, PartialEq, Eq)]
pub enum RecipientEncryptionError {
    InvalidPublicKey,
    InvalidFormat,
    RandomnessFailed,
    KeyDerivationFailed,
    KeyEncapsulationFailed,
    EncryptionFailed,
    AuthenticationFailed,
    FileOperationFailed,
    OutputAlreadyExists,
}

impl From<CryptoError> for RecipientEncryptionError {
    fn from(_: CryptoError) -> Self {
        Self::KeyEncapsulationFailed
    }
}

fn derive_key(
    shared_secret: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, RecipientEncryptionError> {
    if shared_secret.len() != 32 {
        return Err(RecipientEncryptionError::KeyDerivationFailed);
    }

    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);

    hkdf.expand(HKDF_INFO, key.as_mut())
        .map_err(|_| RecipientEncryptionError::KeyDerivationFailed)?;

    Ok(key)
}

/// Encrypts data for an ML-KEM-768 recipient.
///
/// Container format:
/// Magic | Version | Salt | Nonce | KEM ciphertext length
/// | ML-KEM ciphertext | AES-GCM ciphertext + tag
///
/// The complete header, including the ML-KEM ciphertext,
/// is authenticated as AES-GCM additional authenticated data.
pub fn encrypt_for_recipient(
    plaintext: &[u8],
    recipient_public_key: &[u8],
) -> Result<Vec<u8>, RecipientEncryptionError> {
    let (public_len, _, kem_ciphertext_len, _) = mlkem768_get_sizes()?;

    if recipient_public_key.len() != public_len {
        return Err(RecipientEncryptionError::InvalidPublicKey);
    }

    let encapsulation = mlkem768_encapsulate(recipient_public_key)?;

    if encapsulation.ciphertext.len() != kem_ciphertext_len {
        return Err(RecipientEncryptionError::InvalidFormat);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];

    getrandom::getrandom(&mut salt).map_err(|_| RecipientEncryptionError::RandomnessFailed)?;

    getrandom::getrandom(&mut nonce).map_err(|_| RecipientEncryptionError::RandomnessFailed)?;

    let key = derive_key(encapsulation.shared_secret.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| RecipientEncryptionError::EncryptionFailed)?;

    let kem_length = u32::try_from(encapsulation.ciphertext.len())
        .map_err(|_| RecipientEncryptionError::InvalidFormat)?;

    let mut header = Vec::with_capacity(BASE_HEADER_LEN + encapsulation.ciphertext.len());

    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&kem_length.to_be_bytes());
    header.extend_from_slice(&encapsulation.ciphertext);

    let payload = Payload {
        msg: plaintext,
        aad: &header,
    };

    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| RecipientEncryptionError::EncryptionFailed)?;

    let mut output = header;
    output.extend_from_slice(&encrypted);

    Ok(output)
}

/// Decrypts a QVAULT02 container using the recipient's ML-KEM keypair.
pub fn decrypt_for_recipient(
    container: &[u8],
    recipient_keypair: &MlKem768KeyPair,
) -> Result<Vec<u8>, RecipientEncryptionError> {
    if container.len() < BASE_HEADER_LEN + TAG_LEN {
        return Err(RecipientEncryptionError::InvalidFormat);
    }

    if &container[..8] != MAGIC || container[8] != VERSION {
        return Err(RecipientEncryptionError::InvalidFormat);
    }

    let salt_start = 9;
    let salt_end = salt_start + SALT_LEN;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LEN;
    let length_start = nonce_end;
    let length_end = length_start + LENGTH_FIELD_LEN;

    let salt = &container[salt_start..salt_end];
    let nonce = &container[nonce_start..nonce_end];

    let encoded_length: [u8; 4] = container[length_start..length_end]
        .try_into()
        .map_err(|_| RecipientEncryptionError::InvalidFormat)?;

    let kem_length = u32::from_be_bytes(encoded_length) as usize;

    let (_, _, expected_kem_length, _) = mlkem768_get_sizes()?;

    if kem_length != expected_kem_length {
        return Err(RecipientEncryptionError::InvalidFormat);
    }

    let header_end = BASE_HEADER_LEN
        .checked_add(kem_length)
        .ok_or(RecipientEncryptionError::InvalidFormat)?;

    if container.len() < header_end + TAG_LEN {
        return Err(RecipientEncryptionError::InvalidFormat);
    }

    let kem_ciphertext = &container[BASE_HEADER_LEN..header_end];
    let header = &container[..header_end];
    let encrypted = &container[header_end..];

    let shared_secret = mlkem768_decapsulate(kem_ciphertext, recipient_keypair)?;

    let key = derive_key(shared_secret.as_bytes(), salt)?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| RecipientEncryptionError::EncryptionFailed)?;

    let payload = Payload {
        msg: encrypted,
        aad: header,
    };

    cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| RecipientEncryptionError::AuthenticationFailed)
}

/// Creates a new file without overwriting an existing file.
fn write_new_file(path: &Path, data: &[u8]) -> Result<(), RecipientEncryptionError> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(RecipientEncryptionError::OutputAlreadyExists);
        }
        Err(_) => {
            return Err(RecipientEncryptionError::FileOperationFailed);
        }
    };

    if file.write_all(data).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(path);

        return Err(RecipientEncryptionError::FileOperationFailed);
    }

    Ok(())
}

/// Reads a file, encrypts it for an ML-KEM recipient,
/// and writes a new QVAULT02 container.
pub fn encrypt_file_for_recipient(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    recipient_public_key: &[u8],
) -> Result<(), RecipientEncryptionError> {
    let plaintext =
        fs::read(input_path).map_err(|_| RecipientEncryptionError::FileOperationFailed)?;

    let encrypted = encrypt_for_recipient(&plaintext, recipient_public_key)?;

    write_new_file(output_path.as_ref(), &encrypted)
}

/// Reads a QVAULT02 container, decrypts it using the recipient's
/// private key, and writes a new plaintext file.
pub fn decrypt_file_for_recipient(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    recipient_keypair: &MlKem768KeyPair,
) -> Result<(), RecipientEncryptionError> {
    let container =
        fs::read(input_path).map_err(|_| RecipientEncryptionError::FileOperationFailed)?;

    let plaintext = decrypt_for_recipient(&container, recipient_keypair)?;

    write_new_file(output_path.as_ref(), &plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safe::mlkem768_keypair;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_path(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

        std::env::temp_dir().join(format!(
            "quantumvault_recipient_{}_{}_{}",
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
    fn recipient_encryption_roundtrip() {
        let keypair = mlkem768_keypair().unwrap();
        let plaintext = b"QuantumVault QVAULT02 integration test";

        let encrypted = encrypt_for_recipient(plaintext, &keypair.public_key).unwrap();

        assert_eq!(&encrypted[..8], MAGIC);

        let decrypted = decrypt_for_recipient(&encrypted, &keypair).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let recipient = mlkem768_keypair().unwrap();
        let wrong_recipient = mlkem768_keypair().unwrap();

        let encrypted = encrypt_for_recipient(b"confidential data", &recipient.public_key).unwrap();

        assert_eq!(
            decrypt_for_recipient(&encrypted, &wrong_recipient),
            Err(RecipientEncryptionError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_kem_ciphertext_is_rejected() {
        let keypair = mlkem768_keypair().unwrap();

        let mut encrypted = encrypt_for_recipient(b"important data", &keypair.public_key).unwrap();

        encrypted[BASE_HEADER_LEN] ^= 0x01;

        assert_eq!(
            decrypt_for_recipient(&encrypted, &keypair),
            Err(RecipientEncryptionError::AuthenticationFailed)
        );
    }

    #[test]
    fn invalid_container_is_rejected() {
        let keypair = mlkem768_keypair().unwrap();

        assert_eq!(
            decrypt_for_recipient(b"invalid", &keypair),
            Err(RecipientEncryptionError::InvalidFormat)
        );
    }

    #[test]
    fn invalid_public_key_length_is_rejected() {
        assert_eq!(
            encrypt_for_recipient(b"data", &[1, 2, 3]),
            Err(RecipientEncryptionError::InvalidPublicKey)
        );
    }

    #[test]
    fn recipient_file_roundtrip() {
        let keypair = mlkem768_keypair().unwrap();

        let input = test_path("original.txt");
        let encrypted = test_path("encrypted.qv");
        let decrypted = test_path("decrypted.txt");

        let original = b"QuantumVault persistent recipient encryption";

        fs::write(&input, original).unwrap();

        encrypt_file_for_recipient(&input, &encrypted, &keypair.public_key).unwrap();

        decrypt_file_for_recipient(&encrypted, &decrypted, &keypair).unwrap();

        assert_eq!(fs::read(&decrypted).unwrap(), original);

        cleanup(&[&input, &encrypted, &decrypted]);
    }

    #[test]
    fn wrong_recipient_does_not_create_output() {
        let recipient = mlkem768_keypair().unwrap();
        let wrong_recipient = mlkem768_keypair().unwrap();

        let input = test_path("wrong_recipient.qv");
        let output = test_path("wrong_recipient_output.txt");

        let encrypted = encrypt_for_recipient(b"secret data", &recipient.public_key).unwrap();

        fs::write(&input, encrypted).unwrap();

        assert_eq!(
            decrypt_file_for_recipient(&input, &output, &wrong_recipient,),
            Err(RecipientEncryptionError::AuthenticationFailed)
        );

        assert!(!output.exists());

        cleanup(&[&input, &output]);
    }

    #[test]
    fn existing_output_is_not_overwritten() {
        let keypair = mlkem768_keypair().unwrap();

        let input = test_path("no_overwrite_input.txt");
        let output = test_path("no_overwrite_output.qv");

        fs::write(&input, b"original data").unwrap();
        fs::write(&output, b"existing output").unwrap();

        assert_eq!(
            encrypt_file_for_recipient(&input, &output, &keypair.public_key,),
            Err(RecipientEncryptionError::OutputAlreadyExists)
        );

        assert_eq!(fs::read(&output).unwrap(), b"existing output");

        cleanup(&[&input, &output]);
    }
}
