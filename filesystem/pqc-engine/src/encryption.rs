
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce,
};

use rand::{rngs::OsRng, RngCore};

const NONCE_LENGTH: usize = 12;

pub struct EncryptedData {
    pub nonce: [u8; NONCE_LENGTH],
    pub ciphertext: Vec<u8>,
}

// AES-256-GCM encryption
pub fn encrypt_data(
    key: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedData, &'static str> {

    // Initialize AES-256-GCM using the 32-byte key.
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid AES-256 key length")?;

    // Generate a fresh cryptographically secure nonce.
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt and authenticate the plaintext.
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed")?;

    Ok(EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    })
}

// AES-256-GCM decryption
pub fn decrypt_data(
    key: &[u8],
    encrypted_data: &EncryptedData,
) -> Result<Vec<u8>, &'static str> {

    // Initialize AES-256-GCM.
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid AES-256 key length")?;

    let nonce = Nonce::from_slice(&encrypted_data.nonce);

    // Decrypt and verify the authentication tag.
    let plaintext = cipher
        .decrypt(nonce, encrypted_data.ciphertext.as_ref())
        .map_err(|_| "Decryption or authentication failed")?;

    Ok(plaintext)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_and_decryption() {
        let key = [7u8; 32];
        let plaintext = b"QuantumVault secure file";

        let encrypted = encrypt_data(&key, plaintext).unwrap();

        let decrypted = decrypt_data(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [7u8; 16];
        let plaintext = b"Test data";

        let result = encrypt_data(&key, plaintext);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = [7u8; 32];
        let key2 = [8u8; 32];

        let plaintext = b"Secret data";

        let encrypted = encrypt_data(&key1, plaintext).unwrap();

        let result = decrypt_data(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = [7u8; 32];
        let plaintext = b"Important file data";

        let mut encrypted = encrypt_data(&key, plaintext).unwrap();

        encrypted.ciphertext[0] ^= 1;

        let result = decrypt_data(&key, &encrypted);

        assert!(result.is_err());
    }
}
