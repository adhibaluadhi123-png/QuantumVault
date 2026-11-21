use hkdf::Hkdf;
use sha2::Sha256;

use crate::safe::SecretBytes;

const KEY_LENGTH: usize = 32;

const KEY_CONTEXT: &[u8] =
    b"QuantumVault-File-Encryption-v1";

pub fn derive_encryption_key(
    shared_secret: &[u8],
    salt: &[u8],
) -> Result<SecretBytes, &'static str> {

    if shared_secret.is_empty() {
        return Err("Shared secret cannot be empty");
    }

    let hkdf = Hkdf::<Sha256>::new(
        Some(salt),
        shared_secret,
    );

    // Allocate a protected 32-byte buffer.
    let mut derived_key = SecretBytes::new(KEY_LENGTH);

    // Write the derived key directly into that buffer.
    hkdf.expand(
        KEY_CONTEXT,
        derived_key.as_mut_slice(),
    )
    .map_err(|_| "Key derivation failed")?;

    Ok(derived_key)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_length() {
        let shared_secret = [7u8; 32];
        let salt = [9u8; 32];

        let key = derive_encryption_key(
            &shared_secret,
            &salt,
        ).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_same_inputs_produce_same_key() {
        let shared_secret = [7u8; 32];
        let salt = [9u8; 32];

        let key1 = derive_encryption_key(
            &shared_secret,
            &salt,
        ).unwrap();

        let key2 = derive_encryption_key(
            &shared_secret,
            &salt,
        ).unwrap();

        assert_eq!(
            key1.as_slice(),
            key2.as_slice()
        );
    }

    #[test]
    fn test_empty_secret_is_rejected() {
        let result = derive_encryption_key(
            &[],
            &[9u8; 32],
        );

        assert!(result.is_err());
    }
}
