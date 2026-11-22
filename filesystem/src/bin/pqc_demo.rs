
use filesystem::safe::{
    mlkem768_keypair,
    mlkem768_encapsulate,
    mlkem768_decapsulate,
};

use filesystem::key_derivation::derive_encryption_key;

use filesystem::encryption::{
    encrypt_data,
    decrypt_data,
};

use rand::{rngs::OsRng, RngCore};

fn main() {
    // Step 1: Generate ML-KEM key pair
    let keypair = mlkem768_keypair()
        .expect("Key generation failed");

    println!("ML-KEM key generation successful!");

    // Step 2: Sender encapsulates shared secret
    let encapsulation = mlkem768_encapsulate(
        &keypair.public_key
    )
    .expect("Encapsulation failed");

    println!("Shared secret encapsulation successful!");

    // Step 3: Generate a fresh random HKDF salt
    let mut salt = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);

    // Step 4: Sender derives encryption key
    let sender_key = derive_encryption_key(
        encapsulation.shared_secret.as_slice(),
        &salt,
    )
    .expect("Sender key derivation failed");

    println!("Sender encryption key derived!");

    // Step 5: Receiver decapsulates shared secret
    let receiver_secret = mlkem768_decapsulate(
        &encapsulation.ciphertext,
        &keypair.secret_key,
    )
    .expect("Decapsulation failed");

    println!("Receiver recovered shared secret!");

    // Step 6: Receiver derives encryption key
    let receiver_key = derive_encryption_key(
        receiver_secret.as_slice(),
        &salt,
    )
    .expect("Receiver key derivation failed");

    println!("Receiver encryption key derived!");

    // Step 7: Verify derived keys match
    assert_eq!(
        sender_key.as_slice(),
        receiver_key.as_slice(),
        "Derived encryption keys do not match!"
    );

    println!("Both encryption keys match!");

    // Step 8: Prepare sample plaintext
    let plaintext = b"QuantumVault: Secure file encryption test";

    // Step 9: Encrypt using sender's key
    let encrypted = encrypt_data(
        sender_key.as_slice(),
        plaintext,
    )
    .expect("Encryption failed");

    println!("AES-256-GCM encryption successful!");

    // Step 10: Decrypt using receiver's key
    let decrypted = decrypt_data(
        receiver_key.as_slice(),
        &encrypted,
    )
    .expect("Decryption failed");

    println!("AES-256-GCM decryption successful!");

    // Step 11: Verify original data
    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "Decrypted data does not match original!"
    );

    println!("SUCCESS: Original plaintext recovered!");
    println!("QuantumVault cryptographic workflow completed!");
}
