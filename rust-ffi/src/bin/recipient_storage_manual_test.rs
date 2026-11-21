use rust_ffi::key_management::{protect_keypair_file, unprotect_keypair_file};
use rust_ffi::recipient_encryption::{decrypt_file_for_recipient, encrypt_file_for_recipient};
use rust_ffi::safe::mlkem768_keypair;

use std::fs;
use std::path::PathBuf;

fn main() {
    let id = std::process::id();

    let key_path = PathBuf::from(format!("/tmp/quantumvault_recipient_key_{id}.qvk"));
    let input_path = PathBuf::from(format!("/tmp/quantumvault_recipient_input_{id}.txt"));
    let encrypted_path = PathBuf::from(format!("/tmp/quantumvault_recipient_encrypted_{id}.qv"));
    let decrypted_path = PathBuf::from(format!("/tmp/quantumvault_recipient_decrypted_{id}.txt"));

    let passphrase = b"QuantumVault-Test-Passphrase-2026";

    let original_data =
        b"QuantumVault: persistent ML-KEM key storage and recipient encryption integration test.";

    println!("Step 1: Generating ML-KEM-768 keypair...");
    let keypair = mlkem768_keypair().expect("ML-KEM keypair generation failed");

    println!("Step 2: Saving passphrase-protected keypair...");
    protect_keypair_file(&keypair, passphrase, &key_path).expect("Keypair protection failed");

    println!("Protected keypair saved: {}", key_path.display());

    println!("Step 3: Creating original plaintext file...");
    fs::write(&input_path, original_data).expect("Could not create plaintext file");

    println!("Step 4: Encrypting file for recipient...");
    encrypt_file_for_recipient(&input_path, &encrypted_path, &keypair.public_key)
        .expect("Recipient encryption failed");

    println!("QVAULT02 encrypted file created.");

    println!("Step 5: Dropping original keypair...");
    drop(keypair);

    println!("Step 6: Restoring keypair from protected file...");
    let restored_keypair =
        unprotect_keypair_file(&key_path, passphrase).expect("Keypair restoration failed");

    println!("Keypair restored successfully!");

    println!("Step 7: Decrypting with restored keypair...");
    decrypt_file_for_recipient(&encrypted_path, &decrypted_path, &restored_keypair)
        .expect("Recipient decryption failed");

    println!("File decrypted successfully!");

    println!("Step 8: Comparing original and decrypted files...");
    let original = fs::read(&input_path).expect("Could not read original file");

    let decrypted = fs::read(&decrypted_path).expect("Could not read decrypted file");

    assert_eq!(
        original, decrypted,
        "Integration test failed: file contents differ"
    );

    println!("Original and decrypted files match!");

    println!("Step 9: Cleaning up temporary test files...");
    drop(restored_keypair);

    fs::remove_file(&key_path).expect("Could not remove key file");
    fs::remove_file(&input_path).expect("Could not remove input file");
    fs::remove_file(&encrypted_path).expect("Could not remove encrypted file");
    fs::remove_file(&decrypted_path).expect("Could not remove decrypted file");

    println!("All temporary files removed.");
    println!("Persistent recipient encryption integration test PASSED!");
}
