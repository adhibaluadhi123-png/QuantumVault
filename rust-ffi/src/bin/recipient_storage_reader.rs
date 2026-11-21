use rust_ffi::key_management::unprotect_keypair_file;
use rust_ffi::recipient_encryption::decrypt_file_for_recipient;

use std::fs;
use std::path::Path;

const KEY_PATH: &str = "/tmp/quantumvault_separate_process_key.qvk";
const INPUT_PATH: &str = "/tmp/quantumvault_separate_process_input.txt";
const ENCRYPTED_PATH: &str = "/tmp/quantumvault_separate_process_encrypted.qv";
const DECRYPTED_PATH: &str = "/tmp/quantumvault_separate_process_decrypted.txt";

const PASSPHRASE: &[u8] = b"QuantumVault-Test-Passphrase-2026";

fn main() {
    println!("PROCESS B: READER STARTED");

    assert!(Path::new(KEY_PATH).exists(), "Protected keypair not found");
    assert!(
        Path::new(ENCRYPTED_PATH).exists(),
        "Encrypted file not found"
    );

    println!("Step 1: Restoring keypair from protected storage...");
    let keypair = unprotect_keypair_file(KEY_PATH, PASSPHRASE).expect("Keypair restoration failed");

    println!("Step 2: Decrypting recipient-encrypted file...");
    decrypt_file_for_recipient(ENCRYPTED_PATH, DECRYPTED_PATH, &keypair)
        .expect("Recipient decryption failed");

    println!("Step 3: Comparing original and decrypted content...");
    let original = fs::read(INPUT_PATH).expect("Original file not found");
    let decrypted = fs::read(DECRYPTED_PATH).expect("Decrypted file not found");

    assert_eq!(original, decrypted, "File contents do not match");

    println!("Original and decrypted files match!");
    println!("PROCESS B COMPLETED SUCCESSFULLY.");
    println!("SEPARATE-PROCESS PERSISTENCE TEST PASSED.");
}
