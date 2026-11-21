use rust_ffi::key_management::protect_keypair_file;
use rust_ffi::recipient_encryption::encrypt_file_for_recipient;
use rust_ffi::safe::mlkem768_keypair;

use std::fs;
use std::path::Path;

const KEY_PATH: &str = "/tmp/quantumvault_separate_process_key.qvk";
const INPUT_PATH: &str = "/tmp/quantumvault_separate_process_input.txt";
const ENCRYPTED_PATH: &str = "/tmp/quantumvault_separate_process_encrypted.qv";
const PASSPHRASE: &[u8] = b"QuantumVault-Test-Passphrase-2026";

fn main() {
    println!("PROCESS A: WRITER STARTED");

    for path in [KEY_PATH, INPUT_PATH, ENCRYPTED_PATH] {
        if Path::new(path).exists() {
            fs::remove_file(path).expect("Could not remove previous test file");
        }
    }

    println!("Step 1: Generating ML-KEM-768 keypair...");
    let keypair = mlkem768_keypair().expect("Keypair generation failed");

    println!("Step 2: Saving protected recipient keypair...");
    protect_keypair_file(&keypair, PASSPHRASE, KEY_PATH).expect("Keypair protection failed");

    println!("Step 3: Creating plaintext file...");
    let plaintext = b"QuantumVault separate-process persistence verification.";

    fs::write(INPUT_PATH, plaintext).expect("Plaintext creation failed");

    println!("Step 4: Encrypting file for recipient...");
    encrypt_file_for_recipient(INPUT_PATH, ENCRYPTED_PATH, &keypair.public_key)
        .expect("Recipient encryption failed");

    println!("Step 5: Writer verification...");
    assert!(Path::new(KEY_PATH).exists());
    assert!(Path::new(ENCRYPTED_PATH).exists());

    println!("Protected keypair: {KEY_PATH}");
    println!("Encrypted file: {ENCRYPTED_PATH}");
    println!("PROCESS A COMPLETED SUCCESSFULLY.");
    println!("Close this process and run the reader binary separately.");
}
