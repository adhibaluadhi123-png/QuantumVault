use rust_ffi::recipient_encryption::{
    RecipientEncryptionError, decrypt_file_for_recipient, encrypt_file_for_recipient,
};
use rust_ffi::safe::mlkem768_keypair;

use std::fs;
use std::path::PathBuf;

fn main() {
    let id = std::process::id();

    let evidence_dir = PathBuf::from("../reports/crypto-audit");
    fs::create_dir_all(&evidence_dir).expect("Could not create audit evidence directory");

    let input_path = evidence_dir.join(format!("audit_input_{id}.txt"));
    let encrypted_path = evidence_dir.join(format!("audit_encrypted_{id}.qv"));
    let decrypted_path = evidence_dir.join(format!("audit_recovered_{id}.txt"));
    let wrong_key_output = evidence_dir.join(format!("wrong_key_output_{id}.txt"));

    let original_data =
        b"QuantumVault Crypto Audit 2026: Confidential file protected using ML-KEM-768 and AES-256-GCM.";

    println!("=== QUANTUMVAULT CRYPTO AUDIT ===");

    println!("\nStep 1: Generating recipient ML-KEM-768 keypair...");
    let recipient_keypair = mlkem768_keypair().expect("ML-KEM-768 key generation failed");
    println!("PASS: Recipient keypair generated.");

    println!("\nStep 2: Creating confidential input file...");
    fs::write(&input_path, original_data).expect("Could not create input file");
    println!("PASS: {}", input_path.display());

    println!("\nStep 3: Encrypting file for recipient...");
    encrypt_file_for_recipient(&input_path, &encrypted_path, &recipient_keypair.public_key)
        .expect("File encryption failed");
    println!("PASS: Encrypted QVAULT02 container created.");

    let encrypted_data = fs::read(&encrypted_path).expect("Could not read encrypted file");

    assert!(
        encrypted_data.starts_with(b"QVAULT02"),
        "Encrypted file has an unexpected format"
    );
    println!("PASS: QVAULT02 format header verified.");

    assert!(
        !encrypted_data
            .windows(original_data.len())
            .any(|window| window == original_data),
        "Plaintext was found inside encrypted output"
    );
    println!("PASS: Original plaintext not found in encrypted file.");

    println!("\nStep 4: Testing decryption with an incorrect recipient key...");
    let wrong_keypair = mlkem768_keypair().expect("Wrong-recipient key generation failed");

    let wrong_key_result =
        decrypt_file_for_recipient(&encrypted_path, &wrong_key_output, &wrong_keypair);

    assert_eq!(
        wrong_key_result,
        Err(RecipientEncryptionError::AuthenticationFailed),
        "Incorrect recipient key was not rejected as expected"
    );

    assert!(
        !wrong_key_output.exists(),
        "Wrong-key decryption unexpectedly created an output file"
    );

    println!("PASS: Wrong recipient rejected (AuthenticationFailed).");
    println!("PASS: No plaintext output created with wrong key.");

    println!("\nStep 5: Decrypting with the correct recipient key...");
    decrypt_file_for_recipient(&encrypted_path, &decrypted_path, &recipient_keypair)
        .expect("Correct-recipient decryption failed");
    println!("PASS: Correct recipient successfully decrypted the file.");

    println!("\nStep 6: Comparing original and recovered files...");
    let original = fs::read(&input_path).expect("Could not read original");
    let recovered = fs::read(&decrypted_path).expect("Could not read recovered file");

    assert_eq!(
        original, recovered,
        "Recovered data does not match original"
    );
    println!("PASS: Original and recovered files match exactly.");

    println!("\n=== CRYPTO AUDIT RESULTS ===");
    println!("ML-KEM-768 recipient keypair: PASS");
    println!("AES-256-GCM file encryption: PASS");
    println!("QVAULT02 container validation: PASS");
    println!("Plaintext absence check: PASS");
    println!("Wrong-recipient rejection: PASS");
    println!("Correct-recipient decryption: PASS");
    println!("Original/recovered comparison: PASS");

    println!("\nEvidence files:");
    println!("Input:     {}", input_path.display());
    println!("Encrypted: {}", encrypted_path.display());
    println!("Recovered: {}", decrypted_path.display());

    println!("\nCRYPTO AUDIT PASSED.");
    println!("Private key was kept in memory and was not written to the evidence directory.");
}
