use rust_ffi::encryption::{decrypt_file, encrypt_file};
use rust_ffi::safe::{mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keypair};

fn main() {
    let input = "test-data/original.txt";
    let encrypted = "test-data/original.qv";
    let decrypted = "test-data/recovered.txt";

    println!("Step 1: Generating ML-KEM-768 keypair...");
    let keypair = mlkem768_keypair().expect("ML-KEM keypair generation failed");

    println!("Step 2: Generating shared secret using encapsulation...");
    let encapsulation =
        mlkem768_encapsulate(&keypair.public_key).expect("ML-KEM encapsulation failed");

    println!("Step 3: Recovering shared secret using decapsulation...");
    let recovered_secret = mlkem768_decapsulate(&encapsulation.ciphertext, &keypair)
        .expect("ML-KEM decapsulation failed");

    assert_eq!(
        encapsulation.shared_secret.as_bytes(),
        recovered_secret.as_bytes(),
        "ML-KEM shared secrets do not match"
    );
    println!("ML-KEM shared secrets match!");

    println!("Step 4: Encrypting sample file...");
    encrypt_file(input, encrypted, encapsulation.shared_secret.as_bytes())
        .expect("File encryption failed");
    println!("Encrypted file: {}", encrypted);

    println!("Step 5: Decrypting file using recovered shared secret...");
    decrypt_file(encrypted, decrypted, recovered_secret.as_bytes())
        .expect("File decryption failed");
    println!("Decrypted file: {}", decrypted);

    println!("Integration test completed successfully!");
}
