use rust_ffi::safe::{mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keypair};

fn main() {
    // Step 1: Generate an ML-KEM-768 keypair.
    let keypair = mlkem768_keypair().expect("ML-KEM-768 keypair generation failed");

    println!("Key generation successful!");

    // Step 2: Encapsulate using the public key.
    let encapsulation =
        mlkem768_encapsulate(&keypair.public_key).expect("ML-KEM-768 encapsulation failed");

    println!("Encapsulation successful!");

    // Step 3: Recover the shared secret using the private key.
    let recovered_secret = mlkem768_decapsulate(&encapsulation.ciphertext, &keypair)
        .expect("ML-KEM-768 decapsulation failed");

    println!("Decapsulation successful!");

    // Step 4: Compare both shared secrets.
    assert_eq!(
        encapsulation.shared_secret.as_bytes(),
        recovered_secret.as_bytes(),
        "ML-KEM shared secrets do not match"
    );

    println!("SUCCESS: Shared secrets match!");

    // SecretBytes automatically cleans sensitive data when dropped.
}
