
use filesystem::safe::{
    mlkem768_keypair,
    mlkem768_encapsulate,
    mlkem768_decapsulate,
};

fn main() {
    // Step 1: Generate ML-KEM-768 key pair
    let keypair = mlkem768_keypair()
        .expect("Key generation failed");

    println!("Key generation successful!");

    // Step 2: Encapsulation
    let encapsulation = mlkem768_encapsulate(
        &keypair.public_key
    )
    .expect("Encapsulation failed");

    println!("Encapsulation successful!");

    // Step 3: Decapsulation
    let recovered_secret = mlkem768_decapsulate(
        &encapsulation.ciphertext,
        &keypair.secret_key,
    )
    .expect("Decapsulation failed");

    println!("Decapsulation successful!");

    // Step 4: Compare shared secrets
    assert_eq!(
        encapsulation.shared_secret.as_slice(),
        recovered_secret.as_slice(),
        "Shared secrets do not match!"
    );

    println!("SUCCESS: Shared secrets match!");
}

