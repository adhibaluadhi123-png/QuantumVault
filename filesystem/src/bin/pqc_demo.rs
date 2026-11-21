use filesystem::safe::{
    mlkem768_keypair,
    mlkem768_encapsulate,
    mlkem768_decapsulate,
};

use filesystem::key_derivation::derive_encryption_key;

fn main() {
    // Step 1: Generate ML-KEM key pair
    let keypair = mlkem768_keypair()
        .expect("Key generation failed");

    println!("Key generation successful!");

    // Step 2: Encapsulate shared secret
    let encapsulation = mlkem768_encapsulate(
        &keypair.public_key
    )
    .expect("Encapsulation failed");

    println!("Encapsulation successful!");

    // Step 3: Derive encryption key on sender side
    let salt = [9u8; 32];

    let sender_key = derive_encryption_key(
        encapsulation.shared_secret.as_slice(),
        &salt,
    )
    .expect("Sender key derivation failed");

    println!("Sender encryption key derived!");

    // Step 4: Decapsulate on receiver side
    let receiver_secret = mlkem768_decapsulate(
        &encapsulation.ciphertext,
        &keypair.secret_key,
    )
    .expect("Decapsulation failed");

    println!("Decapsulation successful!");

    // Step 5: Derive encryption key on receiver side
    let receiver_key = derive_encryption_key(
        receiver_secret.as_slice(),
        &salt,
    )
    .expect("Receiver key derivation failed");

    println!("Receiver encryption key derived!");

    // Step 6: Verify both keys match
    assert_eq!(
        sender_key.as_slice(),
        receiver_key.as_slice(),
        "Derived encryption keys do not match!"
    );

    assert_eq!(sender_key.len(), 32);

    println!("SUCCESS: Both derived encryption keys match!");
}
