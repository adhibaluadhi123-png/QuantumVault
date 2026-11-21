use rust_ffi::key_management::{protect_keypair_file, unprotect_keypair_file};
use rust_ffi::safe::{mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keypair};

fn main() {
    let path = std::env::temp_dir().join(format!("quantumvault_test_{}.qvk", std::process::id()));

    let passphrase = b"temporary-test-passphrase";

    println!("Step 1: Generating ML-KEM-768 keypair...");
    let keypair = mlkem768_keypair().expect("Keypair generation failed");

    println!("Step 2: Saving passphrase-protected keypair...");
    protect_keypair_file(&keypair, passphrase, &path).expect("Keypair protection failed");

    println!("Protected keypair saved: {}", path.display());

    println!("Step 3: Dropping original keypair...");
    drop(keypair);

    println!("Step 4: Loading keypair from protected file...");
    let restored = unprotect_keypair_file(&path, passphrase).expect("Keypair restoration failed");

    println!("Keypair restored successfully!");

    println!("Step 5: Testing restored keypair...");
    let encapsulation = mlkem768_encapsulate(&restored.public_key).expect("Encapsulation failed");

    let recovered =
        mlkem768_decapsulate(&encapsulation.ciphertext, &restored).expect("Decapsulation failed");

    assert_eq!(
        encapsulation.shared_secret.as_bytes(),
        recovered.as_bytes(),
        "Restored keypair produced a different shared secret"
    );

    println!("ML-KEM shared secrets match!");

    drop(restored);

    std::fs::remove_file(&path).expect("Could not remove temporary test key file");

    println!("Temporary test key file removed.");
    println!("Persistent key storage test completed successfully!");
}
