#[path = "../../pqc-engine/src/ffi.rs"]
mod ffi;

fn main() {
    let mut pk_len = 0usize;
    let mut sk_len = 0usize;
    let mut ct_len = 0usize;
    let mut ss_len = 0usize;

    // Step 1: Get buffer sizes
    let status = unsafe {
        ffi::crypto_mlkem768_get_sizes(
            &mut pk_len,
            &mut sk_len,
            &mut ct_len,
            &mut ss_len,
        )
    };

    assert_eq!(status, 0, "Failed to get ML-KEM sizes");

    // Allocate buffers
    let mut public_key = vec![0u8; pk_len];
    let mut secret_key = vec![0u8; sk_len];
    let mut ciphertext = vec![0u8; ct_len];
    let mut shared_secret_a = vec![0u8; ss_len];
    let mut shared_secret_b = vec![0u8; ss_len];

    // Step 2: Generate key pair
    let status = unsafe {
        ffi::crypto_mlkem768_keypair(
            public_key.as_mut_ptr(),
            pk_len,
            secret_key.as_mut_ptr(),
            sk_len,
        )
    };

    assert_eq!(status, 0, "Key generation failed");
    println!("Key generation successful!");

    // Step 3: Encapsulation
    let status = unsafe {
        ffi::crypto_mlkem768_encapsulate(
            ciphertext.as_mut_ptr(),
            ct_len,
            shared_secret_a.as_mut_ptr(),
            ss_len,
            public_key.as_ptr(),
            pk_len,
        )
    };

    assert_eq!(status, 0, "Encapsulation failed");
    println!("Encapsulation successful!");

    // Step 4: Decapsulation
    let status = unsafe {
        ffi::crypto_mlkem768_decapsulate(
            shared_secret_b.as_mut_ptr(),
            ss_len,
            ciphertext.as_ptr(),
            ct_len,
            secret_key.as_ptr(),
            sk_len,
        )
    };

    assert_eq!(status, 0, "Decapsulation failed");
    println!("Decapsulation successful!");

    // Step 5: Compare shared secrets
    if shared_secret_a == shared_secret_b {
        println!("SUCCESS: Shared secrets match!");
    } else {
        panic!("ERROR: Shared secrets do not match!");
    }

    // Clear sensitive buffers using C cleansing function
    unsafe {
        ffi::crypto_secure_cleanse(
            secret_key.as_mut_ptr(),
            secret_key.len(),
        );

        ffi::crypto_secure_cleanse(
            shared_secret_a.as_mut_ptr(),
            shared_secret_a.len(),
        );

        ffi::crypto_secure_cleanse(
            shared_secret_b.as_mut_ptr(),
            shared_secret_b.len(),
        );
    }
}
