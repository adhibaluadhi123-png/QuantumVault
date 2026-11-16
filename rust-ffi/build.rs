fn main() {
    println!("cargo:rustc-link-search=native=c-engine");
    println!("cargo:rustc-link-lib=static=crypto_engine");

    println!("cargo:rerun-if-changed=c-engine/crypto.c");
    println!("cargo:rerun-if-changed=c-engine/crypto.h");
    println!("cargo:rerun-if-changed=c-engine/libcrypto_engine.a");
}
