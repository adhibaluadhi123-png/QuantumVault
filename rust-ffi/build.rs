fn main() {
    cc::Build::new()
        .file("c-engine/crypto.c")
        .include("c-engine")
        .warnings(true)
        .compile("crypto_engine");

    println!("cargo:rerun-if-changed=c-engine/crypto.c");
    println!("cargo:rerun-if-changed=c-engine/crypto.h");
}
