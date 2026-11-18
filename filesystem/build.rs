fn main() {
    cc::Build::new()
        .file("c-engine/crypto.c")
        .include("c-engine")
        .compile("crypto");

    println!("cargo:rerun-if-changed=c-engine/crypto.c");
    println!("cargo:rerun-if-changed=c-engine/crypto.h");
}
