fn main() {

    cc::Build::new()
        .file("c-engine/crypto.c")
        .include("c-engine")
        .compile("crypto");

    cc::Build::new()
        .file("pqc-engine/c-engine/crypto.c")
        .include("pqc-engine/c-engine")
        .include("/usr/local/include")
        .compile("pqc_crypto");

    // Link against liboqs
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-lib=dylib=oqs");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");

    // Rebuild when C source/header files change
    println!("cargo:rerun-if-changed=c-engine/crypto.c");
    println!("cargo:rerun-if-changed=c-engine/crypto.h");
    println!("cargo:rerun-if-changed=pqc-engine/c-engine/crypto.c");
    println!("cargo:rerun-if-changed=pqc-engine/c-engine/crypto.h");
}
