fn main() {
    // Compile the C wrapper.
    cc::Build::new()
        .file("c-engine/crypto.c")
        .include("c-engine")
        .warnings(true)
        .compile("crypto_engine");

    // Rebuild when C source or header changes.
    println!("cargo:rerun-if-changed=c-engine/crypto.c");
    println!("cargo:rerun-if-changed=c-engine/crypto.h");

    // Link the installed liboqs static library.
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-lib=static=oqs");

    // liboqs dependencies.
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=pthread");
}
