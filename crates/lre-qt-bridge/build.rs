use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    cxx_build::bridge("src/lib.rs")
        .flag_if_supported("-std=c++17")
        .compile("lre_qt_bridge");

    // Keep a stable header for the optional CMake/Qt consumer. The generated
    // header is still produced by cxx_build; this copy only avoids making
    // CMake depend on Cargo's hash-named OUT_DIR.
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let generated = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../desktop/ventris-qt/generated");
    fs::create_dir_all(generated.join("lre-qt-bridge/src")).unwrap();
    fs::create_dir_all(generated.join("rust")).unwrap();
    fs::copy(
        out.join("cxxbridge/include/lre-qt-bridge/src/lib.rs.h"),
        generated.join("lre-qt-bridge/src/lib.rs.h"),
    )
    .unwrap();
    fs::copy(
        out.join("cxxbridge/include/rust/cxx.h"),
        generated.join("rust/cxx.h"),
    )
    .unwrap();
}
