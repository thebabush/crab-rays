fn main() {
    // IDASDK must point to the SDK's src/ subdirectory, e.g. ~/idasdk93/src/
    // That is where both include/ and lib/ live in IDA SDK 9.x.
    let idasdk = std::path::PathBuf::from(
        std::env::var("IDASDK").expect("set IDASDK to the IDA SDK src/ directory (e.g. ~/idasdk93/src)"),
    );
    let include = idasdk.join("include");
    let shim_dir = std::path::PathBuf::from("src/shim");

    // autocxx bindings for all IDA SDK types and helpers used across procmod-rs
    // and loader-rs.  Pass the SDK include as -isystem so clang suppresses all
    // warnings from third-party IDA headers we can't modify.
    let isystem = format!("-isystem{}", include.display());
    let mut b = autocxx_build::Builder::new("src/lib.rs", [&shim_dir])
        .extra_clang_args(&[
            "-std=c++17",
            "-D__EA64__",
            "-DIDA_SDK_VERSION=900",
            &isystem,
        ])
        .build()
        .expect("autocxx build failed");

    b.flag_if_supported("-std=c++17")
        .define("__EA64__", None)
        .flag(isystem.clone())
        .compile("ida-sdk-sys-autocxx");

    // Compile the generic va_list procmod event bridge and the compile-time
    // constant-verification translation unit (constants_check.cpp).
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .flag(&isystem)
        .include(&shim_dir)
        .define("__EA64__", None)
        .file("src/shim/procmod_bridge.cpp")
        .file("src/shim/constants_check.cpp")
        .compile("ida-sdk-sys-bridge");

    // Link against the IDA stub library - pick the right lib subdir for this
    // target.  These directives propagate to all downstream crates.
    let lib_dir = idasdk.join(format!("lib/{}", ida_lib_subdir()));
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=ida");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/shim/insn_helpers.hpp");
    println!("cargo:rerun-if-changed=src/shim/ldr_helpers.hpp");
    println!("cargo:rerun-if-changed=src/shim/procmod_bridge.hpp");
    println!("cargo:rerun-if-changed=src/shim/procmod_bridge.cpp");
    println!("cargo:rerun-if-changed=src/shim/constants_check.cpp");
    println!("cargo:rerun-if-env-changed=IDASDK");
}

/// Returns the IDA SDK lib subdirectory name for the current target, e.g.
/// `arm64_mac_clang_64` or `x86_64_linux_clang_64`.
fn ida_lib_subdir() -> String {
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        Ok(a) => panic!("unsupported target arch for IDA SDK: {a}"),
        Err(_) => panic!("CARGO_CFG_TARGET_ARCH not set"),
    };
    let os = match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => "mac",
        Ok("linux") => "linux",
        Ok(o) => panic!("unsupported target OS for IDA SDK: {o}"),
        Err(_) => panic!("CARGO_CFG_TARGET_OS not set"),
    };
    format!("{arch}_{os}_clang_64")
}
