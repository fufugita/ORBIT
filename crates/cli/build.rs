use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    let output = Command::new(env::var_os("RUSTC").expect("Cargo must supply RUSTC"))
        .arg("--version")
        .output()
        .expect("query build compiler");
    assert!(output.status.success(), "query build compiler failed");
    let compiler = String::from_utf8(output.stdout).expect("compiler version must be UTF-8");
    println!("cargo:rustc-env=ORBIT_BUILD_RUSTC={}", compiler.trim());
}
