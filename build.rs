fn main() {
    println!("cargo::rerun-if-env-changed=OXI_HOLE_VERSION");
    // If OXI_HOLE_VERSION is set (CI builds), inject it as a rustc cfg env.
    // This guarantees cargo tracks the value and recompiles when it changes.
    if let Ok(version) = std::env::var("OXI_HOLE_VERSION") {
        println!("cargo::rustc-env=OXI_HOLE_VERSION={}", version);
    }
}
