fn main() {
    println!("cargo::rerun-if-env-changed=OXI_HOLE_VERSION");

    let version = match std::env::var("OXI_HOLE_VERSION") {
        Ok(v) => v,
        Err(_) => std::env::var("CARGO_PKG_VERSION").unwrap(),
    };

    println!("cargo::rustc-env=OXIHOLE_VERSION={}", version);
}
