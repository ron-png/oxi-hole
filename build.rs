fn main() {
    println!("cargo::rerun-if-env-changed=OXI_DNS_VERSION");

    let version = match std::env::var("OXI_DNS_VERSION") {
        Ok(v) => v,
        Err(_) => std::env::var("CARGO_PKG_VERSION").unwrap(),
    };

    println!("cargo::rustc-env=OXIDNS_VERSION={}", version);
}
