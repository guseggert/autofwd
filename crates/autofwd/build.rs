//! Build script for autofwd.
//!
//! Computes hashes of embedded agent binaries and sets environment variables
//! that can be used at compile time with env!().

use std::fs;
use std::path::Path;

const TARGETS: &[(&str, &str)] = &[
    ("x86_64-unknown-linux-musl", "X86_64"),
    ("aarch64-unknown-linux-musl", "AARCH64"),
    ("armv7-unknown-linux-musleabihf", "ARMV7"),
];

fn main() {
    // Rerun if agent binaries change
    println!("cargo:rerun-if-changed=../../target/agents");

    let agents_dir = Path::new("../../target/agents");

    for (target, env_suffix) in TARGETS {
        let agent_path = agents_dir.join(format!("{}.zst", target));

        let hash = if agent_path.exists() {
            // Compute SHA256 hash of the compressed binary
            let data = fs::read(&agent_path).expect("Failed to read agent binary");
            let full_hash = blake3::hash(&data);
            // Use first 12 characters of hex hash
            full_hash.to_hex()[..12].to_string()
        } else {
            // Use placeholder for development builds without agents
            "000000000000".to_string()
        };

        println!("cargo:rustc-env=AGENT_HASH_{}={}", env_suffix, hash);
    }
}
