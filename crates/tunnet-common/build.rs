//! Bake the git commit hash into the build for `tunnet status` reporting.
//! Lets operators (and the CLI's own mismatch warning) see exactly which
//! commit each binary was built from — version strings alone (`v0.9.1`)
//! cannot distinguish protocol-breaking changes during pre-1.0 development.

fn main() {
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_HASH={hash}");
}
