use std::process::Command;

fn main() {
    // git hash (короткий)
    let git = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=GIT_COMMIT={}", git);

    // build time (UTC)
    let ts = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_TIME_UTC={}", ts);

    // rustc version
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "rustc unknown".into());
    println!("cargo:rustc-env=RUSTC_VER={}", rustc.trim());
}
