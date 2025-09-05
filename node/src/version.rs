use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct VersionInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub git_commit: &'static str,
    pub build_time_utc: &'static str,
    pub rustc: &'static str,
}

pub async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        name: "logos_node",
        version: env!("CARGO_PKG_VERSION"),
        git_commit: env!("GIT_COMMIT"),
        build_time_utc: env!("BUILD_TIME_UTC"),
        rustc: env!("RUSTC_VER"),
    })
}
