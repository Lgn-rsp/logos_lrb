use axum::{response::IntoResponse, Json};
use serde::Serialize;

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

#[derive(Serialize)]
struct Version {
    version: &'static str,
    git_hash: &'static str,
    git_branch: &'static str,
    built_at: &'static str,
}

pub async fn get() -> impl IntoResponse {
    Json(Version {
        version: BUILD_PKG_VERSION,
        git_hash: BUILD_GIT_HASH,
        git_branch: BUILD_GIT_BRANCH,
        built_at: BUILD_TIMESTAMP_RFC3339,
    })
}
