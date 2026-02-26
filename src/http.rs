use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::bootconfig::generate_grub_cfg;
use crate::config::Config;

pub async fn run(config: Arc<Config>) -> Result<()> {
    let bind_addr = format!("{}:{}", config.network.server_ip, config.http.port);

    let app = Router::new()
        .route("/grub/grub.cfg", get(grub_cfg_handler))
        .fallback(static_file_handler)
        .with_state(config.clone());

    let listener = TcpListener::bind(&bind_addr).await?;
    info!("HTTP server listening on {}", bind_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn grub_cfg_handler(State(config): State<Arc<Config>>) -> Response {
    let cfg = generate_grub_cfg(&config);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        cfg,
    )
        .into_response()
}

async fn static_file_handler(
    State(config): State<Arc<Config>>,
    request: Request,
) -> Response {
    let req_path = request.uri().path();

    // Strip leading slash
    let relative = req_path.trim_start_matches('/');
    if relative.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let file_path = config.http.root.join(relative);

    // Path traversal protection: canonicalise and check prefix
    let canonical = match file_path.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let root_canonical = match config.http.root.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if !canonical.starts_with(&root_canonical) {
        warn!("path traversal attempt blocked: {}", req_path);
        return StatusCode::FORBIDDEN.into_response();
    }

    if !canonical.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }

    match tokio::fs::read(&canonical).await {
        Ok(contents) => {
            let content_type = guess_content_type(&canonical);
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                contents,
            )
                .into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn guess_content_type(path: &PathBuf) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("cfg") => "text/plain; charset=utf-8",
        Some("efi") => "application/octet-stream",
        Some("img") => "application/octet-stream",
        Some("gz") => "application/gzip",
        _ => "application/octet-stream",
    }
}
