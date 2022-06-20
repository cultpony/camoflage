use axum::Router;
use axum::error_handling::HandleErrorLayer;
use axum::routing::get;
use axum::http::StatusCode;
use axum_extra::extract::Query;
use clap::StructOpt;
use anyhow::Result;
use flexi_logger::Duplicate;
use log::*;
use tower::ServiceBuilder;
use tower_http::ServiceBuilderExt;
use tower_http::set_header::request;
use tower_http::trace::TraceLayer;
use axum_extra::routing::TypedPath;
use axum_extra::routing::RouterExt;
use serde::Deserialize;

mod cli;
mod secretkey;

#[tokio::main]
async fn main() -> Result<()> {
    let app = cli::Opts::parse();

    flexi_logger::Logger::try_with_env_or_str("info")?
        .duplicate_to_stdout(Duplicate::All)
        .start()?;

    let http = Router::new()
        .route("/", get(root))
        .typed_get(image_url)
        .typed_get(image_url_ext)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    info!("Build router, starting HTTP server");
    
    axum::Server::bind(&format!("0.0.0.0:{}", app.port).parse()?)
        .serve(http.into_make_service())
        .await
        .unwrap();
    Ok(())
}

async fn handle_error(err: axum::BoxError) -> (StatusCode, String) {
    error!("Error in HTTP Middleware: {:?}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error".to_string())
}

async fn root() {}

#[derive(TypedPath, Deserialize)]
#[typed_path("/:digest")]
struct ImageUrl {
    digest: String,
}

#[derive(Deserialize)]
struct ImageUrlQueryPortion {
    url: String,
}

async fn image_url(ImageUrl { digest }: ImageUrl, url: Query<ImageUrlQueryPortion>) {
    todo!()
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/:digest/:url")]
struct ImageUrlExt {
    digest: String,
    url: String,
}
async fn image_url_ext(ImageUrlExt{ digest, url} : ImageUrlExt) {
    todo!()
}

/// The image is pulled from the given URL and stored in the application cache
/// If the image is already in cache, the cache is used instead
async fn retrieve_url(image_url: url::Url) -> Result<std::path::PathBuf> {
    todo!()
}

/// Clean cache of expired entries, freeing diskspace
async fn housekeeping() -> Result<()> {
    todo!()
}
