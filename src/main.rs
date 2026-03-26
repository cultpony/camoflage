use std::net::SocketAddr;

use axum::Extension;
use axum::Router;
use axum_extra::routing::RouterExt;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

mod cli;
mod convert;
mod errors;
mod handlers;
mod media;
mod proxy;
mod safe_url;
mod secretkey;
mod telemetry;

pub use errors::*;

#[tokio::main]
async fn main() -> Result<()> {
    let app = <cli::Opts as clap::Parser>::parse();

    telemetry::init_tracing();

    let proxy = proxy::ImageProxy::new(&app).await?;

    let http = Router::new()
        .typed_get(handlers::image_url)
        .typed_get(handlers::image_url_ext)
        .typed_get(handlers::image_url_primary)
        .typed_get(handlers::sign_image_url)
        .layer(Extension(proxy))
        .layer(Extension(handlers::SignRequestKey(
            app.sign_request_key.clone(),
        )))
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    tracing::info!("Build router, starting HTTP server");

    let listen_on: SocketAddr = format!("0.0.0.0:{}", app.port).parse()?;
    let listener = TcpListener::bind(listen_on).await?;

    axum::serve(listener, http).await?;

    Ok(())
}
