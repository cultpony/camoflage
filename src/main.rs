use axum::Extension;
use axum::Router;
use axum::body::BoxBody;
use axum::body::Bytes;
use axum::body::StreamBody;
use axum::error_handling::HandleErrorLayer;
use axum::routing::get;
use axum::http::StatusCode;
use axum_extra::extract::Query;
use chrono::Duration;
use clap::StructOpt;
use anyhow::Result;
use cli::Opts;
use flexi_logger::Duplicate;
use futures::Stream;
use futures::StreamExt;
use log::*;
use reqwest::redirect::Policy;
use secretkey::SecretKey;
use tower::ServiceBuilder;
use tower_http::ServiceBuilderExt;
use tower_http::set_header::request;
use tower_http::trace::TraceLayer;
use axum_extra::routing::TypedPath;
use axum_extra::routing::RouterExt;
use serde::Deserialize;

mod cli;
mod secretkey;
mod media;

#[tokio::main]
async fn main() -> Result<()> {
    let app = cli::Opts::parse();

    flexi_logger::Logger::try_with_env_or_str("info")?
        .duplicate_to_stdout(Duplicate::All)
        .start()?;
    
    let proxy = ImageProxy::new(&app);

    let http = Router::new()
        .layer(Extension(proxy))
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

async fn image_url(
    ImageUrl { digest }: ImageUrl,
    url: Query<ImageUrlQueryPortion>,
    Extension(image_proxy): Extension<ImageProxy>
) -> StatusCode {
    todo!()
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/:digest/:url")]
struct ImageUrlExt {
    digest: String,
    url: String,
}
async fn image_url_ext(
    ImageUrlExt{ digest, url} : ImageUrlExt,
    Extension(image_proxy): Extension<ImageProxy>) -> (StatusCode, Bytes) {
    let image_url = image_proxy.verify_digest(&digest, url, None).await.unwrap();
    let (status, stream) = image_proxy.retrieve_url(&image_url).await.unwrap();
    (status, stream)
}

pub struct SafeUrl(url::Url);

impl SafeUrl {
    pub unsafe fn trust_url(u: url::Url) -> Self {
        Self(u)
    }
}

#[derive(Clone)]
pub struct ImageProxy {
    key: SecretKey,
    host: String,
    insecure: bool,
    connect_timeout: Duration,
    timeout: Duration,
    max_redirect: usize,
    max_size: usize,
}

impl ImageProxy {
    pub fn new(opts: &Opts) -> Self {
        Self{
            key: opts.secret_key.clone(),
            host: opts.external_domain.clone(),
            insecure: opts.external_insecure,
            connect_timeout: opts.socket_timeout.clone(),
            timeout: opts.request_timeout.clone(),
            max_redirect: opts.max_redir.into(),
            max_size: opts.length_limit.try_into().unwrap(),
        }
    }

    async fn sign(&self, image_url: &url::Url, expire: Option<u64>) -> String {
        self.key.sign_url(image_url, expire).await
    }

    /// Verifies the digest matches the URL, and if yes, converts it into a URL type to be used with the other functions
    async fn verify_digest(&self, digest: &str, image_url: String, expire: Option<&str>) -> Result<SafeUrl> {
        let image_url = image_url.parse()?;
        if !self.key.verify_camo_signature(&image_url, digest, expire).await {
            anyhow::bail!("invalid URL digest")
        }
        Ok(SafeUrl(image_url))
    }

    /// The image is pulled from the given URL and stored in the application cache
    /// If the image is already in cache, the cache is used instead
    async fn retrieve_url(&self, image_url: &SafeUrl) -> Result<(StatusCode, Bytes)> {
        let client = reqwest::ClientBuilder::new()
            .connect_timeout(self.connect_timeout.to_std()?)
            .timeout(self.timeout.to_std()?)
            .redirect(Policy::limited(self.max_redirect))
            .build()?;
        let mut resp = match client.get(image_url.0.clone()).send().await {
            Err(e) => {
                error!("Could not fetch resource: {e}");
                return Ok((StatusCode::NOT_FOUND, Bytes::new()));
            },
            Ok(v) => v,
        };
        let status = resp.status();
        let mime_type = resp.headers().get(reqwest::header::CONTENT_TYPE);
        let bytes = if media::safe_mime_type(mime_type) {
            let expected_size: usize = resp.content_length().map(|x| x.try_into().unwrap()).unwrap_or(self.max_size);
            if expected_size > self.max_size {
                return Ok((StatusCode::NOT_FOUND, Bytes::new()))
            }
            let mut buffer = Vec::with_capacity(expected_size);
            while let Some(chunk) = resp.chunk().await? {
                buffer.extend_from_slice(&chunk[..]);
                if buffer.len() > self.max_size {
                    buffer.truncate(self.max_size);
                    break;
                }
            }
            buffer.into()
        } else {
            Bytes::new()
        };
        Ok((status, bytes))
    }

    /// Clean cache of expired entries, freeing diskspace
    async fn housekeeping(&self) -> Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use axum::Extension;
    use chrono::Duration;

    use crate::{ImageProxy, cli::Opts, SafeUrl, image_url_ext, ImageUrlExt};
    use anyhow::Result;

    pub fn config() -> ImageProxy {
        ImageProxy::new(&Opts{
            port: 8081,
            via_header: "Camoflage Asset Proxy".to_string(),
            secret_key: crate::secretkey::SecretKey::new("0x24FEEDFACEDEADBEEFCAFE"),
            length_limit: 5242880,
            max_redir: 10,
            socket_timeout: Duration::milliseconds(10000),
            request_timeout: Duration::milliseconds(10000),
            timing_allow_origin: None,
            hostname: "localhost".to_string(),
            keep_alive: true,
            proxy: None,
            external_domain: "camo.local".to_string(),
            external_insecure: false,
        })
    }

    macro_rules! test_status_and_body {
        ($name:ident ; $url:expr => $status:expr) => {
            test_status_and_body!($name ; $url => $status, 0);
        };

        ($name:ident ; $url:expr => $status:expr, $len:expr) => {
            #[tokio::test]
            async fn $name() -> Result<()> {
                let image_url = $url;
                let image_url = unsafe { SafeUrl::trust_url(image_url.parse()?) };
                let image_proxy = config();
                let digest = image_proxy.sign(&image_url.0, None).await;
        
                let (status, data) = image_url_ext(ImageUrlExt{ digest, url: image_url.0.to_string() }, Extension(image_proxy)).await;
        
                assert_eq!(status.as_u16(), $status, "Expected 404 Status Code response for input {}", image_url.0);
                assert_eq!(data.len(), $len, "Expected Body with {} bytes as response", $len);
        
                Ok(())
            }
        };
    }

    test_status_and_body!(test_404_plain; "http://camo-localhost-test.herokuapp.com" => 404);
    test_status_and_body!(test_404_envexclude; "http://iphone.internal.example.org/foo.cgi" => 404);
    test_status_and_body!(test_404_nonimage; "https://github.com/atmos/cinderella/raw/master/bootstrap.sh" => 404);
    test_status_and_body!(test_404_toobig; "http://apod.nasa.gov/apod/image/0505/larryslookout_spirit_big.jpg" => 404);
}