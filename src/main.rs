pub use errors::*;
use axum::body::Bytes;
use axum::headers::{ContentType, HeaderMapExt};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::Extension;
use axum::Router;
use axum_extra::extract::Query;
use axum_extra::routing::RouterExt;
use axum_extra::routing::TypedPath;
use chrono::Duration;
use clap::StructOpt;
use cli::Opts;
use flexi_logger::Duplicate;
use log::*;
use reqwest::redirect::Policy;
use secretkey::SecretKey;
use serde::Deserialize;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

mod cli;
pub mod diskcache;
mod media;
mod secretkey;
mod errors;

#[tokio::main]
async fn main() -> Result<()> {
    let app = cli::Opts::parse();

    flexi_logger::Logger::try_with_env_or_str("info")?
        .duplicate_to_stdout(Duplicate::All)
        .start()?;

    let proxy = ImageProxy::new(&app).await?;

    let http = Router::new()
        .typed_get(image_url)
        .typed_get(image_url_ext)
        .typed_get(image_url_primary)
        .typed_get(sign_image_url)
        .layer(Extension(proxy))
        .layer(Extension(SignRequestKey(app.sign_request_key.clone())))
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    info!("Build router, starting HTTP server");

    axum::Server::bind(&format!("0.0.0.0:{}", app.port).parse()?)
        .serve(http.into_make_service())
        .await
        .unwrap();
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SignRequestKey(Option<String>);

#[derive(TypedPath, Deserialize)]
#[typed_path("/sign/:sign_request_key/:url/:expire")]
struct SignImageUrl {
    url: url::Url,
    sign_request_key: String,
    expire: u64,
}

async fn sign_image_url(
    SignImageUrl {
        url,
        sign_request_key,
        expire,
    }: SignImageUrl,
    Extension(image_proxy): Extension<ImageProxy>,
    Extension(SignRequestKey(key)): Extension<SignRequestKey>,
) -> Result<(StatusCode, String)> {
    if key
        .map(|key| secretkey::static_cmp_str(&sign_request_key, &key))
        .unwrap_or(true)
    {
        let expire = if expire == 0 { None } else { Some(expire) };
        Ok((StatusCode::OK, image_proxy.sign_url(&url, expire).await?))
    } else {
        Ok((StatusCode::UNAUTHORIZED, "".to_string()))
    }
}

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
    image_proxy: Extension<ImageProxy>,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let url = url.url.clone();
    image_url_ext(ImageUrlExt { digest, url }, image_proxy).await
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/:digest/:url")]
struct ImageUrlExt {
    digest: String,
    url: String,
}

async fn image_url_ext(
    ImageUrlExt { digest, url }: ImageUrlExt,
    Extension(image_proxy): Extension<ImageProxy>,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    image_url_primary(
        ImageUrlFull {
            digest,
            url,
            expire: "0".to_string(),
        },
        Extension(image_proxy),
    )
    .await
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/:digest/:url/:expire")]
struct ImageUrlFull {
    digest: String,
    url: String,
    expire: String,
}

async fn image_url_primary(
    ImageUrlFull {
        digest,
        url,
        expire,
    }: ImageUrlFull,
    Extension(image_proxy): Extension<ImageProxy>,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let expire = match expire.as_str() {
        "0" => None,
        v => Some(v),
    };
    let image_url = image_proxy.verify_digest(&digest, url, expire).await?;
    let (status, original_headers, stream) = image_proxy.retrieve_url(&image_url).await?;
    let mut headers = HeaderMap::new();
    {
        use axum::headers::*;
        headers.typed_insert(
            CacheControl::new()
                .with_private()
                .with_no_cache()
                .with_no_store(),
        );
        headers.typed_insert(Expires::from(std::time::UNIX_EPOCH));
        match original_headers.typed_get::<ContentType>() {
            Some(v) => headers.typed_insert(v),
            None => (),
        };
    }
    Ok((status, headers, stream))
}

#[derive(Debug, Clone)]
pub struct SafeUrl(url::Url);

impl SafeUrl {
    /// Turst the incoming URL to be valid and good
    ///
    /// # Safety
    ///
    /// If the URL provided is a local network URL or localhost, the constructed SafeUrl
    /// type is invalid and callers are permitted to panic or cause UB.
    ///
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
    disk_cache: Option<diskcache::DiskCache>,
}

impl ImageProxy {
    pub async fn new(opts: &Opts) -> Result<Self> {
        Ok(Self {
            key: opts.secret_key.clone(),
            host: opts.external_domain.clone(),
            insecure: opts.external_insecure,
            connect_timeout: opts.socket_timeout,
            timeout: opts.request_timeout,
            max_redirect: opts.max_redir.into(),
            max_size: opts.length_limit.try_into().unwrap(),
            disk_cache: match &opts.cache_dir {
                Some(cache_dir) => Some(
                    diskcache::DiskCache::new(
                        cache_dir.clone(),
                        opts.cache_dir_size,
                        opts.cache_mem_size,
                        opts.cache_expire_after,
                    )
                    .await?,
                ),
                None => None,
            },
        })
    }

    async fn sign(&self, image_url: &url::Url, expire: Option<u64>) -> String {
        self.key.sign_url(image_url, expire).await
    }

    async fn sign_url(&self, image_url: &url::Url, expire: Option<u64>) -> Result<String> {
        Ok(self
            .key
            .sign_url_as_url(image_url, expire, &self.host)
            .await?
            .as_str()
            .to_owned())
    }

    /// Verifies the digest matches the URL, and if yes, converts it into a URL type to be used with the other functions
    async fn verify_digest(
        &self,
        digest: &str,
        image_url: String,
        expire: Option<&str>,
    ) -> Result<SafeUrl> {
        let image_url = match expire {
            None => String::from_utf8(hex::decode(image_url.clone())
                .map_err(|e| -> Error { e.into() })
                .with_context(|| format!("could not parse digest string {image_url:?}"))?)?,
            Some(_) => {
                String::from_utf8(base64::decode_config(image_url, base64::URL_SAFE_NO_PAD)?)?
            }
        };
        let image_url = image_url
            .parse()
            .map_err(|e: url::ParseError| -> Error { e.into() })
            .with_context(|| format!("URL {} invalid", image_url))?;
        if !self
            .key
            .verify_camo_signature(&image_url, digest, expire)
            .await
        {
            return Err(Error::InvalidURLDigest);
        }
        Ok(SafeUrl(image_url))
    }

    /// The image is pulled from the given URL and stored in the application cache
    /// If the image is already in cache, the cache is used instead
    async fn retrieve_url(&self, image_url: &SafeUrl) -> Result<(StatusCode, HeaderMap, Bytes)> {
        if !image_url.0.has_host() {
            return Ok((StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()));
        }
        if image_url.0.password().is_some() || !image_url.0.username().is_empty() {
            return Ok((StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()));
        }
        if !(image_url.0.scheme() == "http" || image_url.0.scheme() == "https") {
            return Ok((StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()));
        }
        let is_local_ip = {
            let host = image_url.0.host_str();
            let host: Option<std::net::IpAddr> =
                host.map(|x| x.parse()).transpose().unwrap_or(None);
            match host {
                None => false,
                Some(v) => {
                    v.is_unspecified()
                        || match v {
                            std::net::IpAddr::V4(v4) => {
                                v4.is_link_local()
                                    || v4.is_documentation()
                                    || v4.is_loopback()
                                    || v4.is_private()
                            }
                            std::net::IpAddr::V6(v6) => v6.is_loopback(),
                        }
                }
            }
        };
        if is_local_ip {
            warn!("Rejected {:?} as local URL", image_url);
            return Ok((StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()));
        }
        let client = reqwest::ClientBuilder::new()
            .connect_timeout(self.connect_timeout.to_std()?)
            .timeout(self.timeout.to_std()?)
            .redirect(Policy::limited(self.max_redirect))
            .build()?;
        let mut resp = match client.get(image_url.0.clone()).send().await {
            Err(e) => {
                error!("Could not fetch resource: {e}");
                return Ok((StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()));
            }
            Ok(v) => v,
        };
        let status = resp.status();
        let headers = resp.headers().clone();
        let mime_type = resp.headers().get(reqwest::header::CONTENT_TYPE);
        let bytes = if media::safe_mime_type(mime_type) {
            let expected_size: usize = resp
                .content_length()
                .map(|x| x.try_into().unwrap())
                .unwrap_or(self.max_size);
            if expected_size > self.max_size {
                warn!("Image exceeded size limit at {:?}", image_url);
                return Ok((StatusCode::NOT_FOUND, headers, Bytes::new()));
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
            warn!("Image is unsafe mime type at {:?}", image_url);
            return Ok((StatusCode::NOT_FOUND, headers, Bytes::new()));
        };
        Ok((status, headers, bytes))
    }

    /// Clean cache of expired entries, freeing diskspace
    async fn housekeeping(&self) -> Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use axum::{headers::HeaderMapExt, Extension};
    use chrono::Duration;

    use crate::{cli::Opts, image_url_ext, ImageProxy, ImageUrlExt, SafeUrl};

    pub async fn config() -> crate::Result<ImageProxy> {
        ImageProxy::new(&Opts {
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
            sign_request_key: None,
            cache_dir: None,
            cache_dir_size: ubyte::ByteUnit::Byte(0),
            cache_mem_size: ubyte::ByteUnit::Byte(0),
            cache_expire_after: Duration::seconds(0),
        }).await
    }

    macro_rules! test_status_and_body {
        ($name:ident ; $url:expr => $status:expr) => {
            test_status_and_body!($name ; $url => $status; |_,_,_| true);
        };

        ($name:ident ; $url:expr => $status:expr, $len:literal) => {
            test_status_and_body!($name ; $url => $status ; |_, _, data: Bytes| {
                assert_eq!(data.len(), $len, "Expected Body with {} bytes as response", $len);
                true
            });
        };

        ($name:ident ; $url:expr => $status:expr; $body:expr) => {
            #[tokio::test]
            async fn $name() -> crate::Result<()> {
                let image_url = $url;
                let image_url = unsafe { SafeUrl::trust_url(image_url.parse().expect("could not parse URL")) };
                let image_proxy = config().await?;
                let digest = image_proxy.sign(&image_url.0, None).await;

                use axum::http::StatusCode;
                use axum::headers::HeaderMap;
                use axum::body::Bytes;
                let (status, headers, data): (StatusCode, HeaderMap, Bytes) = image_url_ext(ImageUrlExt{ digest, url: hex::encode(image_url.0.to_string()) }, Extension(image_proxy)).await?;

                assert_eq!(status.as_u16(), $status, "Expected {} Status Code response for input {:?}", $status, image_url.0);

                assert!($body(status, headers.clone(), data.clone()), "Validation failed");

                if (status == StatusCode::OK) {
                    println!("headers: {:?}", headers);
                    if !crate::media::is_svg(headers.get(reqwest::header::CONTENT_TYPE)) {
                        assert!(crate::media::verify_data(&data), "Must be valid media");
                    }
                }
                Ok(())
            }
        };
    }

    // test_proxy_localhost_test_server
    // test_proxy_survives_redirect_without_location
    test_status_and_body!(test_follows_https_redirect_for_image_links; "https://user-images.githubusercontent.com/38/30243591-b332eb8a-9561-11e7-8b8c-cad1fe0c821c.jpg" => 200);
    // test_doesnt_crash_with_non_url_encoded_url
    // test_always_sets_security_headers
    test_status_and_body!(test_proxy_valid_image_url; "http://media.ebaumsworld.com/picture/Mincemeat/Pimp.jpg" => 200);
    test_status_and_body!(test_svg_image_with_delimited_content_type_url; "https://saucelabs.com/browser-matrix/bootstrap.svg" => 200);
    test_status_and_body!(test_proxy_valid_image_url_with_crazy_subdomain; "http://68.media.tumblr.com/c5834ed541c6f7dd760006b05754d4cf/tumblr_osr3veEPRj1uzkitwo1_1280.jpg" => 200);
    test_status_and_body!(test_strict_image_content_type_checking; "http://calm-shore-1799.herokuapp.com/foo.png" => 404);
    test_status_and_body!(test_proxy_valid_google_chart_url;
        "http://chart.apis.google.com/chart?chs=920x200&chxl=0:%7C2010-08-13%7C2010-09-12%7C2010-10-12%7C2010-11-11%7C1:%7C0%7C0%7C0%7C0%7C0%7C0&chm=B,EBF5FB,0,0,0&chco=008Cd6&chls=3,1,0&chg=8.3,20,1,4&chd=s:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&chxt=x,y&cht=lc"
        => 200
    );
    // reqwest seems to have issues with chunked data
    // SKIP: test_status_and_body!(test_proxy_valid_chunked_image_file; "https://www.httpwatch.com/httpgallery/chunked/chunkedimage.aspx" => 200);
    test_status_and_body!(test_proxy_https_octocat; "https://octodex.github.com/images/original.png" => 200);
    test_status_and_body!(test_proxy_https_gravatar; "https://1.gravatar.com/avatar/a86224d72ce21cd9f5bee6784d4b06c7" => 200);
    test_status_and_body!(test_follows_redirects; "https://httpbin.org/redirect-to?status_code=301&url=https%3A%2F%2Fhttpbin.org%2Fimage%2Fjpeg" => 200);
    test_status_and_body!(test_follows_redirects_with_path_only_location_headers; "https://httpbin.org/redirect-to?url=%2Fimage%2Fjpeg" => 200);
    // TODO: 404 resp with image
    // TODO: crash server test
    test_status_and_body!(test_404s_on_infinidirect; "http://modeselektor.herokuapp.com/" => 404, 0);
    // not needed: URLs without base aren't valid to request
    //test_status_and_body!(test_404s_on_urls_without_an_http_host; "/picture/Mincemeat/Pimp.jpg" => 404, 0);
    test_status_and_body!(test_404s_on_images_greater_than_5_megabytes; "http://apod.nasa.gov/apod/image/0505/larryslookout_spirit_big.jpg" => 404, 0);
    test_status_and_body!(test_404s_on_host_not_found; "http://flabergasted.cx" => 404, 0);
    test_status_and_body!(test_404s_on_non_image_content_type; "https://github.com/atmos/cinderella/raw/master/bootstrap.sh" => 404, 0);
    test_status_and_body!(test_404s_on_connect_timeout; "http://10.0.0.1/foo.cgi" => 404, 0);
    test_status_and_body!(test_404s_on_environmental_excludes; "http://iphone.internal.example.org/foo.cgi" => 404, 0);
    test_status_and_body!(test_follows_temporary_redirects; "https://httpbin.org/redirect-to?status_code=302&url=https%3A%2F%2Fhttpbin.org%2Fimage%2Fjpeg" => 200 ; |status, header, data| {
        true
    });
    test_status_and_body!(test_request_from_self; "http://camo-localhost-test.herokuapp.com" => 404, 0);
    test_status_and_body!(test_404s_send_cache_headers; "http://example.org/" => 404 ; |status: StatusCode, headers: HeaderMap, data: Bytes| {
        use axum::headers;
        use axum::http::*;
        assert_eq!(data.len(), 0, "Data must be empty");
        assert_eq!(status, StatusCode::NOT_FOUND, "Must not be anything but NOT_FOUND Status");
        assert_eq!(headers.typed_get::<headers::Expires>(), Some(headers::Expires::from(std::time::UNIX_EPOCH)), "Expire header must be passed through");
        assert_eq!(
            headers.typed_get::<headers::CacheControl>(),
            Some(headers::CacheControl::new().with_private().with_no_cache().with_no_store()),
            "Cache-Control Header must be set"
        );
        true
    });
}
