use axum::Extension;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum_extra::extract::Query;
use axum_extra::routing::TypedPath;
use serde::Deserialize;

use tracing::instrument;

use crate::errors::*;
use crate::proxy::ImageProxy;
use crate::secretkey;

#[derive(Clone, Debug)]
pub(crate) struct SignRequestKey(pub(crate) Option<String>);

#[derive(TypedPath, Deserialize)]
#[typed_path("/sign/{sign_request_key}/{url}/{expire}")]
pub(crate) struct SignImageUrl {
    pub(crate) url: url::Url,
    pub(crate) sign_request_key: String,
    pub(crate) expire: u64,
}

#[instrument(skip(image_proxy))]
pub(crate) async fn sign_image_url(
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
#[typed_path("/{digest}")]
pub(crate) struct ImageUrl {
    pub(crate) digest: String,
}

#[derive(Deserialize)]
pub(crate) struct ImageUrlQueryPortion {
    pub(crate) url: String,
}

pub(crate) async fn image_url(
    ImageUrl { digest }: ImageUrl,
    url: Query<ImageUrlQueryPortion>,
    image_proxy: Extension<ImageProxy>,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let url = url.url.clone();
    image_url_ext(ImageUrlExt { digest, url }, image_proxy).await
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/{digest}/{url}")]
pub(crate) struct ImageUrlExt {
    pub(crate) digest: String,
    pub(crate) url: String,
}

pub(crate) async fn image_url_ext(
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
#[typed_path("/{digest}/{url}/{expire}")]
pub(crate) struct ImageUrlFull {
    pub(crate) digest: String,
    pub(crate) url: String,
    pub(crate) expire: String,
}

#[instrument(skip(image_proxy))]
pub(crate) async fn image_url_primary(
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
        use axum_extra::headers::*;
        headers.typed_insert(
            CacheControl::new()
                .with_private()
                .with_no_cache()
                .with_no_store(),
        );
        headers.typed_insert(Expires::from(std::time::UNIX_EPOCH));
        if let Some(v) = original_headers.typed_get::<ContentType>() {
            headers.typed_insert(v);
        }
    }
    Ok((status, headers, stream))
}

#[cfg(test)]
mod test {
    use axum::Extension;
    use std::str::FromStr;
    use time::Duration;

    use crate::cli::Opts;
    use crate::proxy::ImageProxy;
    use crate::safe_url::SafeUrl;
    use crate::errors::Context;
    use axum_extra::headers::HeaderMapExt;
    use super::{image_url_ext, ImageUrlExt};

    pub async fn config() -> crate::Result<ImageProxy> {
        ImageProxy::new(&Opts {
            port: 8081,
            via_header: "Camoflage Asset Proxy".to_string(),
            secret_key: crate::secretkey::SecretKey::from_str("0x24FEEDFACEDEADBEEFCAFE").unwrap(),
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
        })
        .await
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
            #[cfg(feature = "net-tests")]
            #[tokio::test]
            async fn $name() -> crate::Result<()> {
                let image_url = $url;
                let image_url = unsafe { SafeUrl::trust_url(image_url.parse().expect("could not parse URL")) };
                let image_proxy = config().await?;
                let digest = image_proxy.sign(&image_url.0, None).await;

                use axum::http::StatusCode;
                use axum_extra::headers::HeaderMap;
                use axum::body::Bytes;
                let (status, headers, data): (StatusCode, HeaderMap, Bytes) = image_url_ext(ImageUrlExt { digest, url: hex::encode(image_url.0.to_string()) }, Extension(image_proxy)).await?;

                assert_eq!(status.as_u16(), $status, "Expected {} Status Code response for input {:?}", $status, image_url.0);

                assert!($body(status, headers.clone(), data.clone()), "Validation failed");

                if status == StatusCode::OK {
                    println!("headers: {:?}", headers);
                    if !crate::media::is_svg(headers.typed_get::<axum_extra::headers::ContentType>().as_ref()) {
                        crate::media::verify_data(&data)
                            .map_err(|e| -> crate::Error { e.into() })
                            .context("must be valid media")?;
                    }
                }
                Ok(())
            }
        };
    }

    // --- Signing endpoint unit tests (no network) ---

    #[tokio::test]
    async fn test_sign_endpoint_valid_key() {
        let proxy = config().await.unwrap();
        let (status, body) = super::sign_image_url(
            super::SignImageUrl {
                url: "https://example.com/image.png".parse().unwrap(),
                sign_request_key: "mykey".to_string(),
                expire: 0,
            },
            Extension(proxy),
            Extension(super::SignRequestKey(Some("mykey".to_string()))),
        )
        .await
        .unwrap();
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(!body.is_empty(), "signed URL should be non-empty");
    }

    #[tokio::test]
    async fn test_sign_endpoint_wrong_key() {
        let proxy = config().await.unwrap();
        let (status, _) = super::sign_image_url(
            super::SignImageUrl {
                url: "https://example.com/image.png".parse().unwrap(),
                sign_request_key: "wrongkey".to_string(),
                expire: 0,
            },
            Extension(proxy),
            Extension(super::SignRequestKey(Some("rightkey".to_string()))),
        )
        .await
        .unwrap();
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_sign_endpoint_no_key_configured() {
        // When no sign request key is configured, all signing requests are allowed.
        let proxy = config().await.unwrap();
        let (status, body) = super::sign_image_url(
            super::SignImageUrl {
                url: "https://example.com/image.png".parse().unwrap(),
                sign_request_key: "anything".to_string(),
                expire: 0,
            },
            Extension(proxy),
            Extension(super::SignRequestKey(None)),
        )
        .await
        .unwrap();
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_sign_endpoint_with_expiry() {
        let proxy = config().await.unwrap();
        let (status, body) = super::sign_image_url(
            super::SignImageUrl {
                url: "https://example.com/image.png".parse().unwrap(),
                sign_request_key: "key".to_string(),
                expire: 9999999999,
            },
            Extension(proxy),
            Extension(super::SignRequestKey(Some("key".to_string()))),
        )
        .await
        .unwrap();
        assert_eq!(status, axum::http::StatusCode::OK);
        // V2 signed URL has 4 path segments (host/digest/b64url/expire)
        let segment_count = body.trim_matches('/').split('/').count();
        assert!(
            segment_count >= 4,
            "V2 URL should contain expire segment, got: {body}"
        );
    }

    // test_proxy_localhost_test_server
    // test_proxy_survives_redirect_without_location
    test_status_and_body!(test_follows_https_redirect_for_image_links; "https://user-images.githubusercontent.com/38/30243591-b332eb8a-9561-11e7-8b8c-cad1fe0c821c.jpg" => 200);
    // test_doesnt_crash_with_non_url_encoded_url
    // test_always_sets_security_headers
    // test_status_and_body!(test_proxy_valid_image_url; "http://media.ebaumsworld.com/picture/Mincemeat/Pimp.jpg" => 200);
    test_status_and_body!(test_svg_image_with_delimited_content_type_url; "https://saucelabs.com/browser-matrix/bootstrap.svg" => 200);
    test_status_and_body!(test_proxy_valid_image_url_with_crazy_subdomain; "http://68.media.tumblr.com/c5834ed541c6f7dd760006b05754d4cf/tumblr_osr3veEPRj1uzkitwo1_1280.jpg" => 200);
    test_status_and_body!(test_strict_image_content_type_checking; "http://calm-shore-1799.herokuapp.com/foo.png" => 404);
    test_status_and_body!(test_proxy_https_octocat; "https://octodex.github.com/images/original.png" => 200);
    test_status_and_body!(test_proxy_https_gravatar; "https://1.gravatar.com/avatar/a86224d72ce21cd9f5bee6784d4b06c7" => 200);

    test_status_and_body!(test_404s_on_infinidirect; "http://modeselektor.herokuapp.com/" => 404, 0);
    test_status_and_body!(test_404s_on_images_greater_than_5_megabytes; "http://apod.nasa.gov/apod/image/0505/larryslookout_spirit_big.jpg" => 404, 0);
    test_status_and_body!(test_404s_on_host_not_found; "http://flabergasted.cx" => 404, 0);
    test_status_and_body!(test_404s_on_non_image_content_type; "https://github.com/atmos/cinderella/raw/master/bootstrap.sh" => 404, 0);
    test_status_and_body!(test_404s_on_connect_timeout; "http://10.0.0.1/foo.cgi" => 404, 0);
    test_status_and_body!(test_404s_on_environmental_excludes; "http://iphone.internal.example.org/foo.cgi" => 404, 0);
    test_status_and_body!(test_request_from_self; "http://camo-localhost-test.herokuapp.com" => 404, 0);
    test_status_and_body!(test_404s_send_cache_headers; "http://example.org/" => 404 ; |status: StatusCode, headers: HeaderMap, data: Bytes| {
        use axum_extra::headers;
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
