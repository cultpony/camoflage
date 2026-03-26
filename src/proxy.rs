use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use tracing::{error, info, instrument, trace, warn};
use reqwest::redirect::Policy;
use time::Duration;

use crate::cli::Opts;
use crate::convert::{reqw_hm_to_http1, reqw_status_to_http1};
use crate::errors::*;
use crate::media;
use crate::safe_url::SafeUrl;
use crate::secretkey::SecretKey;

#[derive(Clone)]
pub(crate) struct ImageProxy {
    pub(crate) key: SecretKey,
    host: String,
    connect_timeout: Duration,
    timeout: Duration,
    max_redirect: usize,
    max_size: usize,
}

impl ImageProxy {
    pub(crate) async fn new(opts: &Opts) -> Result<Self> {
        Ok(Self {
            key: opts.secret_key.clone(),
            host: opts.external_domain.clone(),
            connect_timeout: opts.socket_timeout,
            timeout: opts.request_timeout,
            max_redirect: opts.max_redir.into(),
            max_size: opts.length_limit.try_into().unwrap(),
        })
    }

    #[cfg(test)]
    pub(crate) async fn sign(&self, image_url: &url::Url, expire: Option<u64>) -> String {
        self.key.sign_url(image_url, expire).await
    }

    pub(crate) async fn sign_url(
        &self,
        image_url: &url::Url,
        expire: Option<u64>,
    ) -> Result<String> {
        Ok(self
            .key
            .sign_url_as_url(image_url, expire, &self.host)
            .await?
            .as_str()
            .to_owned())
    }

    /// Verifies the digest matches the URL, and if so, returns a validated SafeUrl.
    #[instrument(skip(self))]
    pub(crate) async fn verify_digest(
        &self,
        digest: &str,
        image_url: String,
        expire: Option<&str>,
    ) -> Result<SafeUrl> {
        let image_url = match expire {
            None => String::from_utf8(
                hex::decode(image_url.clone())
                    .map_err(|e| -> Error { e.into() })
                    .unwrap_or_else(|_| {
                        trace!("non-encoded URL, check your library if it supports encoding the URL too");
                        image_url.as_bytes().to_vec()
                    }),
            )?,
            Some(_) => {
                use base64::Engine;
                let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                String::from_utf8(engine.decode(image_url)?)?
            }
        };
        let image_url = image_url
            .parse()
            .map_err(|e: url::ParseError| -> Error { e.into() })
            .with_context(|| format!("URL {:?} invalid", image_url))?;
        info!("Got URL {image_url:?} decoded from query, checking signature");
        if !self
            .key
            .verify_camo_signature(&image_url, digest, expire)
            .await
        {
            return Err(Error::InvalidURLDigest);
        }
        Ok(SafeUrl(image_url))
    }

    /// Fetches the image from the remote URL, applying SSRF guards and MIME/size validation.
    #[instrument(skip(self))]
    pub(crate) async fn retrieve_url(
        &self,
        image_url: &SafeUrl,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
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
            .connect_timeout(self.connect_timeout.unsigned_abs())
            .timeout(self.timeout.unsigned_abs())
            .redirect(Policy::limited(self.max_redirect))
            .build()?;
        let mut resp = match client.get(image_url.0.clone()).send().await {
            Err(e) => {
                error!("Could not fetch resource: {e}");
                return Ok((StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()));
            }
            Ok(v) => v,
        };
        let status = reqw_status_to_http1(resp.status());
        let headers = reqw_hm_to_http1(resp.headers().clone());
        use axum_extra::headers::HeaderMapExt;
        let mime_type = headers.typed_get::<axum_extra::headers::ContentType>();
        let bytes: Bytes = if media::safe_mime_type(mime_type.as_ref()) {
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
        if !media::is_svg(mime_type.as_ref()) {
            media::verify_data(&bytes)
                .with_context(|| format!("no valid media at {image_url:?}"))?;
        }
        Ok((status, headers, bytes))
    }
}

#[cfg(test)]
mod test {
    use axum::http::StatusCode;
    use time::Duration;

    use crate::cli::Opts;
    use crate::errors::Error;
    use crate::safe_url::SafeUrl;

    use super::ImageProxy;

    async fn config() -> crate::Result<ImageProxy> {
        ImageProxy::new(&Opts {
            port: 8081,
            via_header: "Camoflage Asset Proxy".to_string(),
            secret_key: crate::secretkey::SecretKey::new("test-secret-key"),
            length_limit: 5242880,
            max_redir: 4,
            socket_timeout: Duration::milliseconds(5000),
            request_timeout: Duration::milliseconds(5000),
            timing_allow_origin: None,
            hostname: "localhost".to_string(),
            keep_alive: false,
            proxy: None,
            external_domain: "camo.local".to_string(),
            external_insecure: false,
            sign_request_key: None,
        })
        .await
    }

    #[tokio::test]
    async fn test_verify_digest_valid_v1() {
        let proxy = config().await.unwrap();
        let url: url::Url = "https://example.com/image.png".parse().unwrap();
        let digest = proxy.sign(&url, None).await;
        let hex_url = hex::encode(url.as_str());
        let result = proxy.verify_digest(&digest, hex_url, None).await;
        assert!(result.is_ok(), "valid V1 digest should verify: {result:?}");
    }

    #[tokio::test]
    async fn test_verify_digest_invalid_signature() {
        let proxy = config().await.unwrap();
        let url: url::Url = "https://example.com/image.png".parse().unwrap();
        let hex_url = hex::encode(url.as_str());
        let result = proxy.verify_digest("deadbeefdeadbeef", hex_url, None).await;
        assert!(
            matches!(result, Err(Error::InvalidURLDigest)),
            "wrong digest should return InvalidURLDigest"
        );
    }

    #[tokio::test]
    async fn test_verify_digest_valid_v2() {
        let proxy = config().await.unwrap();
        let url: url::Url = "https://example.com/image.png".parse().unwrap();
        // Use a far-future expiry (year 2100)
        let expire: u64 = 4102444800;
        let digest = proxy.sign(&url, Some(expire)).await;
        let b64_url = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_str())
        };
        // sign_url_as_url builds the full path: /{digest}/{b64_url}/{expire_encoded}
        let signed_url = proxy
            .key
            .sign_url_as_url(&url, Some(expire), "camo.local")
            .await
            .unwrap();
        let expire_seg = signed_url
            .path_segments()
            .unwrap()
            .nth(2)
            .unwrap()
            .to_string();
        let result = proxy.verify_digest(&digest, b64_url, Some(&expire_seg)).await;
        assert!(result.is_ok(), "valid V2 digest should verify: {result:?}");
    }

    #[tokio::test]
    async fn test_verify_digest_expired_v2() {
        let proxy = config().await.unwrap();
        let url: url::Url = "https://example.com/image.png".parse().unwrap();
        // Expiry in the past (Unix timestamp 1)
        let expire: u64 = 1;
        let digest = proxy.sign(&url, Some(expire)).await;
        let b64_url = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_str())
        };
        // encode_expiry(1) matches what the real code uses
        let expire_encoded = {
            use base64::Engine;
            let mut buf = [0u8; 8];
            buf[..8].copy_from_slice(&expire.to_le_bytes());
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
            encoded.trim_end_matches('A').to_string()
        };
        let result = proxy
            .verify_digest(&digest, b64_url, Some(&expire_encoded))
            .await;
        assert!(
            matches!(result, Err(Error::InvalidURLDigest)),
            "expired V2 url should return InvalidURLDigest, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_retrieve_url_rejects_no_host() {
        let proxy = config().await.unwrap();
        let url = unsafe { SafeUrl::trust_url("data:image/png,abc".parse().unwrap()) };
        let (status, _, _) = proxy.retrieve_url(&url).await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_retrieve_url_rejects_credentials() {
        let proxy = config().await.unwrap();
        let url =
            unsafe { SafeUrl::trust_url("http://user:pass@example.com/img.png".parse().unwrap()) };
        let (status, _, _) = proxy.retrieve_url(&url).await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_retrieve_url_rejects_non_http_scheme() {
        let proxy = config().await.unwrap();
        let url = unsafe { SafeUrl::trust_url("ftp://example.com/img.png".parse().unwrap()) };
        let (status, _, _) = proxy.retrieve_url(&url).await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_retrieve_url_rejects_loopback_ip() {
        let proxy = config().await.unwrap();
        let url = unsafe { SafeUrl::trust_url("http://127.0.0.1/img.png".parse().unwrap()) };
        let (status, _, _) = proxy.retrieve_url(&url).await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
