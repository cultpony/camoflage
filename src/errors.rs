use std::net::IpAddr;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use bytes::Bytes;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid Hexadecimal Data: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Invalid UTF8: {0}")]
    UTF8Error(#[from] std::string::FromUtf8Error),
    #[error("I/O Error occured: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Request Error: {0}")]
    HTTPClientError(#[from] reqwest::Error),
    #[error("Could not parse JSON: {0}")]
    JSONError(#[from] serde_json::Error),
    #[error("Could not parse address: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error("Could not parse URL: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("Could not decode image: {0}")]
    ImageError(#[from] image::ImageError),
    #[error("Could not decode base64 data")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid HMAC Key Size")]
    HmacInvalidLength(#[from] hmac::digest::InvalidLength),

    #[error("URL Digest Invalid")]
    InvalidURLDigest,

    #[error("Other: {0}")]
    Other(String),
    #[error("{0}: {1}")]
    WithContext(String, Box<Error>),

    #[error("Host {0:?} was banned")]
    HostBannedFromProxy(String),
    #[error("Host {0:?} was banned due to it's IP")]
    HostIPBannedFromProxy(IpAddr),
    #[error("Host {0:?} was banned due to it's DNS resolved IP {1:?}")]
    HostDNSIPBannedFromProxy(String, IpAddr),

    #[error("Secret Key given as file but file not present or not a file: {0:?}")]
    FileKeyGivenFileError(String),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::HostBannedFromProxy(l0), Self::HostBannedFromProxy(r0)) => l0 == r0,
            (Self::HostIPBannedFromProxy(l0), Self::HostIPBannedFromProxy(r0)) => l0 == r0,
            (Self::HostDNSIPBannedFromProxy(l0, l1), Self::HostDNSIPBannedFromProxy(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            _ => false,
        }
    }
}

pub trait Context {
    fn context(self, c: &str) -> Self;
    fn with_context(self, c: impl Fn() -> String) -> Self;
}

impl<T> Context for Result<T> {
    fn context(self, c: &str) -> Result<T> {
        match self {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::WithContext(c.to_string(), Box::new(e))),
        }
    }

    fn with_context(self, c: impl Fn() -> String) -> Self {
        match self {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::WithContext(c(), Box::new(e))),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::InvalidURLDigest => {
                (StatusCode::GONE, Bytes::from("URL expired or invalid")).into_response()
            }
            v => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from(v.to_string()),
            )
                .into_response(),
        }
    }
}
