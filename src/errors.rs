use axum::response::IntoResponse;
use bytes::Bytes;
use reqwest::StatusCode;


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
    #[error("Logger produced error: {0}")]
    LoggingError(#[from] flexi_logger::FlexiLoggerError),
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
}

pub trait Context{
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
            Err(e) => Err(Error::WithContext(c(), Box::new(e)))
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::InvalidURLDigest => (StatusCode::GONE, Bytes::from("URL expired or invalid")).into_response(),
            v => (StatusCode::INTERNAL_SERVER_ERROR,Bytes::from(v.to_string())).into_response(),
        }
    }
}