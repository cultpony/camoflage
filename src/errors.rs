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
    #[error("Time out of Range: {0}")]
    TimeOutOfRange(#[from] time::OutOfRangeError),
    #[error("Request Error: {0}")]
    HTTPClientError(#[from] reqwest::Error),
    #[error("Could not parse JSON: {0}")]
    JSONError(#[from] serde_json::Error),
    #[error("Error in Cache: {0}")]
    CacheError(#[from] forceps::ForcepError),
    #[error("Logger produced error: {0}")]
    LoggingError(#[from] flexi_logger::FlexiLoggerError),
    #[error("Could not parse address: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error("Could not parse URL: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("Could not decode image: {0}")]
    ImageError(#[from] image::ImageError),
    #[error("Could not parse byte unit string: {0}")]
    ByteUnit(ubyte::Error),
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

impl From<ubyte::Error> for Error {
    fn from(v: ubyte::Error) -> Self {
        Self::ByteUnit(v)
    }
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
            Error::HexError(_) => todo!(),
            Error::UTF8Error(_) => todo!(),
            Error::IOError(_) => todo!(),
            Error::TimeOutOfRange(_) => todo!(),
            Error::HTTPClientError(_) => todo!(),
            Error::JSONError(_) => todo!(),
            Error::CacheError(_) => todo!(),
            Error::LoggingError(_) => todo!(),
            Error::AddrParseError(_) => todo!(),
            Error::UrlParseError(_) => todo!(),
            Error::ImageError(_) => todo!(),
            Error::ByteUnit(_) => todo!(),
            Error::Base64(_) => todo!(),
            Error::HmacInvalidLength(_) => todo!(),
            Error::InvalidURLDigest => (StatusCode::GONE, Bytes::from("URL expired or invalid")).into_response(),
            Error::Other(_) => todo!(),
            Error::WithContext(_, _) => todo!(),
        }
    }
}