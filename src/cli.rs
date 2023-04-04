use crate::{Error, Result};

use crate::secretkey::SecretKey;

fn parse_duration(s: &str) -> Result<time::Duration> {
    duration_str::parse_time(s).map_err(|e| Error::Other(e.to_string()))
}

#[derive(clap::Parser, Clone, Debug)]
pub struct Opts {
    /// Port to listen on
    #[clap(long, env = "CAMO_PORT", default_value = "8081")]
    pub port: u16,
    /// The Domain to use for generating URLs
    #[clap(long, env = "CAMO_EXT_HOST", default_value = "localhost")]
    pub external_domain: String,
    /// Allow using HTTP for requesting from CAMO
    #[clap(long, env = "CAMO_EXT_INSECURE")]
    pub external_insecure: bool,
    /// Via header to send to downstream
    #[clap(long, env = "CAMO_HEADER_VIA", default_value = "Camoflage Asset Proxy")]
    pub via_header: String,
    /// Signing Key to use for CAMO URLs
    ///
    /// You must set this even if you plan to use Sign Requests
    #[clap(long, env = "CAMO_SECRET_KEY")]
    pub secret_key: SecretKey,
    /// How large a response may get before aborting
    #[clap(long, default_value = "5242880")]
    pub length_limit: u32,
    /// Maximum amount of redirects
    #[clap(long, default_value = "4")]
    pub max_redir: u8,
    /// Time to wait for the server to establish any connection at all
    #[clap(long, value_parser = parse_duration, default_value = "10s")]
    pub socket_timeout: time::Duration,
    /// Time to wait for the server to complete a request
    #[clap(long, value_parser = parse_duration, default_value = "5s")]
    pub request_timeout: time::Duration,
    /// Timing Allow Origin Header
    #[clap(long)]
    pub timing_allow_origin: Option<String>,
    #[clap(long, default_value = "unknown")]
    pub hostname: String,
    /// Enable TCP/HTTP Keep-Alive (currently unused)
    #[clap(long)]
    pub keep_alive: bool,
    /// Upstream network proxy
    #[clap(long, env = "CAMO_HTTP_PROXY")]
    pub proxy: Option<String>,
    /// The Sign Request Key
    ///
    /// Encode your URL as base64, then send a request to /sign/:sign_request_key/:url/:expire
    ///
    /// You will receive the signed URL as text/plain response.
    ///
    /// This enables driving CAMO without the need for any specialized library or exposing
    /// the signing key itself
    /// 
    /// WARNING: This feature is not well tested yet
    #[clap(long, env = "CAMO_SIGN_REQUEST_KEY")]
    pub sign_request_key: Option<String>,
}
