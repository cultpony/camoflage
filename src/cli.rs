use std::{path::PathBuf, str::FromStr};

use crate::{Result, Error};

use crate::secretkey::SecretKey;

fn parse_duration(s: &str) -> Result<chrono::Duration> {
    duration_str::parse_chrono(s).map_err(|e| Error::Other(e.to_string()))
}

fn parse_bytes(s: &str) -> Result<ubyte::ByteUnit> {
    Ok(ubyte::ByteUnit::from_str(s)?)
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
    #[clap(long)]
    pub secret_key: SecretKey,
    /// How large a response may get before aborting
    #[clap(long, default_value = "5242880")]
    pub length_limit: u32,
    /// Maximum amount of redirects
    #[clap(long, default_value = "4")]
    pub max_redir: u8,
    /// Time to wait for the server to establish any connection at all
    #[clap(long, parse(try_from_str = parse_duration), default_value = "10s")]
    pub socket_timeout: chrono::Duration,
    /// Time to wait for the server to complete a request
    #[clap(long, parse(try_from_str = parse_duration), default_value = "5s")]
    pub request_timeout: chrono::Duration,
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
    /// This enables driving CAMO without the need for any specialized library.
    #[clap(long, env = "CAMO_SIGN_REQUEST_KEY")]
    pub sign_request_key: Option<String>,

    /// The directory to store cache data into
    /// 
    /// If not specified no caching takes place
    #[clap(long, env = "CAMO_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Amount of disk space *should* be used
    /// 
    /// The GC process attempts to target this amount of disk usage but may use more
    /// 
    /// Default value is 5 Gigabyte
    #[clap(long, env = "CAMO_CACHE_DIR_SIZE", default_value = "5G", parse(try_from_str = parse_bytes))]
    pub cache_dir_size: ubyte::ByteUnit,

    /// Amout of memory to use on a simple LRU cache ring
    /// 
    /// Default value is 500 Megabyte
    #[clap(long, env = "CAMO_CACHE_DIR_SIZE", default_value = "500M", parse(try_from_str = parse_bytes))]
    pub cache_mem_size: ubyte::ByteUnit,

    /// If an entry reaches the given duration, it is evicted
    /// regardless of it's cache status
    /// 
    /// Default is 1 Week
    #[clap(long, env = "CAMO_CACHE_EXPIRE_AFTER", default_value = "1 week", parse(try_from_str = parse_duration))]
    pub cache_expire_after: chrono::Duration,
}