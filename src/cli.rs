use anyhow::Result;

use crate::secretkey::SecretKey;

fn parse_duration(s: &str) -> Result<chrono::Duration> {
    Ok(duration_str::parse_chrono(s)?)
}

#[derive(clap::Parser, Clone, Debug)]
pub struct Opts {
    #[clap(long, env = "CAMO_PORT", default_value = "8081")]
    pub port: u16,
    #[clap(long, env = "CAMO_HEADER_VIA", default_value = "Camoflage Asset Proxy")]
    pub via_header: String,
    #[clap(long)]
    pub secret_key: SecretKey,
    #[clap(long, default_value = "5242880")]
    pub length_limit: u32,
    #[clap(long, default_value = "4")]
    pub max_redir: u8,
    #[clap(long, parse(try_from_str = parse_duration), default_value = "10s")]
    pub socket_timeout: chrono::Duration,
    #[clap(long, parse(try_from_str = parse_duration), default_value = "5s")]
    pub request_timeout: chrono::Duration,
    #[clap(long)]
    pub timing_allow_origin: Option<String>,
    #[clap(long, default_value = "unknown")]
    pub hostname: String,
    #[clap(long)]
    pub keep_alive: bool,
    #[clap(long, env = "CAMO_HTTP_PROXY")]
    pub proxy: Option<String>,
}