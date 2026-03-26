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

#[cfg(test)]
mod test {
    use clap::Parser;

    use super::Opts;

    #[test]
    fn test_default_values() {
        let opts = Opts::try_parse_from(["camoflage", "--secret-key", "testkey"]).unwrap();
        assert_eq!(opts.port, 8081);
        assert_eq!(opts.external_domain, "localhost");
        assert!(!opts.external_insecure);
        assert_eq!(opts.via_header, "Camoflage Asset Proxy");
        assert_eq!(opts.length_limit, 5242880);
        assert_eq!(opts.max_redir, 4);
        assert_eq!(opts.hostname, "unknown");
        assert!(!opts.keep_alive);
        assert!(opts.proxy.is_none());
        assert!(opts.sign_request_key.is_none());
        assert!(opts.timing_allow_origin.is_none());
    }

    #[test]
    fn test_missing_required_key_errors() {
        let result = Opts::try_parse_from(["camoflage"]);
        assert!(result.is_err(), "should fail without --secret-key");
    }

    #[test]
    fn test_duration_parsing() {
        let opts =
            Opts::try_parse_from(["camoflage", "--secret-key", "k", "--socket-timeout", "500ms"])
                .unwrap();
        assert_eq!(opts.socket_timeout, time::Duration::milliseconds(500));

        let opts =
            Opts::try_parse_from(["camoflage", "--secret-key", "k", "--socket-timeout", "2m"])
                .unwrap();
        assert_eq!(opts.socket_timeout, time::Duration::seconds(120));
    }

    #[test]
    fn test_optional_flags() {
        let opts = Opts::try_parse_from([
            "camoflage",
            "--secret-key",
            "k",
            "--sign-request-key",
            "signkey",
            "--timing-allow-origin",
            "*",
            "--proxy",
            "http://proxy:3128",
            "--external-insecure",
            "--keep-alive",
        ])
        .unwrap();
        assert_eq!(opts.sign_request_key.as_deref(), Some("signkey"));
        assert_eq!(opts.timing_allow_origin.as_deref(), Some("*"));
        assert_eq!(opts.proxy.as_deref(), Some("http://proxy:3128"));
        assert!(opts.external_insecure);
        assert!(opts.keep_alive);
    }
}
