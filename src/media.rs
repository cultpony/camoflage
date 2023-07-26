use std::collections::HashSet;

use crate::{Result, Error};
use axum::{body::Bytes, http::HeaderValue};

pub fn safe_mime_type(mime_type: Option<&HeaderValue>) -> bool {
    let mime_type = match mime_type {
        None => return false,
        Some(v) => v,
    };
    match mime_type.to_str() {
        Err(_) => false,
        Ok(mime_type) => SAFE_MIME_TYPES.contains(&*mime_type.to_lowercase()),
    }
}

/// Returns Ok() if, and only if, the host is not on the banned list
/// and *all* IPs it resolves to are not part of the banned set.
pub fn is_host_safe(host: &str) -> Result<()> {
    if let Ok(ip) = host.parse() {
        for net in REJECT_IP_NETS.iter() {
            if net.contains(ip) {
                return Err(Error::HostIPBannedFromProxy(ip))
            }
        }
    }
    for bnd_host in REJECT_HOSTNAMES.iter() {
        if host.ends_with(bnd_host) {
            return Err(Error::HostBannedFromProxy(host.to_string()))
        }
    }
    todo!("resolve host")
}

pub fn is_svg(mime_type: Option<&HeaderValue>) -> bool {
    let mime_type = match mime_type {
        None => return false,
        Some(v) => v,
    };
    match mime_type.to_str() {
        Err(_) => false,
        Ok(mime_type) => mime_type.to_lowercase() == "image/svg+xml",
    }
}

pub fn verify_data(data: &Bytes) -> Result<()> {
    let format = image::guess_format(data)?;
    let mut datac = Vec::new();
    datac.extend_from_slice(data);
    let mut data = std::io::Cursor::new(datac);
    let mut reader = image::io::Reader::with_format(&mut data, format).with_guessed_format()?;
    let mut limits = image::io::Limits::default();
    limits.max_image_height = Some(100_000);
    limits.max_image_width = Some(100_000);
    limits.max_alloc = Some(512_000_000);
    reader.limits(limits);
    let _ = reader.decode()?;
    Ok(())
}

lazy_static::lazy_static! {
    static ref REJECT_HOSTNAMES: HashSet<&'static str> = {
        let mut m = HashSet::new();
        const REJECT_HOSTNAMES_LIST: [&str; 3] = [
                "localhost",
                "localdomain",
                "localhost.localdomain",
        ];
        for i in REJECT_HOSTNAMES_LIST {
            m.insert(i);
        }
        m
    };

    static ref REJECT_IP_NETS: [ipnetwork::IpNetwork; 14] = {
        let mut m = Vec::with_capacity(14);
        const REJECT_IP_NETS_LIST: [&str; 14] = [
            // ipv4 loopback
            "127.0.0.0/8",
            // ipv4 link local
            "169.254.0.0/16",
            // ipv4 rfc1918
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            // unspecified address
            "::/128",
            // ipv6 loopback
            "::1/128",
            // ipv4 mapped onto ipv6
            "::ffff:0:0/96",
            // discard prefix
            "100::/64",
            // addresses reserved for documentation and example code rfc3849
            "2001:db8::/32",
            // ipv6 ULA. Encompasses rfc4193 (fd00::/8)
            "fc00::/7",
            // ipv6 link local
            "fe80::/10",
            // old ipv6 site local
            "fec0::/10",
            // global multicast
            "ff00::/8",
        ];
        for i in REJECT_IP_NETS_LIST {
            m.push(i.parse().unwrap());
        }
        m.try_into().unwrap()
    };

    static ref SAFE_MIME_TYPES: HashSet<&'static str> = {
        let mut m = HashSet::new();
        const SAFE_MIME_TYPES_LIST: [&str; 44] = [
            "image/bmp",
            "image/cgm",
            "image/g3fax",
            "image/gif",
            "image/ief",
            "image/jp2",
            "image/jpeg",
            "image/jpg",
            "image/pict",
            "image/png",
            "image/prs.btif",
            "image/svg+xml",
            "image/tiff",
            "image/vnd.adobe.photoshop",
            "image/vnd.djvu",
            "image/vnd.dwg",
            "image/vnd.dxf",
            "image/vnd.fastbidsheet",
            "image/vnd.fpx",
            "image/vnd.fst",
            "image/vnd.fujixerox.edmics-mmr",
            "image/vnd.fujixerox.edmics-rlc",
            "image/vnd.microsoft.icon",
            "image/vnd.ms-modi",
            "image/vnd.net-fpx",
            "image/vnd.wap.wbmp",
            "image/vnd.xiff",
            "image/webp",
            "image/x-cmu-raster",
            "image/x-cmx",
            "image/x-icon",
            "image/x-macpaint",
            "image/x-pcx",
            "image/x-pict",
            "image/x-portable-anymap",
            "image/x-portable-bitmap",
            "image/x-portable-graymap",
            "image/x-portable-pixmap",
            "image/x-quicktime",
            "image/x-rgb",
            "image/x-xbitmap",
            "image/x-xpixmap",
            "image/x-xwindowdump",
            "application/octet-stream"
        ];
        for i in SAFE_MIME_TYPES_LIST {
            m.insert(i);
        }
        m
    };
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use crate::Error;
    use axum::http::HeaderValue;
    use std::str::FromStr;

    #[test]
    fn sanity_check_mime_bans() {
        assert!(
            !super::safe_mime_type(Some(&HeaderValue::from_static("text/json"))),
            "text/json may not be a safe mime type"
        );
    }

    #[test]
    fn sanity_check_offline_hostbans() {
        assert_eq!(
            Err(Error::HostIPBannedFromProxy(IpAddr::from_str("127.0.0.1").unwrap())),
            super::is_host_safe("127.0.0.1"),
            "127.0.0.1 is not safe but was allowed"
        );
        assert_eq!(
            Err(Error::HostIPBannedFromProxy(IpAddr::from_str("127.0.7.1").unwrap())),
            super::is_host_safe("127.0.7.1"),
            "127.0.7.1 is not safe but was allowed"
        );
        assert_eq!(
            Err(Error::HostIPBannedFromProxy(IpAddr::from_str("fd31:f924:d60c:5914:26a9:4380:583b:4cca").unwrap())),
            super::is_host_safe("fd31:f924:d60c:5914:26a9:4380:583b:4cca"),
            "fd31:f924:d60c:5914:26a9:4380:583b:4cca is not safe but was allowed"
        );
        assert_eq!(
            Err(Error::HostBannedFromProxy("localhost".to_string())),
            super::is_host_safe("localhost"),
            "localhost is not safe but was allowed"
        );
        assert_eq!(
            Err(Error::HostBannedFromProxy("localdomain".to_string())),
            super::is_host_safe("localdomain"),
            "localdomain is not safe but was allowed"
        );
        assert_eq!(
            Err(Error::HostBannedFromProxy("localhost.localdomain".to_string())),
            super::is_host_safe("localhost.localdomain"),
            "localhost.localdomain is not safe but was allowed"
        );
    }
}
