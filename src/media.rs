use std::collections::HashSet;

use crate::Result;
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
    static ref SAFE_MIME_TYPES: HashSet<&'static str> = {
        let mut m = HashSet::new();
        const SAFE_MIME_TYPES_LIST: [&str; 43] = [
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
            "image/x-xwindowdump"
        ];
        for i in SAFE_MIME_TYPES_LIST {
            m.insert(i);
        }
        m
    };
}
