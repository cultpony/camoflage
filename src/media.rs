use std::collections::HashSet;

use axum::http::HeaderValue;

pub fn safe_mime_type(mime_type: Option<&HeaderValue>) -> bool {
    let mime_type = match mime_type {
        None => return false,
        Some(v) => v,
    };
    match mime_type.to_str() {
        Err(e) => false,
        Ok(mime_type) => SAFE_MIME_TYPES.contains(mime_type),
    }
}

lazy_static::lazy_static!{
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