pub(crate) fn reqw_status_to_http1(status: reqwest::StatusCode) -> axum::http::StatusCode {
    axum::http::StatusCode::from_u16(status.as_u16()).unwrap()
}

pub(crate) fn reqw_hm_to_http1(
    header_map: reqwest::header::HeaderMap,
) -> axum_extra::headers::HeaderMap {
    axum_extra::headers::HeaderMap::from_iter(header_map.into_iter().filter_map(|(name, value)| {
        match name {
            Some(name) => {
                let name =
                    axum_extra::headers::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap();
                let value =
                    axum_extra::headers::HeaderValue::from_str(value.to_str().unwrap()).unwrap();
                Some((name, value))
            }
            None => None,
        }
    }))
}
