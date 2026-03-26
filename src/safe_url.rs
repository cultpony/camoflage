#[derive(Clone)]
pub(crate) struct SafeUrl(pub(crate) url::Url);

impl SafeUrl {
    /// Trust the incoming URL to be valid and good
    ///
    /// # Safety
    ///
    /// If the URL provided is a local network URL or localhost, the constructed SafeUrl
    /// type is invalid and callers are permitted to panic or cause UB.
    ///
    #[allow(dead_code)]
    pub(crate) unsafe fn trust_url(u: url::Url) -> Self {
        Self(u)
    }
}

impl std::fmt::Debug for SafeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SafeUrl").field(&self.0.to_string()).finish()
    }
}
