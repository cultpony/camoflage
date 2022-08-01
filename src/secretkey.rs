use std::str::FromStr;

use anyhow::Context;
use anyhow::Result;
use hmac::Hmac;
use hmac::Mac;
use sha1::Digest;
use sha1::Sha1;
use sha3::Sha3_256 as Sha3;

#[derive(Clone)]
pub struct SecretKey(String, bool);

pub fn static_cmp(a: Vec<u8>, b: Vec<u8>) -> bool {
    assert!(
        a.len() == b.len(),
        "Hash Size mismatch is not allowed to occur"
    );
    a.into_iter()
        .zip(b.into_iter())
        .map(|(a, b)| (a ^ b) as u64)
        .sum::<u64>()
        == 0
}

pub fn static_cmp_str<S: Clone + Into<String>, S2: Clone + Into<String>>(a: &S, b: &S2) -> bool {
    let a: String = a.clone().into();
    let b: String = b.clone().into();
    static_cmp(a.into_bytes(), b.into_bytes())
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<..>)")
    }
}

impl FromStr for SecretKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let _: Hmac<Sha1> =
            Hmac::<Sha1>::new_from_slice(s.as_bytes()).context("invalid key supplied")?;
        let _: Hmac<Sha3> =
            Hmac::<Sha3>::new_from_slice(s.as_bytes()).context("invalid key supplied")?;
        Ok(SecretKey(s.to_string(), true))
    }
}

fn encode_expiry(expiry: u64) -> String {
    let expiry = expiry.to_le_bytes();
    base64::encode_config(expiry, base64::URL_SAFE_NO_PAD)
        .trim_end_matches('A')
        .to_string()
}

fn decode_expiry<S: Into<String>>(expiry: S) -> Result<u64> {
    let mut expiry: String = expiry.into();
    while expiry.len() < 11 {
        expiry.push('A');
    }
    let decoded = base64::decode_config(expiry, base64::URL_SAFE_NO_PAD)?;
    let decoded: [u8; 8] = decoded.try_into().unwrap();
    Ok(u64::from_le_bytes(decoded))
}

impl SecretKey {
    pub fn new<S: Into<String>>(key: S) -> Self {
        Self(key.into(), true)
    }

    /// Disable using shae3 for signing URLs with expiry (the V2 URLs)
    pub fn disable_sha3(&mut self) {
        self.1 = false
    }
    /// Returns true if the given URL matches the digest and expiry data
    /// If no expiry data is given, normal CAMO signature is used, otherwise the version is determined
    /// from the digest data.
    /// Any error results in a false output, meaning the digest is not considered valid
    pub async fn verify_camo_signature(
        &self,
        image_url: &url::Url,
        digest: &str,
        expire: Option<&str>,
    ) -> bool {
        let expire = match expire.map(decode_expiry).transpose() {
            Err(_) => return false,
            Ok(v) => v,
        };
        let signed = self.sign_url(image_url, expire).await;
        let digest = Self::hash_digest(digest);
        let signed = Self::hash_digest(signed);
        static_cmp(digest, signed)
            && expire
                .map(|x| {
                    x > std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                })
                .unwrap_or(true)
    }

    fn hash_digest<S: Into<String>>(digest: S) -> Vec<u8> {
        let digest: String = digest.into();
        let mut hash = sha3::Sha3_512::default();
        hash.update(digest.as_bytes());
        let digest = hash.finalize();
        digest.as_slice().to_vec()
    }

    pub async fn sign_url(&self, image_url: &url::Url, expire: Option<u64>) -> String {
        match expire {
            Some(expire) => {
                let mut hm = Hmac::<Sha3>::new_from_slice(self.0.as_bytes()).expect("invalid key");
                hm.update(image_url.as_str().as_bytes());
                hm.update(&expire.to_le_bytes());
                base64::encode_config(hm.finalize().into_bytes(), base64::URL_SAFE_NO_PAD)
            }
            None => {
                let mut hm = Hmac::<Sha1>::new_from_slice(self.0.as_bytes()).expect("invalid key");
                hm.update(image_url.as_str().as_bytes());
                hex::encode(hm.finalize().into_bytes())
            }
        }
    }

    /// Sign URL and construct the final URL to be used
    ///
    /// The signed URL will use the Camo Inline Format
    pub async fn sign_url_as_url(
        &self,
        image_url: &url::Url,
        expire: Option<u64>,
        host: impl Into<String>,
    ) -> Result<url::Url> {
        let sign = self.sign_url(image_url, expire).await;
        let host: String = host.into();
        let mut url = url::Url::from_str(&format!("https://{host}/"))?;
        let url_encoded = if expire.is_some() {
            base64::encode_config(image_url.as_str(), base64::URL_SAFE_NO_PAD)
        } else {
            hex::encode(image_url.as_str())
        };
        url.path_segments_mut()
            .unwrap()
            .push(sign.as_str())
            .push(&url_encoded);
        if let Some(expire) = expire {
            url.path_segments_mut()
            .unwrap()
            .push(&encode_expiry(expire));
        }
        Ok(url)
    }

    /// Sign URL and construct the final URL to be used.
    ///
    /// The signed URL will use the Camo Query Format
    pub async fn sign_url_as_qurl(
        &self,
        image_url: &url::Url,
        expire: Option<u64>,
        host: impl Into<String>,
    ) -> Result<url::Url> {
        let sign = self.sign_url(image_url, expire).await;
        let host: String = host.into();
        let mut url = url::Url::from_str(&format!("https://{host}/"))?;
        let url_encoded = if expire.is_some() {
            base64::encode_config(image_url.as_str(), base64::URL_SAFE_NO_PAD)
        } else {
            image_url.to_string()
        };
        url.path_segments_mut().unwrap().push(sign.as_str());
        url.query_pairs_mut().append_pair("url", &url_encoded);
        if let Some(expire) = expire {
            url.path_segments_mut()
            .unwrap()
            .push(&encode_expiry(expire));
        }
        Ok(url)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::secretkey::{decode_expiry, encode_expiry, SecretKey};
    use anyhow::{Context, Result};

    #[test]
    fn test_expiry_encoding() {
        for i in 0..(u16::MAX as u64) {
            let j = encode_expiry(i);
            let id = decode_expiry(j).context(format!("error on {i}")).unwrap();
            assert_eq!(i, id);
        }
        for i in (u32::MAX as u64 - u16::MAX as u64)..(u32::MAX as u64 + u16::MAX as u64) {
            let j = encode_expiry(i);
            let id = decode_expiry(j).context(format!("error on {i}")).unwrap();
            assert_eq!(i, id);
        }
        for i in (u64::MAX - u16::MAX as u64)..u64::MAX {
            let j = encode_expiry(i);
            let id = decode_expiry(j).context(format!("error on {i}")).unwrap();
            assert_eq!(i, id);
        }
    }

    #[tokio::test]
    async fn test_verify_camo_signature() -> Result<()> {
        let key = SecretKey::from_str("0x24FEEDFACEDEADBEEFCAFE")?;

        assert_eq!(
            "8255af44e5880ee446e28d6c73ef7be5136bf2c8",
            key.sign_url(&url::Url::from_str("https://test.invalid/image.png")?, None)
                .await
        );

        assert_eq!(
            "gCJY_Y4efO8oZdufalXKSFcq-gUUol90CoDfl2tkxQo",
            key.sign_url(
                &url::Url::from_str("https://test.invalid/image.png")?,
                Some(160000)
            )
            .await
        );

        let key = SecretKey::from_str("somekeythatisuniqueandstufflikethat")?;

        assert_eq!("3608e93ba99430a7fb28344e910330004ad51b84", key.sign_url(&url::Url::from_str("http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg")?, None).await);

        assert_eq!("7lj6h6sXhJnlX0DJ5sE8y0vzXNBDXCr9vm-_crBlilM", key.sign_url(&url::Url::from_str("http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg")?, Some(160000)).await);

        Ok(())
    }

    #[tokio::test]
    async fn test_sign_camo_url() -> Result<()> {
        let key = SecretKey::from_str("somekeythatisuniqueandstufflikethat")?;

        assert_eq!(
            "https://www.example.com/3608e93ba99430a7fb28344e910330004ad51b84/687474703a2f2f34302e6d656469612e74756d626c722e636f6d2f34353734646530396531323037646262383732663963303138616462353763382f74756d626c725f6e67796131685955424f31727139656b326f315f313238302e6a7067",
            key.sign_url_as_url(&url::Url::from_str("http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg")?, None, "www.example.com").await?.as_str()
        );

        assert_eq!(
            "https://www.example.com/7lj6h6sXhJnlX0DJ5sE8y0vzXNBDXCr9vm-_crBlilM/aHR0cDovLzQwLm1lZGlhLnR1bWJsci5jb20vNDU3NGRlMDllMTIwN2RiYjg3MmY5YzAxOGFkYjU3YzgvdHVtYmxyX25neWExaFlVQk8xcnE5ZWsybzFfMTI4MC5qcGc/AHEC",
            key.sign_url_as_url(&url::Url::from_str("http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg")?, Some(160000), "www.example.com").await?.as_str()
        );

        assert_eq!(
            "https://www.example.com/3608e93ba99430a7fb28344e910330004ad51b84?url=http%3A%2F%2F40.media.tumblr.com%2F4574de09e1207dbb872f9c018adb57c8%2Ftumblr_ngya1hYUBO1rq9ek2o1_1280.jpg",
            key.sign_url_as_qurl(&url::Url::from_str("http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg")?, None, "www.example.com").await?.as_str()
        );

        assert_eq!(
            "https://www.example.com/7lj6h6sXhJnlX0DJ5sE8y0vzXNBDXCr9vm-_crBlilM/AHEC?url=aHR0cDovLzQwLm1lZGlhLnR1bWJsci5jb20vNDU3NGRlMDllMTIwN2RiYjg3MmY5YzAxOGFkYjU3YzgvdHVtYmxyX25neWExaFlVQk8xcnE5ZWsybzFfMTI4MC5qcGc",
            key.sign_url_as_qurl(&url::Url::from_str("http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg")?, Some(160000), "www.example.com").await?.as_str()
        );
        Ok(())
    }
}
