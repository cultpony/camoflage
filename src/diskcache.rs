use crate::Result;
use axum::http::Uri;
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use ubyte::ByteUnit;

#[derive(Clone)]
pub struct DiskCache {
    min_size: u64,
    inner: Arc<forceps::Cache>,
    expire_after: Duration,
}

#[derive(Deserialize, Serialize, Eq, PartialEq, Clone)]
pub struct CacheData {
    pub headers: HashMap<String, String>,
    pub expires_at: DateTime<Utc>,
    pub data: Bytes,
}

impl DiskCache {
    pub async fn new(
        path: PathBuf,
        target_disk_size: ByteUnit,
        memory_lru_size: ByteUnit,
        expire_after: Duration,
    ) -> Result<Self> {
        let cache = forceps::CacheBuilder::new(path)
            .dir_depth(3)
            .memory_lru_max_size(memory_lru_size.as_u64() as usize)
            .track_access(true)
            .build()
            .await?;
        Ok(Self {
            inner: Arc::new(cache),
            min_size: target_disk_size.as_u64(),
            expire_after,
        })
    }

    async fn generate_from_insert<F>(&self, url: String, insert: F) -> Result<CacheData> where F: Future<Output = Result<CacheData>> {
        let mut cd = insert.await?;
        cd.expires_at = Utc::now() + self.expire_after;
        let cdj = serde_json::to_vec(&cd)?;
        self.inner.write(url, cdj).await?;
        Ok(cd)
    }

    pub async fn get_or_insert<F>(&self, url: Uri, insert: F) -> Result<CacheData>
    where
        F: Future<Output = Result<CacheData>>,
    {
        let url = url.to_string();
        match self.inner.read(url.clone()).await {
            Ok(bytes) => {
                // type hint, otherwise rustc gets angery
                let bytes: Bytes = bytes;
                let resp: CacheData = serde_json::from_slice(&bytes)?;
                if resp.expires_at < Utc::now() {
                    // Expired, refresh from future
                    self.inner.remove(url.clone()).await?;
                    self.generate_from_insert(url, insert).await
                } else {
                    Ok(resp)
                }
            }
            Err(forceps::Error::NotFound) => self.generate_from_insert(url, insert).await,
            Err(e) => Err(e.into()),
        }
    }

    pub async fn gc(&self) -> Result<()> {
        self.inner
            .evict_with(forceps::evictors::LruEvictor::new(self.min_size))
            .await?;
        Ok(())
    }
}
