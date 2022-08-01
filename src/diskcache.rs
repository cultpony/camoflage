use std::collections::HashMap;

use anyhow::Result;
use async_std::io::{BufReader, BufWriter, ReadExt};
use cap_async_std::fs;
use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Weak};
use tokio::sync::RwLock;

/// DiskCache implements a simple on-disk cache for response data
pub struct DiskCache<K>
where
    K: Hash + Eq + Serialize + DeserializeOwned + Send + Clone,
{
    root: fs::Dir,
    ref_list: Arc<RwLock<HashMap<K, Weak<RwLock<CacheEntry>>>>>,
    entries: Arc<RwLock<Vec<Arc<RwLock<CacheEntry>>>>>,
    ttl: Duration,
    /// Maximum number of bytes the cache may use on disk
    max_size: usize,
    /// Maximum amount of entries to hold in RAM
    max_entries: usize,
}

impl<K: Hash + Eq + Serialize + DeserializeOwned + Send + Clone> DiskCache<K> {
    pub fn new(path: fs::Dir, max_entries: usize, max_disk_size: usize, ttl: Duration) -> Self {
        Self {
            root: path,
            ref_list: Arc::new(RwLock::new(HashMap::new())),
            entries: Arc::new(RwLock::new(Vec::new())),
            ttl,
            max_size: max_disk_size,
            max_entries,
        }
    }

    pub async fn gc(&self) -> Result<()> {
        // Trim out excess entries by removing the oldest ent
        let max_entries = self.max_entries;
        let entries = self.entries.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut entries = entries.blocking_write();
            if entries.len() > 0 {
                while entries.len() > max_entries {
                    let index = entries.iter()
                        .enumerate()
                        .max_by(|(_, a): &(usize, &Arc<RwLock<CacheEntry>>), (_, b): &(usize, &Arc<RwLock<CacheEntry>>)| {
                            let a = a.blocking_read();
                            let b = b.blocking_read();
                            let cmp = a.expires_at().cmp(&b.expires_at());
                            drop(b);
                            drop(a);
                            cmp
                        })
                        .map(|(idx, _)| idx)
                        .unwrap_or(0);
                    drop(entries.remove(index));
                }
                Ok(())
            } else {
                Ok(())
            }
        }).await??;

        // Remove all entries from the reflist that we don't have a strong reference for anymore
        let mut ref_list = self.ref_list.write().await;
        let mut delete_keys = Vec::new();
        for entry in ref_list.keys().clone() {
            if let Some(wref) = ref_list.get(entry) {
                if wref.strong_count() == 0 {
                    delete_keys.push(entry.clone());
                }
            }
        }
        for entry in delete_keys {
            ref_list.remove(&entry);
        }

        Ok(())
    }

    pub async fn get_or_insert<F>(&self, key: K, insert_fn: F) -> Result<cap_async_std::fs::File>
    where
        F: Future<Output = Result<cap_async_std::fs::File>>,
    {
        if let Some(wref) = self.ref_list.read().await.get(&key) {
            match wref.upgrade() {
                Some(sref) => match sref.write().await.read(&self.root).await? {
                    Some(f) => return Ok(f),
                    None => (),
                },
                None => (),
            }
        }
        match CacheEntry::read_key(&key, &self.root).await? {
            Some(entry) => {
                let entry = Arc::new(RwLock::new(entry));
                self.entries.write().await.push(entry.clone());
                let r = entry
                    .write()
                    .await
                    .read(&self.root)
                    .await?
                    .expect("we just wrote this, it should exist");
                drop(entry);
                Ok(r)
            }
            None => {
                let file = insert_fn.await?;
                let file = BufReader::new(file);
                let entry = CacheEntry::create(&self.root, key, file, self.ttl).await?;
                let entry = Arc::new(RwLock::new(entry));
                self.entries.write().await.push(entry.clone());
                let r = entry
                    .write()
                    .await
                    .read(&self.root)
                    .await?
                    .expect("we just wrote this, it should exist");
                drop(entry);
                Ok(r)
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct CacheEntry
{
    /// The Key Hash
    key: [u8; 32],
    /// When the Cache Entry was created
    created_on: DateTime<Utc>,
    /// The time when the file in question was last opened for reading
    last_access_on: DateTime<Utc>,
    /// How many times the file has been opened to reset the expiry
    refreshes: u8,
    /// How long after last_access_on the file expires
    ttl: std::time::Duration,
}

impl CacheEntry {
    pub fn ttl(&self) -> Duration {
        Duration::from_std(self.ttl).expect("what are you even doing with TTL's this large?")
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.last_access_on + self.ttl()
    }

    /// Called when the Entry experiences a CACHE HIT
    fn stamp(&mut self) {
        self.last_access_on = Utc::now();
        self.refreshes += 1;
    }

    fn persist_self(&self) -> Result<()> {
        todo!()
    }

    pub async fn delete(self, root: &fs::Dir) -> Result<()> {
        root.remove_file(self.this_filename()).await?;
        Ok(())
    }

    pub async fn read(&mut self, root: &fs::Dir) -> Result<Option<fs::File>> {
        self.stamp();
        self.persist_self()?;
        if root.exists(self.this_filename()).await {
            Ok(Some(root.open(self.this_filename()).await?))
        } else {
            Ok(None)
        }
    }

    pub async fn read_key<K: Hash + Eq + Serialize + DeserializeOwned>(key: &K, root: &fs::Dir) -> Result<Option<Self>> {
        if root.exists(Self::indexname(key)).await {
            let data = root.open(Self::indexname(key)).await?;
            let mut data = BufReader::new(data);
            let mut buf = String::new();
            data.read_to_string(&mut buf).await?;
            let data = serde_json::from_str(&*buf)?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    fn hash_key<K: Hash + Eq + Serialize + DeserializeOwned>(key: &K) -> [u8; 32] {
        let mut hasher = Sha3Hasher::default();
        key.hash(&mut hasher);
        hasher.full_hash()
    }

    fn filename<K: Hash + Eq + Serialize + DeserializeOwned>(key: &K) -> String {
        let full_hash = Self::hash_key(key);
        let filename = hex::encode(full_hash);
        let filename = format!("{filename}.dat");
        filename
    }

    fn this_filename(&self) -> String {
        format!("{}.dat", hex::encode(&self.key))
    }

    fn indexname<K: Hash + Eq + Serialize + DeserializeOwned>(key: &K) -> String {
        let full_hash = Self::hash_key(key);
        let filename = hex::encode(full_hash);
        let filename = format!("{filename}.idx");
        filename
    }

    fn this_indexname(&self) -> String {
        format!("{}.idx", hex::encode(&self.key))
    }

    pub async fn create<R: async_std::io::BufRead, K: Hash + Eq + Serialize + DeserializeOwned>(
        root: &fs::Dir,
        key: K,
        data: R,
        ttl: Duration,
    ) -> Result<Self> {
        let mut data = Box::pin(BufReader::new(data));
        let filename = Self::filename(&key);
        let mut file = root.create(filename).await?;
        let mut file = BufWriter::new(&mut file);
        async_std::io::copy(&mut data, &mut file).await?;
        let r = Self {
            key: Self::hash_key(&key),
            created_on: Utc::now(),
            last_access_on: Utc::now(),
            refreshes: 0,
            ttl: ttl.to_std().unwrap(),
        };
        r.persist_self()?;
        Ok(r)
    }
}

#[derive(Default)]
pub struct Sha3Hasher(sha3::Sha3_256);

impl Sha3Hasher {
    pub fn full_hash(&self) -> [u8; 32] {
        let r = self.0.clone().finalize();
        r.try_into().unwrap()
    }
}

impl std::hash::Hasher for Sha3Hasher {
    fn finish(&self) -> u64 {
        let r = self.full_hash();
        u64::from_le_bytes(r[0..8].try_into().unwrap())
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}
