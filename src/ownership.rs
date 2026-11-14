//! Who owns a recording: `moderation/publishers/<hash>`, written once by
//! the first account to push the hash and never overwritten.

use anyhow::Context;
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;

use crate::moderation::valid_subject;
use crate::store::s3::S3Client;

pub use crate::moderation::BlobOwner;

/// `moderation/publishers/<hash>`: the recording's owner record.
pub const PUBLISHERS: &str = "publishers";

/// Read the owner record stored under `hash`, strictly: it must be the
/// record's JSON, name `hash` itself and carry a valid subject.
pub fn parse_owner(hash: &str, bytes: &[u8]) -> anyhow::Result<BlobOwner> {
    let owner: BlobOwner =
        serde_json::from_slice(bytes).with_context(|| format!("owner record {hash} unreadable"))?;
    anyhow::ensure!(owner.hash == hash, "owner record {hash} names another hash");
    anyhow::ensure!(
        valid_subject(&owner.subject),
        "owner record {hash} has an invalid subject"
    );
    Ok(owner)
}

/// Where owner records live. Object-safe, so the gate needs no type
/// parameter. `S3Client` in production.
pub trait OwnerStore: Send + Sync + 'static {
    /// The record's bytes, or `None` when the hash has no owner.
    fn get_owner<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>>;

    /// Create the record only if none exists. `false`: one already does,
    /// and it is left as it was.
    fn create_owner<'a>(
        &'a self,
        hash: &'a str,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>>;
}

impl OwnerStore for S3Client {
    fn get_owner<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>> {
        Box::pin(self.get_moderation_record(PUBLISHERS, hash))
    }

    fn create_owner<'a>(
        &'a self,
        hash: &'a str,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
        Box::pin(self.create_moderation_record(PUBLISHERS, hash, body))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Owner records keyed by hash. With `down` set every call fails; with
    /// `hang` set `get_owner` never resolves.
    #[derive(Default)]
    pub struct MemOwners {
        pub records: Mutex<HashMap<String, Bytes>>,
        pub down: AtomicBool,
        pub hang: AtomicBool,
    }

    impl OwnerStore for MemOwners {
        fn get_owner<'a>(
            &'a self,
            hash: &'a str,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>> {
            Box::pin(async move {
                if self.hang.load(Ordering::Relaxed) {
                    std::future::pending::<()>().await;
                }
                anyhow::ensure!(!self.down.load(Ordering::Relaxed), "down");
                Ok(self.records.lock().unwrap().get(hash).cloned())
            })
        }

        fn create_owner<'a>(
            &'a self,
            hash: &'a str,
            body: Bytes,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
            Box::pin(async move {
                anyhow::ensure!(!self.down.load(Ordering::Relaxed), "down");
                match self.records.lock().unwrap().entry(hash.to_string()) {
                    Entry::Occupied(_) => Ok(false),
                    Entry::Vacant(slot) => {
                        slot.insert(body);
                        Ok(true)
                    }
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemOwners;
    use super::*;

    const H: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

    #[test]
    fn parse_owner_is_strict() {
        let good = format!(r#"{{"hash":"{H}","subject":"u1","endpointId":"e","at":1}}"#);
        let owner = parse_owner(H, good.as_bytes()).unwrap();
        assert_eq!(owner.hash, H);
        assert_eq!(owner.subject, "u1");
        assert_eq!(owner.endpoint_id, "e");
        assert_eq!(owner.at, 1);

        let other = "cd".repeat(32);
        let wrong_hash = format!(r#"{{"hash":"{other}","subject":"u1","endpointId":"e","at":1}}"#);
        assert!(parse_owner(H, wrong_hash.as_bytes()).is_err());

        let bad_subject = format!(r#"{{"hash":"{H}","subject":"a/b","endpointId":"e","at":1}}"#);
        assert!(parse_owner(H, bad_subject.as_bytes()).is_err());

        assert!(parse_owner(H, b"not json").is_err());

        let no_at = format!(r#"{{"hash":"{H}","subject":"u1","endpointId":"e"}}"#);
        assert!(parse_owner(H, no_at.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn create_owner_never_overwrites() {
        let mem = MemOwners::default();
        let owners: &dyn OwnerStore = &mem;
        let first = Bytes::from_static(b"first");
        let second = Bytes::from_static(b"second");
        assert!(owners.create_owner(H, first.clone()).await.unwrap());
        assert!(!owners.create_owner(H, second).await.unwrap());
        assert_eq!(owners.get_owner(H).await.unwrap(), Some(first));
    }
}
