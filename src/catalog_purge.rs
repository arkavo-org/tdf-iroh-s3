//! Deleting stored `arkavo.creator-catalog/1` documents after the cutover
//! to `/2` (tdf-iroh-s3#39).
//!
//! A `/1` document carries its entries' titles and attributes in the clear,
//! and stays readable by its hash until it is deleted. This removes each
//! one's `catalog-documents/<hash>` and `catalog-outboards/<hash>`, except a
//! document a catalog tag or a v2 pointer still names: deleting it would
//! leave that creator's catalog dangling, so it is reported and kept until
//! the creator publishes `/2`. Run as `tdf-iroh-s3 purge-catalogs-1`, a dry
//! run unless `--delete` is given.

use anyhow::Result;
use bytes::Bytes;
use std::collections::HashSet;
use std::future::Future;

use crate::creator_catalog::{self, Schema};

/// What the purge reads and deletes.
pub trait PurgeStore {
    /// Every stored catalog document's hash.
    fn catalog_document_hashes(&self) -> impl Future<Output = Result<Vec<String>>>;
    fn catalog_document(&self, hash: &str) -> impl Future<Output = Result<Option<Bytes>>>;
    /// The hashes the tags under `tag_prefix` name.
    fn tag_targets(&self, tag_prefix: &str) -> impl Future<Output = Result<Vec<String>>>;
    /// The catalog hashes the stored v2 pointers name.
    fn pointer_targets(&self) -> impl Future<Output = Result<Vec<String>>>;
    /// Delete a catalog document and its outboard.
    fn delete_catalog_document(&self, hash: &str) -> impl Future<Output = Result<()>>;
}

/// What a purge found, each list in hash order.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// `/1` documents deleted, or that `--delete` would delete.
    pub purged: Vec<String>,
    /// `/1` documents a tag or pointer still names: kept.
    pub in_use: Vec<String>,
    /// Documents without a readable schema: kept, for a person to look at.
    pub unreadable: Vec<String>,
    /// `/2` documents, untouched.
    pub kept: usize,
}

/// Find, and with `delete` remove, the stored `/1` documents nothing names.
pub async fn purge_schema_1<S: PurgeStore>(
    store: &S,
    tag_prefix: &str,
    delete: bool,
) -> Result<PurgeReport> {
    let mut named: HashSet<String> = store.tag_targets(tag_prefix).await?.into_iter().collect();
    named.extend(store.pointer_targets().await?);

    let mut hashes = store.catalog_document_hashes().await?;
    hashes.sort();
    let mut report = PurgeReport::default();
    for hash in hashes {
        let Some(body) = store.catalog_document(&hash).await? else {
            continue;
        };
        match creator_catalog::declared_schema(&body) {
            Some(Schema::V2) => report.kept += 1,
            Some(Schema::V1) if named.contains(&hash) => report.in_use.push(hash),
            Some(Schema::V1) => {
                if delete {
                    store.delete_catalog_document(&hash).await?;
                }
                report.purged.push(hash);
            }
            None => report.unreadable.push(hash),
        }
    }
    Ok(report)
}

impl PurgeStore for crate::store::s3::S3Client {
    async fn catalog_document_hashes(&self) -> Result<Vec<String>> {
        self.list_names("catalog-documents/").await
    }

    async fn catalog_document(&self, hash: &str) -> Result<Option<Bytes>> {
        Ok(self.get_catalog_document(hash).await?.map(|(body, _)| body))
    }

    async fn tag_targets(&self, tag_prefix: &str) -> Result<Vec<String>> {
        let mut targets = Vec::new();
        for name in self.list_names(&format!("tags/{tag_prefix}")).await? {
            if let Some(hash) = self.get_tag(&format!("{tag_prefix}{name}")).await? {
                targets.push(hash);
            }
        }
        Ok(targets)
    }

    async fn pointer_targets(&self) -> Result<Vec<String>> {
        let mut targets = Vec::new();
        for sub in self.list_names("catalog-pointers/").await? {
            if let Some((body, _)) = self.get_catalog_pointer(&sub).await? {
                targets.push(crate::catalogs_v2_api::stored_seq(&body)?.1);
            }
        }
        Ok(targets)
    }

    async fn delete_catalog_document(&self, hash: &str) -> Result<()> {
        self.delete_catalog_document(hash).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator_catalog::test_support::{catalog, catalog2, entry, entry2};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Mem {
        documents: Mutex<BTreeMap<String, Bytes>>,
        tags: Vec<String>,
        pointers: Vec<String>,
        deleted: Mutex<Vec<String>>,
    }

    impl PurgeStore for Mem {
        async fn catalog_document_hashes(&self) -> Result<Vec<String>> {
            // Unsorted, as a listing may come.
            Ok(self
                .documents
                .lock()
                .unwrap()
                .keys()
                .rev()
                .cloned()
                .collect())
        }
        async fn catalog_document(&self, hash: &str) -> Result<Option<Bytes>> {
            Ok(self.documents.lock().unwrap().get(hash).cloned())
        }
        async fn tag_targets(&self, tag_prefix: &str) -> Result<Vec<String>> {
            assert_eq!(tag_prefix, "catalog/");
            Ok(self.tags.clone())
        }
        async fn pointer_targets(&self) -> Result<Vec<String>> {
            Ok(self.pointers.clone())
        }
        async fn delete_catalog_document(&self, hash: &str) -> Result<()> {
            self.documents.lock().unwrap().remove(hash);
            self.deleted.lock().unwrap().push(hash.to_string());
            Ok(())
        }
    }

    fn h(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn store() -> Mem {
        let v1 = |n: u8| Bytes::from(catalog("a", vec![entry("rec-1", &h(n))]));
        let documents = BTreeMap::from([
            (h(1), v1(1)),
            (h(2), v1(2)),
            (h(3), v1(3)),
            (
                h(4),
                Bytes::from(catalog2("a", vec![entry2("rec-1", &h(9), &h(8))])),
            ),
            (h(5), Bytes::from_static(b"not json")),
        ]);
        Mem {
            documents: Mutex::new(documents),
            tags: vec![h(2)],
            pointers: vec![h(3), h(4)],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_dry_run_reports_and_deletes_nothing() {
        let s = store();
        let report = purge_schema_1(&s, "catalog/", false).await.unwrap();
        assert_eq!(
            report,
            PurgeReport {
                purged: vec![h(1)],
                in_use: vec![h(2), h(3)],
                unreadable: vec![h(5)],
                kept: 1,
            }
        );
        assert!(s.deleted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_only_unnamed_v1_documents() {
        let s = store();
        let report = purge_schema_1(&s, "catalog/", true).await.unwrap();
        assert_eq!(report.purged, vec![h(1)]);
        assert_eq!(*s.deleted.lock().unwrap(), vec![h(1)]);
        assert_eq!(s.documents.lock().unwrap().len(), 4);
    }
}
