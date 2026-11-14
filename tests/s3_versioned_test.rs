//! `ObjectStore for S3Client` against a real versioned bucket: conditional
//! creates, delete markers, version listing across pages and version
//! deletion (plan call 12). Every test is ignored, and passes without touching S3 when
//! `TDF_IROH_S3_VERSIONED_BUCKET` or `AWS_REGION` is unset:
//!
//! ```text
//! TDF_IROH_S3_VERSIONED_BUCKET=<scratch versioned bucket> AWS_REGION=<region> \
//!     cargo test --test s3_versioned_test -- --ignored
//! ```
//!
//! Credentials come from the default AWS chain. Each test writes under a
//! prefix of its own and deletes every version it wrote, also when it fails.

use bytes::Bytes;
use futures::FutureExt;
use std::collections::{BTreeSet, HashSet};
use std::panic::AssertUnwindSafe;
use std::time::{SystemTime, UNIX_EPOCH};
use tdf_iroh_s3::object_store::{ObjectStore, VersionInfo};
use tdf_iroh_s3::store::s3::S3Client;

/// A client on the scratch bucket under a prefix no other test or run
/// uses, or `None` to skip.
async fn scratch(test: &str) -> Option<S3Client> {
    let (Ok(bucket), Ok(region)) = (
        std::env::var("TDF_IROH_S3_VERSIONED_BUCKET"),
        std::env::var("AWS_REGION"),
    ) else {
        eprintln!("{test} skipped: set TDF_IROH_S3_VERSIONED_BUCKET and AWS_REGION");
        return None;
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let prefix = format!(
        "tdf-iroh-s3-versioned-test/{test}-{}-{nanos}/",
        std::process::id()
    );
    Some(S3Client::new(&bucket, &region, &prefix).await.unwrap())
}

/// Delete every version under the test's prefix, then report the test's
/// outcome: its panic, if it had one, or a cleanup failure.
async fn clean_up(s3: &S3Client, outcome: std::thread::Result<()>) {
    let cleaned = async {
        let keys: BTreeSet<String> = s3
            .list_versions("")
            .await?
            .into_iter()
            .map(|v| v.key)
            .collect();
        for key in &keys {
            s3.delete_all_versions(key).await?;
        }
        anyhow::ensure!(
            s3.list_versions("").await?.is_empty(),
            "versions are left under the test prefix"
        );
        anyhow::Ok(())
    }
    .await;
    if let Err(panic) = outcome {
        if let Err(e) = cleaned {
            eprintln!("cleanup failed too: {e:#}");
        }
        std::panic::resume_unwind(panic);
    }
    cleaned.expect("clean up the test prefix");
}

fn body(s: &str) -> Bytes {
    Bytes::from(s.to_string())
}

/// Write-once holds while an object exists, and ends once every version is
/// gone: what `release-owner` relies on.
#[tokio::test]
#[ignore = "needs a real versioned bucket: TDF_IROH_S3_VERSIONED_BUCKET"]
async fn conditional_create_after_version_deletion() {
    let Some(s3) = scratch("conditional-create").await else {
        return;
    };
    let outcome = AssertUnwindSafe(async {
        let key = format!("moderation/publishers/{}", "ab".repeat(32));
        assert!(s3.create(&key, body("first")).await.unwrap());
        assert!(!s3.create(&key, body("second")).await.unwrap());
        assert_eq!(s3.get(&key).await.unwrap(), Some(body("first")));
        assert_eq!(s3.head_owner(&key).await.unwrap(), Some(None));

        assert_eq!(s3.delete_all_versions(&key).await.unwrap(), 1);
        assert!(s3.list_versions(&key).await.unwrap().is_empty());
        assert_eq!(s3.get(&key).await.unwrap(), None);
        assert_eq!(s3.head_owner(&key).await.unwrap(), None);

        assert!(s3.create(&key, body("third")).await.unwrap());
        assert_eq!(s3.get(&key).await.unwrap(), Some(body("third")));
    })
    .catch_unwind()
    .await;
    clean_up(&s3, outcome).await;
}

/// A plain `DeleteObject` leaves a delete marker, as a node's delete or an
/// operator's console delete would: it is listed as a marker, leaves no
/// current object, `create` writes over it, and `delete_all_versions`
/// counts and removes it with the key's versions. A plain delete of a key
/// that never held an object leaves a lone marker, removed the same way.
#[tokio::test]
#[ignore = "needs a real versioned bucket: TDF_IROH_S3_VERSIONED_BUCKET"]
async fn a_delete_marker_is_listed_created_over_and_deleted() {
    let Some(s3) = scratch("delete-marker").await else {
        return;
    };
    let outcome = AssertUnwindSafe(async {
        let hash = "ef".repeat(32);
        let (blob, outboard) = (format!("blobs/{hash}"), format!("outboards/{hash}"));
        s3.put(&blob, body("blob")).await.unwrap();
        // Plain deletes of `blobs/<hash>` and of `outboards/<hash>`, which
        // was never written.
        s3.delete_blob(&hash).await.unwrap();

        let markers =
            |versions: &[VersionInfo]| versions.iter().filter(|v| v.delete_marker).count();
        let versions = s3.list_versions(&blob).await.unwrap();
        assert_eq!(versions.len(), 2, "{versions:?}");
        assert_eq!(markers(&versions), 1, "{versions:?}");
        assert!(versions.iter().all(|v| v.key == blob && v.modified > 0));
        assert_eq!(s3.get(&blob).await.unwrap(), None);
        assert_eq!(s3.head_owner(&blob).await.unwrap(), None);
        assert!(
            s3.list(&blob).await.unwrap().is_empty(),
            "no current object"
        );
        let lone = s3.list_versions(&outboard).await.unwrap();
        assert_eq!(lone.len(), 1, "{lone:?}");
        assert_eq!(markers(&lone), 1, "{lone:?}");

        assert!(s3.create(&blob, body("again")).await.unwrap());
        assert_eq!(s3.get(&blob).await.unwrap(), Some(body("again")));
        let versions = s3.list_versions(&blob).await.unwrap();
        assert_eq!(versions.len(), 3, "{versions:?}");
        assert_eq!(markers(&versions), 1, "{versions:?}");

        assert_eq!(s3.delete_all_versions(&blob).await.unwrap(), 3);
        assert_eq!(s3.delete_all_versions(&outboard).await.unwrap(), 1);
        assert!(s3.list_versions("").await.unwrap().is_empty());
    })
    .catch_unwind()
    .await;
    clean_up(&s3, outcome).await;
}

/// Listings span pages: versions of one key split across pages (the
/// version ID marker), and current objects (the continuation token).
/// Deleting one key's versions across pages spares a key it is a prefix of.
#[tokio::test]
#[ignore = "needs a real versioned bucket: TDF_IROH_S3_VERSIONED_BUCKET"]
async fn version_listing_paginates() {
    let Some(s3) = scratch("version-listing").await else {
        return;
    };
    let s3 = s3.with_list_page_size(2);
    let outcome = AssertUnwindSafe(async {
        for i in 0..4 {
            s3.put("v/a", body(&format!("a{i}"))).await.unwrap();
        }
        s3.put("v/ab", body("ab")).await.unwrap();

        let versions = s3.list_versions("v/").await.unwrap();
        assert_eq!(versions.len(), 5, "{versions:?}");
        let ids: HashSet<(&str, &str)> = versions
            .iter()
            .map(|v| (v.key.as_str(), v.version_id.as_str()))
            .collect();
        assert_eq!(ids.len(), 5, "no version listed twice");
        assert_eq!(versions.iter().filter(|v| v.key == "v/a").count(), 4);
        assert!(versions.iter().all(|v| !v.delete_marker && v.modified > 0));

        for key in ["o/1", "o/2", "o/3"] {
            s3.put(key, body(key)).await.unwrap();
        }
        let listed: Vec<String> = s3
            .list("o/")
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.key)
            .collect();
        assert_eq!(listed, ["o/1", "o/2", "o/3"]);

        assert_eq!(s3.delete_all_versions("v/a").await.unwrap(), 4);
        let left = s3.list_versions("v/").await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].key, "v/ab");
    })
    .catch_unwind()
    .await;
    clean_up(&s3, outcome).await;
}

/// Two creates of one key at once: S3 lets exactly one through, and the
/// other reports `false` (412, or 409 while the first is in flight).
#[tokio::test]
#[ignore = "needs a real versioned bucket: TDF_IROH_S3_VERSIONED_BUCKET"]
async fn a_concurrent_conditional_create_reports_false() {
    let Some(s3) = scratch("concurrent-create").await else {
        return;
    };
    let outcome = AssertUnwindSafe(async {
        let key = format!("moderation/publishers/{}", "cd".repeat(32));
        let (a, b) = tokio::join!(s3.create(&key, body("a")), s3.create(&key, body("b")));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert!(a ^ b, "exactly one create wins: {a} {b}");
        let winner = if a { body("a") } else { body("b") };
        assert_eq!(s3.get(&key).await.unwrap(), Some(winner));
        assert_eq!(s3.list_versions(&key).await.unwrap().len(), 1);
    })
    .catch_unwind()
    .await;
    clean_up(&s3, outcome).await;
}
