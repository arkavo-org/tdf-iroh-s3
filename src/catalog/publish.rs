//! Orchestrates one creator publish: write payload + manifest to S3,
//! append a CWT-authenticated event to the iroh-docs replica.
//!
//! Catalog projection is reader-side; nothing is written back to the
//! replica as a snapshot.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::auth::VerifiedClaims;
use crate::catalog::keys;
use crate::catalog::replica::CatalogReplica;
use crate::catalog::{
    CatalogEntry, ContentManifest, ContentMetadata, EventAuthorization, PublishEvent,
    PublishEventKind, PublishOutcome,
};
use crate::store::s3::S3Client;

/// Publish a validated TDF blob into the creator's namespace.
///
/// Caller must have already passed the blob through the validation pipeline
/// and verified the CWT (see [`crate::auth::Verifier::verify`]). This
/// function does not re-verify; it assigns identity, persists payload +
/// manifest to S3, and appends a CWT-authorized publish event to the
/// catalog replica.
pub async fn publish_content(
    metadata: ContentMetadata,
    payload: Bytes,
    auth: &VerifiedClaims,
    replica: &CatalogReplica,
    s3: &S3Client,
) -> Result<PublishOutcome> {
    if metadata.title.trim().is_empty() {
        bail!("content metadata title must not be empty");
    }

    // v1 read-side CWT exposes the issuer-supplied identity as `subject`.
    // The catalog's persisted shape still calls this `creator_id`; the
    // publisher-side rewrite (Task 12+) will reconcile naming end to end.
    let creator_id = auth.subject.as_str();
    let content_id = blake3::hash(&payload).to_hex().to_string();
    let payload_size = payload.len() as u64;
    let published_at = now_rfc3339()?;
    let prefix = s3.prefix();

    // 1. Payload — idempotent: skip if a prior publish already wrote the bytes.
    let payload_key = keys::content_payload_key(prefix, creator_id, &content_id);
    if !s3.head_object(&payload_key).await? {
        s3.put_object_bytes(&payload_key, payload).await?;
    }

    let tdf_ref = format!("iroh:{content_id}");
    let manifest_key = keys::content_manifest_key(prefix, creator_id, &content_id);

    // 2. Per-content manifest. Overwrites on republish so the latest
    //    creator-supplied metadata wins.
    let content_manifest = ContentManifest {
        content_id: content_id.clone(),
        creator_id: creator_id.to_string(),
        title: metadata.title.clone(),
        visibility: metadata.visibility,
        required_tier_ids: metadata.required_tier_ids.clone(),
        payload_size,
        tdf_ref: tdf_ref.clone(),
        published_at: published_at.clone(),
    };
    s3.put_json(&manifest_key, &content_manifest).await?;

    let entry = CatalogEntry {
        content_id: content_id.clone(),
        creator_id: creator_id.to_string(),
        title: metadata.title,
        visibility: metadata.visibility,
        required_tier_ids: metadata.required_tier_ids,
        tdf_ref,
        manifest_ref: manifest_key,
        published_at: published_at.clone(),
    };

    // 3. Append the publish event to the iroh-docs replica.
    //    `replica.append_event` allocates the next seq, stamps it into
    //    the body, and writes the entry atomically.
    let authorization = EventAuthorization {
        cwt_b64: STANDARD.encode(&auth.raw_cwt),
        issuer: auth.issuer.clone(),
        cti: auth.cti.clone(),
    };
    let event = PublishEvent {
        seq: 0, // overwritten by replica.append_event
        creator_id: creator_id.to_string(),
        content_id: content_id.clone(),
        kind: PublishEventKind::Publish,
        published_at,
        entry,
        authorization,
    };
    let seq = replica.append_event(event).await?;

    Ok(PublishOutcome { content_id, seq })
}

fn now_rfc3339() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("Failed to format current time as RFC3339")
}
