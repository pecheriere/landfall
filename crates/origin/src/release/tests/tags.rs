//! The release tag: unsigned, lightweight, annotated and signed.

use landfall_core::tag::TagVerifyError;

use super::super::ReleaseError;
use super::{
    BUNDLE, SIGNED_COMMIT, VALID_TAG, VW_COMMIT, VW_DIGEST, VW_REPO, VW_TAG, mount_signed_tag,
    mount_unsigned_release, platform, servers, signed_config, unsigned_config, verify,
};
use crate::attestation::SLSA_PROVENANCE;
use crate::test_support::{mount_bundles, mount_ref, mount_tag};

#[tokio::test]
async fn unsigned_release_verifies_end_to_end() {
    let (github, registry) = servers().await;
    mount_unsigned_release(&github, &registry).await;
    mount_bundles(
        &registry,
        VW_REPO,
        &VW_DIGEST.parse().unwrap(),
        &[(BUNDLE, SLSA_PROVENANCE)],
    )
    .await;

    let origin = verify(
        &github,
        &registry,
        &unsigned_config(121_898_717),
        VW_TAG,
        "linux/arm64",
    )
    .await
    .unwrap();
    assert_eq!(origin.commit.as_ref(), VW_COMMIT);
    assert_eq!(origin.tag, None);
    assert_eq!(origin.attestation.digest.as_ref(), VW_DIGEST);
    assert_eq!(origin.attestation.commit.as_ref(), VW_COMMIT);
    assert_eq!(
        origin.platforms,
        ["linux/amd64", "linux/arm/v7", "linux/arm64", "linux/arm/v6"].map(platform)
    );
    let json = serde_json::to_value(&origin).unwrap();
    assert_eq!(json["tag"], serde_json::Value::Null);
    assert_eq!(json["attestation"]["digest"], VW_DIGEST);
    assert_eq!(json["platforms"][1]["variant"], "v7");
}

#[tokio::test]
async fn bad_tag_pattern_is_refused_before_any_request() {
    let (github, registry) = servers().await;
    let result = verify(&github, &registry, &signed_config(), "1.2.3", "linux/amd64").await;
    assert!(
        matches!(result, Err(ReleaseError::TagPattern(_))),
        "{result:?}"
    );
    assert!(github.received_requests().await.unwrap().is_empty());
    assert!(registry.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn lightweight_tag_is_not_signed() {
    let (github, registry) = servers().await;
    mount_ref(&github, "example/app", "v1.2.3", "commit", SIGNED_COMMIT).await;

    let result = verify(
        &github,
        &registry,
        &signed_config(),
        "v1.2.3",
        "linux/amd64",
    )
    .await;
    assert!(
        matches!(
            result,
            Err(ReleaseError::TagSignature(TagVerifyError::NotSigned))
        ),
        "{result:?}"
    );
    let error = result.unwrap_err();
    assert_eq!(error.to_string(), "tag signature");
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "tag is not signed"
    );
}

#[tokio::test]
async fn unsigned_annotated_tag_is_not_signed() {
    let (github, registry) = servers().await;
    let sha = "1".repeat(40);
    mount_ref(&github, "example/app", "v1.2.3", "tag", &sha).await;
    mount_tag(
        &github,
        ("example/app", "v1.2.3"),
        &sha,
        (SIGNED_COMMIT, "commit"),
        None,
    )
    .await;

    let result = verify(
        &github,
        &registry,
        &signed_config(),
        "v1.2.3",
        "linux/amd64",
    )
    .await;
    assert!(
        matches!(
            result,
            Err(ReleaseError::TagSignature(TagVerifyError::NotSigned))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn unsigned_deployment_accepts_a_lightweight_tag() {
    let (github, registry) = servers().await;
    // The tag step passes on a lightweight tag; nothing is in the
    // registry, so the next step fails.
    mount_ref(&github, VW_REPO, VW_TAG, "commit", VW_COMMIT).await;

    let result = verify(
        &github,
        &registry,
        &unsigned_config(121_898_717),
        VW_TAG,
        "linux/amd64",
    )
    .await;
    assert!(matches!(result, Err(ReleaseError::Index(_))), "{result:?}");
}

#[tokio::test]
async fn bad_signature_is_refused() {
    let (github, registry) = servers().await;
    // The object id matches the bytes served, but the signed message
    // was altered after signing.
    let tampered = String::from_utf8(VALID_TAG.to_vec()).unwrap().replacen(
        "release v1.2.3",
        "release v1.2.4",
        1,
    );
    assert_ne!(tampered.as_bytes(), VALID_TAG);
    mount_signed_tag(&github, tampered.as_bytes()).await;

    let result = verify(
        &github,
        &registry,
        &signed_config(),
        "v1.2.3",
        "linux/amd64",
    )
    .await;
    assert!(
        matches!(
            result,
            Err(ReleaseError::TagSignature(TagVerifyError::BadSignature))
        ),
        "{result:?}"
    );
}
