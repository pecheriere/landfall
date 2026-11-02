//! The index and the attestation that must name the signed commit.

use landfall_core::release::PlatformError;

use super::super::ReleaseError;
use super::{
    BUNDLE, INDEX, OTHER_COMMIT_TAG, SIGNED_COMMIT, VALID_TAG, VW_COMMIT, VW_DIGEST, VW_REPO,
    VW_TAG, mount_signed_tag, mount_signed_tag_of, mount_unsigned_release, platform, servers,
    signed_config, signed_fixture_project_config, unsigned_config, verify,
};
use crate::attestation::{AttestationError, SLSA_PROVENANCE};
use crate::fetch::{FetchError, OCI_INDEX, OCI_MANIFEST};
use crate::test_support::{mount_bundles, mount_manifest, mount_token};

#[tokio::test]
async fn single_arch_manifest_is_refused() {
    let (github, registry) = servers().await;
    mount_signed_tag(&github, VALID_TAG).await;
    mount_token(&registry).await;
    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
    mount_manifest(
        &registry,
        ("example/app", "1.2.3"),
        OCI_MANIFEST,
        manifest.to_vec(),
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
            Err(ReleaseError::Index(FetchError::MediaType { .. }))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn missing_bundle_is_refused() {
    let (github, registry) = servers().await;
    mount_signed_tag(&github, VALID_TAG).await;
    mount_token(&registry).await;
    mount_manifest(
        &registry,
        ("example/app", "1.2.3"),
        OCI_INDEX,
        INDEX.to_vec(),
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
            Err(ReleaseError::Bundle(FetchError::Bundles { count: 0, .. }))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn signed_tag_commit_is_what_the_attestation_must_name() {
    let (github, registry) = servers().await;
    // A signed tag of the fixture project that matches the real bundle
    // in repository, ids, tag and workflow, but names another commit:
    // the bundle is refused for its commit, so the signed tag's commit is
    // what the attestation is checked against.
    mount_signed_tag_of(&github, (VW_REPO, VW_TAG), OTHER_COMMIT_TAG).await;
    mount_token(&registry).await;
    mount_manifest(
        &registry,
        (VW_REPO, VW_TAG),
        OCI_INDEX,
        INDEX.to_vec(),
        Some(VW_DIGEST),
    )
    .await;
    mount_bundles(
        &registry,
        VW_REPO,
        &VW_DIGEST.parse().unwrap(),
        &[(BUNDLE, SLSA_PROVENANCE)],
    )
    .await;

    let result = verify(
        &github,
        &registry,
        &signed_fixture_project_config(),
        VW_TAG,
        "linux/amd64",
    )
    .await;
    match result {
        Err(ReleaseError::Attestation(AttestationError::Identity {
            field,
            expected,
            found,
        })) => {
            assert_eq!(field, "source_repository_digest");
            assert_eq!(expected, SIGNED_COMMIT);
            assert_eq!(found, VW_COMMIT);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn identity_mismatch_is_refused() {
    let (github, registry) = servers().await;
    mount_unsigned_release(&github, &registry).await;
    mount_bundles(
        &registry,
        VW_REPO,
        &VW_DIGEST.parse().unwrap(),
        &[(BUNDLE, SLSA_PROVENANCE)],
    )
    .await;

    let result = verify(
        &github,
        &registry,
        &unsigned_config(1),
        VW_TAG,
        "linux/amd64",
    )
    .await;
    match result {
        Err(ReleaseError::Attestation(AttestationError::Identity { field, .. })) => {
            assert_eq!(field, "source_repository_identifier");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn missing_platform_is_refused() {
    let (github, registry) = servers().await;
    mount_unsigned_release(&github, &registry).await;
    mount_bundles(
        &registry,
        VW_REPO,
        &VW_DIGEST.parse().unwrap(),
        &[(BUNDLE, SLSA_PROVENANCE)],
    )
    .await;

    let result = verify(
        &github,
        &registry,
        &unsigned_config(121_898_717),
        VW_TAG,
        "linux/riscv64",
    )
    .await;
    match result {
        Err(ReleaseError::Platform(PlatformError::Missing { want, available })) => {
            assert_eq!(want, platform("linux/riscv64"));
            assert_eq!(available.len(), 4);
        }
        other => panic!("{other:?}"),
    }
}
