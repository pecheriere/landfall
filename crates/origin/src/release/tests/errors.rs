//! Platforms, and how errors are told apart.

use landfall_core::release::{ReleaseRun, RunRuleError};
use landfall_core::tag::TagVerifyError;

use super::super::{ReleaseError, verify_release};
use super::{
    BUNDLE, VW_COMMIT, VW_DIGEST, VW_REPO, VW_TAG, deployment, mount_unsigned_release, platform,
    root, servers, signed_config, unsigned_config, verify,
};
use crate::attestation::{AttestationError, SLSA_PROVENANCE};
use crate::fetch::{Endpoints, FetchError, Fetcher};
use crate::test_support::{fetcher, mount_bundles};
use crate::trust::{Refresh, load_trusted_root};

/// The controller has no platform of its own, so it has none to miss: the
/// release that fails only that step passes without it.
#[tokio::test]
async fn the_origin_alone_asks_for_no_platform() {
    let (github, registry) = servers().await;
    mount_unsigned_release(&github, &registry).await;
    mount_bundles(
        &registry,
        VW_REPO,
        &VW_DIGEST.parse().unwrap(),
        &[(BUNDLE, SLSA_PROVENANCE)],
    )
    .await;

    let origin = super::super::verify_release_origin(
        &fetcher(&github, &registry),
        &root(),
        &unsigned_config(121_898_717),
        &deployment(),
        &VW_TAG.parse().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(origin.attestation.digest.as_ref(), VW_DIGEST);
    assert_eq!(origin.platforms.len(), 4);
}

#[test]
fn a_failed_fetch_can_be_told_from_the_rest() {
    let fetch = || FetchError::NotFound {
        url: "https://example.test".to_owned(),
    };
    assert!(ReleaseError::Listing(fetch()).fetch_error().is_some());
    assert!(!ReleaseError::Listing(fetch()).is_refusal());
    assert!(ReleaseError::Index(fetch()).fetch_error().is_some());
    assert!(ReleaseError::NoTrustRoot.fetch_error().is_none());
    assert!(!ReleaseError::NoTrustRoot.is_refusal());
}

#[tokio::test]
async fn unknown_deployment_is_refused() {
    let (github, registry) = servers().await;
    let result = verify_release(
        &fetcher(&github, &registry),
        &root(),
        &signed_config(),
        &"other/prod".parse().unwrap(),
        &"v1.2.3".parse().unwrap(),
        &platform("linux/amd64"),
    )
    .await;
    assert!(
        matches!(result, Err(ReleaseError::UnknownDeployment(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn refusals_are_told_apart_from_unavailable_material() {
    let (github, registry) = servers().await;
    // Nothing is mounted: the tag ref is a 404, which a later try may
    // find.
    let result = verify(
        &github,
        &registry,
        &unsigned_config(121_898_717),
        VW_TAG,
        "linux/amd64",
    )
    .await;
    match result {
        Err(error @ ReleaseError::TagCommit(FetchError::NotFound { .. })) => {
            assert!(!error.is_refusal(), "{error:?}");
        }
        other => panic!("{other:?}"),
    }

    // A verification result is a refusal.
    assert!(ReleaseError::TagSignature(TagVerifyError::NotSigned).is_refusal());
    let run = |run| ReleaseRun { run, attempt: 1 };
    let runs = vec![run(1), run(2)];
    assert!(ReleaseError::Runs(RunRuleError::SeveralRuns { runs }).is_refusal());
    assert!(ReleaseError::Attestation(AttestationError::Signature("x".to_owned())).is_refusal());

    // What one bad answer from a server can cause is not: a 200 HTML error
    // page must not refuse a release for good.
    let bundles = |count| FetchError::Bundles {
        digest: VW_DIGEST.parse().unwrap(),
        count,
    };
    let url = || "https://example.test/x".to_owned();
    let json = || FetchError::Json {
        url: url(),
        source: serde_json::from_str::<u8>("<html>").unwrap_err(),
    };
    let malformed = || FetchError::Malformed {
        url: url(),
        reason: "x".to_owned(),
    };
    let media_type = || FetchError::MediaType {
        url: url(),
        found: "text/html".to_owned(),
        expected: "json",
    };
    let too_large = || FetchError::TooLarge {
        url: url(),
        limit: 1,
    };
    for fetch in [json(), malformed(), media_type(), too_large()] {
        assert!(!ReleaseError::Index(fetch).is_refusal());
    }
    for fetch in [json(), malformed(), media_type(), too_large()] {
        assert!(!ReleaseError::TagObject(fetch).is_refusal());
    }
    for fetch in [json(), malformed(), media_type(), too_large()] {
        assert!(!ReleaseError::TagCommit(fetch).is_refusal());
    }
    for fetch in [json(), malformed(), media_type(), too_large()] {
        assert!(!ReleaseError::Bundle(fetch).is_refusal());
    }
    assert!(!ReleaseError::Bundle(bundles(2)).is_refusal());
    assert!(!ReleaseError::Attestation(AttestationError::Bundle("junk".to_owned())).is_refusal());
    assert!(
        !ReleaseError::Attestation(AttestationError::ClockBehind("late".to_owned())).is_refusal()
    );
    let outside = ReleaseError::Runs(RunRuleError::VersionDigestOutside {
        digest: VW_DIGEST.parse().unwrap(),
    });
    assert!(!outside.is_refusal());
    assert!(outside.is_slow_to_retry());
    // A release still being published has no provenance bundle yet.
    assert!(!ReleaseError::Bundle(bundles(0)).is_refusal());
    assert!(!ReleaseError::UnknownDeployment(deployment()).is_refusal());
}

/// The attestation fixture's release, verified end to end against the
/// real GitHub API, GHCR and Sigstore TUF repository, as an unsigned
/// deployment.
#[tokio::test]
#[ignore = "network: runs nightly in advisories.yml"]
async fn live_unsigned_release_verifies() {
    let cache = tempfile::tempdir().unwrap();
    let root = load_trusted_root(cache.path(), Refresh::Online)
        .await
        .unwrap();
    let mut fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
    // The nightly job passes its token for the higher API rate limit.
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        fetcher = fetcher.with_github_token(&token).unwrap();
    }

    let origin = verify_release(
        &fetcher,
        &root,
        &unsigned_config(121_898_717),
        &deployment(),
        &VW_TAG.parse().unwrap(),
        &platform("linux/amd64"),
    )
    .await
    .unwrap();
    assert_eq!(origin.commit.as_ref(), VW_COMMIT);
    assert_eq!(origin.tag, None);
    assert_eq!(origin.attestation.digest.as_ref(), VW_DIGEST);
}
