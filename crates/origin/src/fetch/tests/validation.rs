//! What is refused before or after a request.

use landfall_core::ids::ReleaseTag;
use reqwest::Url;
use serde_json::json;
use wiremock::MockServer;

use super::super::{Endpoints, FetchError, MAX_TAG_DEPTH, OCI_INDEX, OCI_MANIFEST};
use super::{
    BUNDLE, IMAGE, RELEASE_COMMIT, SBOM, index_body, mount_blob, mount_bundles, mount_manifest,
    mount_ref, mount_tag, release_digest, repo, tag,
};
use crate::attestation::SLSA_PROVENANCE;
use crate::test_support::{
    bundle_manifest, fetcher, fetcher_for, mount_token, referrers_index, referrers_tag, sha256,
};

#[test]
fn endpoints_must_be_https() {
    let https = Url::parse("https://registry.example").unwrap();
    for bad in [
        "http://api.example",
        "https://user:pass@api.example",
        "https://api.example/?x=1",
        "https://api.example/#x",
    ] {
        let result = Endpoints::new(Url::parse(bad).unwrap(), https.clone());
        assert!(
            matches!(result, Err(FetchError::Endpoint { .. })),
            "{bad}: {result:?}"
        );
        let result = Endpoints::new(https.clone(), Url::parse(bad).unwrap());
        assert!(
            matches!(result, Err(FetchError::Endpoint { .. })),
            "{bad}: {result:?}"
        );
    }
    assert!(Endpoints::public().is_ok());
}

#[tokio::test]
async fn image_name_is_validated() {
    let fetcher = fetcher_for("http://127.0.0.1:9", "http://127.0.0.1:9");
    for bad in [
        "",
        "Example/app",
        "example/../app",
        "example//app",
        "example/app?x",
        "-x/app",
        "example/app:tag",
    ] {
        let result = fetcher.resolve_index(bad, &tag()).await;
        assert!(
            matches!(result, Err(FetchError::Image(_))),
            "{bad:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn release_tag_outside_oci_grammar_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    mount_manifest(&registry, "y", OCI_INDEX, index_body(), None).await;
    let fetcher = fetcher(&github, &registry);
    for bad in ["x/manifests/y", "a+b"] {
        let tag: ReleaseTag = bad.parse().unwrap();
        let result = fetcher.resolve_index(IMAGE, &tag).await;
        match result {
            Err(FetchError::OciTag(refused)) => assert_eq!(refused, tag),
            other => panic!("{bad}: {other:?}"),
        }
    }
    let requests = registry.received_requests().await.unwrap();
    assert!(
        requests.is_empty(),
        "{} requests reached the registry",
        requests.len()
    );
}

#[tokio::test]
async fn index_without_platforms_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    let mut index: serde_json::Value = serde_json::from_slice(&index_body()).unwrap();
    // Only the attestation manifest is left, which is not a platform.
    let attestation = index["manifests"][1].clone();
    index["manifests"] = json!([attestation]);
    let body = serde_json::to_vec(&index).unwrap();
    mount_manifest(&registry, "v1.2.3", OCI_INDEX, body, None).await;

    let result = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::Malformed { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn deeply_nested_tag_is_refused_without_extra_requests() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let shas: Vec<String> = (1..=MAX_TAG_DEPTH + 1)
        .map(|n| n.to_string().repeat(40))
        .collect();
    mount_ref(&github, "tag", &shas[0]).await;
    for pair in shas.windows(2) {
        mount_tag(&github, &pair[0], (&pair[1], "tag"), None).await;
    }
    mount_tag(
        &github,
        &shas[MAX_TAG_DEPTH],
        (RELEASE_COMMIT, "commit"),
        None,
    )
    .await;

    let result = fetcher(&github, &registry)
        .tag_commit(&repo(), &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::TagDepth { .. })),
        "{result:?}"
    );
    // The ref, then exactly MAX_TAG_DEPTH tag objects.
    let requests = github.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1 + MAX_TAG_DEPTH);
}

#[tokio::test]
async fn provenance_bundle_is_selected_over_sbom() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    let sbom: &[u8] = b"{\"an\":\"sbom bundle\"}";
    mount_bundles(
        &registry,
        &digest,
        &[(sbom, SBOM), (BUNDLE, SLSA_PROVENANCE)],
    )
    .await;

    let bundle = fetcher(&github, &registry)
        .bundle(IMAGE, &digest)
        .await
        .unwrap();
    assert_eq!(bundle, BUNDLE);
}

#[tokio::test]
async fn bundle_descriptor_without_predicate_type_is_not_counted() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    mount_token(&registry).await;
    let manifest = bundle_manifest(&digest, BUNDLE, SLSA_PROVENANCE);
    let index = referrers_index(&[(&manifest, None)]);
    mount_manifest(&registry, &referrers_tag(&digest), OCI_INDEX, index, None).await;

    let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
    assert!(
        matches!(result, Err(FetchError::Bundles { count: 0, .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn manifest_annotation_disagreeing_with_descriptor_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    mount_token(&registry).await;
    let manifest = bundle_manifest(&digest, BUNDLE, SBOM);
    let index = referrers_index(&[(&manifest, Some(SLSA_PROVENANCE))]);
    mount_manifest(&registry, &referrers_tag(&digest), OCI_INDEX, index, None).await;
    mount_manifest(&registry, &sha256(&manifest), OCI_MANIFEST, manifest, None).await;
    mount_blob(&registry, &sha256(BUNDLE), BUNDLE.to_vec()).await;

    let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
    assert!(
        matches!(result, Err(FetchError::Malformed { .. })),
        "{result:?}"
    );
}
