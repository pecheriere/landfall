//! Tag objects, tag commits and image indexes.

use landfall_core::ids::CommitSha;
use landfall_core::release::Platform;
use serde_json::json;
use wiremock::MockServer;

use super::super::{DOCKER_LIST, FetchError, OCI_INDEX, OCI_MANIFEST};
use super::{
    IMAGE, RELEASE_COMMIT, VALID_TAG, index_body, mount_manifest, mount_ref, mount_tag,
    release_digest, repo, tag,
};
use crate::attestation::SLSA_PROVENANCE;
use crate::test_support::{
    bundle_manifest, fetcher, mount_token, payload_and_signature, sha256, tag_object_id,
};

#[tokio::test]
async fn tag_object_round_trips() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let sha = tag_object_id(VALID_TAG);
    let (payload, signature) = payload_and_signature(VALID_TAG);
    mount_ref(&github, "tag", &sha).await;
    mount_tag(
        &github,
        &sha,
        (RELEASE_COMMIT, "commit"),
        Some((&payload, &signature)),
    )
    .await;

    let raw = fetcher(&github, &registry)
        .tag_object(&repo(), &tag())
        .await
        .unwrap();
    assert_eq!(raw, VALID_TAG);
}

#[tokio::test]
async fn lightweight_tag_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_ref(&github, "commit", RELEASE_COMMIT).await;

    let result = fetcher(&github, &registry)
        .tag_object(&repo(), &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::LightweightTag { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn unsigned_annotated_tag_is_not_signed() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let sha = "1".repeat(40);
    mount_ref(&github, "tag", &sha).await;
    mount_tag(&github, &sha, (RELEASE_COMMIT, "commit"), None).await;

    let result = fetcher(&github, &registry)
        .tag_object(&repo(), &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::NotSigned { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn tag_object_id_mismatch_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let sha = tag_object_id(VALID_TAG);
    let (payload, signature) = payload_and_signature(VALID_TAG);
    let altered = payload.replace("release v1.2.3", "release v1.2.4");
    mount_ref(&github, "tag", &sha).await;
    mount_tag(
        &github,
        &sha,
        (RELEASE_COMMIT, "commit"),
        Some((&altered, &signature)),
    )
    .await;

    let result = fetcher(&github, &registry)
        .tag_object(&repo(), &tag())
        .await;
    match result {
        Err(FetchError::ObjectId { expected, computed }) => {
            assert_eq!(expected, sha);
            assert_ne!(computed, sha);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn tag_commit_peels_annotated_and_lightweight() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_ref(&github, "commit", RELEASE_COMMIT).await;
    let commit = fetcher(&github, &registry)
        .tag_commit(&repo(), &tag())
        .await
        .unwrap();
    assert_eq!(commit, RELEASE_COMMIT.parse::<CommitSha>().unwrap());

    let annotated = MockServer::start().await;
    let (outer, inner) = ("1".repeat(40), "2".repeat(40));
    mount_ref(&annotated, "tag", &outer).await;
    mount_tag(&annotated, &outer, (&inner, "tag"), None).await;
    mount_tag(&annotated, &inner, (RELEASE_COMMIT, "commit"), None).await;
    let commit = fetcher(&annotated, &registry)
        .tag_commit(&repo(), &tag())
        .await
        .unwrap();
    assert_eq!(commit, RELEASE_COMMIT.parse::<CommitSha>().unwrap());

    let tree = MockServer::start().await;
    mount_ref(&tree, "tag", &outer).await;
    mount_tag(&tree, &outer, (&inner, "tree"), None).await;
    let result = fetcher(&tree, &registry).tag_commit(&repo(), &tag()).await;
    assert!(
        matches!(result, Err(FetchError::ObjectType { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn index_digest_is_computed_from_bytes() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    let body = index_body();
    let expected = sha256(&body);
    mount_manifest(&registry, "v1.2.3", OCI_INDEX, body, None).await;

    let (digest, platforms) = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await
        .unwrap();
    assert_eq!(digest.as_ref(), expected);
    assert_eq!(
        platforms,
        [
            Platform {
                os: "linux".into(),
                architecture: "amd64".into(),
                variant: None
            },
            Platform {
                os: "linux".into(),
                architecture: "arm".into(),
                variant: Some("v7".into()),
            },
        ]
    );
}

#[tokio::test]
async fn docker_manifest_list_is_accepted_with_matching_header() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    let body = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": DOCKER_LIST,
        "manifests": [{
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": sha256(b"arm64"), "size": 1000,
            "platform": { "architecture": "arm64", "os": "linux", "variant": "v8" },
        }],
    }))
    .unwrap();
    let expected = sha256(&body);
    mount_manifest(&registry, "v1.2.3", DOCKER_LIST, body, Some(&expected)).await;

    let (digest, platforms) = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await
        .unwrap();
    assert_eq!(digest.as_ref(), expected);
    assert_eq!(platforms.len(), 1);
}

#[tokio::test]
async fn manifest_digest_mismatch_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    let body = index_body();
    let header = sha256(b"some other index");
    mount_manifest(&registry, "v1.2.3", OCI_INDEX, body.clone(), Some(&header)).await;

    let result = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await;
    match result {
        Err(FetchError::Digest {
            expected, computed, ..
        }) => {
            assert_eq!(expected, header);
            assert_eq!(computed, sha256(&body));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn single_arch_manifest_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    let body = bundle_manifest(&release_digest(), b"{}", SLSA_PROVENANCE);
    mount_manifest(&registry, "v1.2.3", OCI_MANIFEST, body, None).await;

    let result = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await;
    match result {
        Err(FetchError::MediaType { found, .. }) => assert_eq!(found, OCI_MANIFEST),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn index_whose_body_contradicts_its_media_type_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    let mut index: serde_json::Value = serde_json::from_slice(&index_body()).unwrap();
    index["mediaType"] = json!(OCI_MANIFEST);
    let body = serde_json::to_vec(&index).unwrap();
    mount_manifest(&registry, "v1.2.3", OCI_INDEX, body, None).await;

    let result = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::MediaType { .. })),
        "{result:?}"
    );
}
