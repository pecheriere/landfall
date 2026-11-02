//! Bundles by referrers tag, and the caps on what is read.

use landfall_core::ids::ImageDigest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::MockServer;

use super::super::{FetchError, MANIFEST_LIMIT, OCI_INDEX, OCI_MANIFEST, TAG_OBJECT_LIMIT};
use super::{
    BUNDLE, GITHUB_TOKEN, IMAGE, RELEASE_COMMIT, VALID_TAG, index_body, mount_blob, mount_bundles,
    mount_manifest, mount_ref, mount_tag, release_digest, repo, tag,
};
use crate::attestation::SLSA_PROVENANCE;
use crate::test_support::{
    bundle_manifest, fetcher, fetcher_for, mount_token, payload_and_signature, referrers_tag,
    sha256, tag_object_id,
};

#[tokio::test]
async fn bundle_is_found_by_referrers_tag() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    mount_bundles(&registry, &digest, &[(BUNDLE, SLSA_PROVENANCE)]).await;

    let bundle = fetcher(&github, &registry)
        .bundle(IMAGE, &digest)
        .await
        .unwrap();
    assert_eq!(bundle, BUNDLE);
}

#[tokio::test]
async fn bundle_manifest_tagged_directly_is_found() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    mount_token(&registry).await;
    let manifest = bundle_manifest(&digest, BUNDLE, SLSA_PROVENANCE);
    mount_manifest(
        &registry,
        &referrers_tag(&digest),
        OCI_MANIFEST,
        manifest,
        None,
    )
    .await;
    mount_blob(&registry, &sha256(BUNDLE), BUNDLE.to_vec()).await;

    let bundle = fetcher(&github, &registry)
        .bundle(IMAGE, &digest)
        .await
        .unwrap();
    assert_eq!(bundle, BUNDLE);
}

#[tokio::test]
async fn two_bundles_are_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    mount_bundles(
        &registry,
        &digest,
        &[
            (BUNDLE, SLSA_PROVENANCE),
            (b"{\"another\":\"bundle\"}", SLSA_PROVENANCE),
        ],
    )
    .await;

    let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
    assert!(
        matches!(result, Err(FetchError::Bundles { count: 2, .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn missing_referrers_tag_means_no_bundle() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;

    let result = fetcher(&github, &registry)
        .bundle(IMAGE, &release_digest())
        .await;
    assert!(
        matches!(result, Err(FetchError::Bundles { count: 0, .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn bundle_for_another_subject_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    let other: ImageDigest = sha256(b"another index").parse().unwrap();
    mount_token(&registry).await;
    let manifest = bundle_manifest(&other, BUNDLE, SLSA_PROVENANCE);
    mount_manifest(
        &registry,
        &referrers_tag(&digest),
        OCI_MANIFEST,
        manifest,
        None,
    )
    .await;
    mount_blob(&registry, &sha256(BUNDLE), BUNDLE.to_vec()).await;

    let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
    assert!(
        matches!(result, Err(FetchError::Malformed { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn bundle_not_matching_its_descriptor_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let digest = release_digest();
    mount_token(&registry).await;
    let manifest = bundle_manifest(&digest, BUNDLE, SLSA_PROVENANCE);
    mount_manifest(
        &registry,
        &referrers_tag(&digest),
        OCI_MANIFEST,
        manifest,
        None,
    )
    .await;
    let mut altered = BUNDLE.to_vec();
    altered[10] ^= 1;
    mount_blob(&registry, &sha256(BUNDLE), altered).await;

    let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
    assert!(
        matches!(result, Err(FetchError::Digest { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn oversized_body_is_refused() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_token(&registry).await;
    let body = vec![b' '; MANIFEST_LIMIT + 1];
    mount_manifest(&registry, "v1.2.3", OCI_INDEX, body, None).await;

    let result = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await;
    assert!(
        matches!(
            result,
            Err(FetchError::TooLarge {
                limit: MANIFEST_LIMIT,
                ..
            })
        ),
        "{result:?}"
    );
}

/// Without a `Content-Length`, the cap is enforced on the bytes as they
/// arrive: a chunked body one byte over the cap is refused.
#[tokio::test]
async fn oversized_chunked_body_is_refused() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..n]);
        }
        let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                        transfer-encoding: chunked\r\n\r\n";
        socket.write_all(head.as_bytes()).await.unwrap();
        let chunk = vec![b' '; 1024];
        let mut sent = 0;
        // The client hangs up once it is over the cap; writes then fail.
        while sent <= TAG_OBJECT_LIMIT {
            let frame = [format!("{:x}\r\n", chunk.len()).as_bytes(), &chunk, b"\r\n"].concat();
            if socket.write_all(&frame).await.is_err() {
                return;
            }
            sent += chunk.len();
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });

    let base = format!("http://{address}");
    let result = fetcher_for(&base, &base).tag_object(&repo(), &tag()).await;
    assert!(
        matches!(
            result,
            Err(FetchError::TooLarge {
                limit: TAG_OBJECT_LIMIT,
                ..
            })
        ),
        "{result:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn token_is_not_sent_to_registry() {
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
    mount_manifest(&registry, "v1.2.3", OCI_INDEX, index_body(), None).await;
    let digest = release_digest();
    mount_bundles(&registry, &digest, &[(BUNDLE, SLSA_PROVENANCE)]).await;

    let fetcher = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap();
    fetcher.tag_object(&repo(), &tag()).await.unwrap();
    fetcher.resolve_index(IMAGE, &tag()).await.unwrap();
    fetcher.bundle(IMAGE, &digest).await.unwrap();

    let authorization = |request: &wiremock::Request| {
        request
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned())
    };
    let to_github = github.received_requests().await.unwrap();
    assert!(!to_github.is_empty());
    for request in &to_github {
        assert_eq!(
            authorization(request).as_deref(),
            Some("Bearer github-test-token")
        );
    }
    let to_registry = registry.received_requests().await.unwrap();
    assert!(to_registry.len() >= 5);
    for request in &to_registry {
        let sent = authorization(request);
        assert!(
            sent.as_deref().is_none_or(|v| !v.contains(GITHUB_TOKEN)),
            "{} carried the GitHub token",
            request.url
        );
        if request.url.path().starts_with("/v2/") {
            assert_eq!(sent.as_deref(), Some("Bearer registry-test-token"));
        }
    }
}
