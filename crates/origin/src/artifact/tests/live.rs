//! A real file, through the real GitHub, against the real bundle.

use serde_json::Value;
use wiremock::MockServer;

use super::super::{ReleaseFileNames, ReleaseIdentity, verify_release_file};
use super::{
    BUNDLE, OWNER_ID, REAL_BUNDLE, REAL_COMMIT, REAL_FILE, REAL_SUMS, REAL_SUMS_NAME, REAL_TAG,
    REPO, REPO_ID, Release, SIGNER_SEED, WORKFLOW, commit, digest, principal, repo, root,
    signer_key, tag,
};
use crate::fetch::{BINARY_LIMIT, Endpoints, Fetcher};
use crate::test_support::{TestSigner, fetcher, sha256};

/// Real signature, real identity, real sums, real bytes: downloads `act`'s file through
/// the real redirect and storage host, then serves it with the real bundle and sums and a
/// tag object signed here over `act`'s real commit, as `act` isn't signed by a key of ours.
/// Needs network; an 8 MB third-party file.
#[tokio::test]
#[ignore = "needs the network and downloads an 8 MB file"]
async fn live_real_release_file_verifies() {
    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let mut public = Fetcher::new(Endpoints::public().unwrap()).unwrap();
    if let Some(token) = &token {
        public = public.with_github_token(token).unwrap();
    }
    let repo = repo();
    let release_tag = tag(REAL_TAG);
    let assets = public.release_assets(&repo, &release_tag).await.unwrap();
    let asset = assets.iter().find(|a| a.name == REAL_FILE).unwrap();
    let bytes = public
        .release_asset(&repo, asset, BINARY_LIMIT)
        .await
        .unwrap();
    assert_eq!(u64::try_from(bytes.len()).unwrap(), asset.size);
    assert_eq!(sha256(&bytes), github_digest(token.as_deref()).await);

    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let release = Release {
        tag_object: Some(TestSigner::new(SIGNER_SEED).tag_object(REAL_TAG, REAL_COMMIT)),
        assets: vec![
            (REAL_FILE, bytes.len(), bytes.clone()),
            (REAL_SUMS_NAME, REAL_SUMS.len(), REAL_SUMS.to_vec()),
            (BUNDLE, REAL_BUNDLE.len(), REAL_BUNDLE.to_vec()),
        ],
    };
    release.serve(&github, REAL_TAG).await;
    let key = signer_key();
    let signers = [(principal(), &key)];
    let identity = ReleaseIdentity {
        repo: &repo,
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        workflow: WORKFLOW,
        signers: &signers,
    };
    let verified = verify_release_file(
        &fetcher(&github, &registry),
        &root(),
        &identity,
        &release_tag,
        &ReleaseFileNames {
            file: REAL_FILE,
            sums: REAL_SUMS_NAME,
            bundle: BUNDLE,
        },
    )
    .await
    .unwrap();

    assert_eq!(verified.bytes, bytes);
    assert_eq!(verified.digest, digest(&bytes));
    assert_eq!(verified.attestation.digest, digest(&bytes));
    assert_eq!(verified.commit, commit(REAL_COMMIT));
    assert_eq!(
        verified.attestation.run_url,
        "https://github.com/nektos/act/actions/runs/41234509130/attempts/1"
    );
}

/// What GitHub says the file's digest is, read apart from the code under test.
async fn github_digest(token: Option<&str>) -> String {
    let client = reqwest::Client::builder()
        .user_agent("landfall-test")
        .build()
        .unwrap();
    let mut request = client.get(format!(
        "https://api.github.com/repos/{REPO}/releases/tags/{REAL_TAG}"
    ));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let body = request.send().await.unwrap().bytes().await.unwrap();
    let release: Value = serde_json::from_slice(&body).unwrap();
    release["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|asset| asset["name"] == REAL_FILE)
        .unwrap()["digest"]
        .as_str()
        .unwrap()
        .to_owned()
}
