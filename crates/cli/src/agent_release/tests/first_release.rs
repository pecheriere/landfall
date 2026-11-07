//! The first release, `v0.1.0-rc.1`, as it was published, verified offline: our own key on
//! our own tag, our own workflow's bundle and our own sums, through the code `host install`
//! runs. `tests/fixtures/first-release/README.md` says how each file was taken.

use landfall_core::ids::{ReleaseTag, RepoName};
use landfall_origin::artifact::{FileError, ReleaseFileNames, VerifiedFile, verify_release_file};
use landfall_origin::fetch::{Endpoints, Fetcher};
use landfall_origin::trust::TrustRoot;
use reqwest::Url;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::{SUMS_ASSET, bundle_asset, project_identity, release_version, signer_refs};
use crate::project;

/// `GET /repos/<repo>/git/ref/tags/<tag>`, as GitHub answered it.
const TAG_REF: &[u8] = include_bytes!("../../../tests/fixtures/first-release/tag-ref.json");

/// `GET /repos/<repo>/git/tags/<sha>`, as GitHub answered it.
const TAG_OBJECT: &[u8] = include_bytes!("../../../tests/fixtures/first-release/tag-object.json");

const LICENSE: &[u8] = include_bytes!("../../../tests/fixtures/first-release/LICENSE-MIT");

const SUMS: &[u8] = include_bytes!("../../../tests/fixtures/first-release/SHA256SUMS");

const BUNDLE: &[u8] =
    include_bytes!("../../../tests/fixtures/first-release/landfall-0.1.0-rc.1.sigstore.json");

const TRUSTED_ROOT: &str = include_str!("../../../tests/fixtures/first-release/trusted_root.json");

const TAG: &str = "v0.1.0-rc.1";

const TAG_OBJECT_SHA: &str = "eb34bcbd17ead0bd41238f1d3f624c0f83c23fd6";

const COMMIT: &str = "42e8a3c14edc7a869fe6a45e9d1712a5e59bfea5";

/// The release key's fingerprint, as `SECURITY.md` publishes it.
const SIGNER_FINGERPRINT: &str = "SHA256:NQDx0iXAXnjJDtJz662lf+yEZuX46AZ20/RHcBU0TIk";

const LICENSE_NAME: &str = "LICENSE-MIT";

/// GitHub's digest of `LICENSE-MIT` in the release, which `SHA256SUMS` also gives.
const LICENSE_DIGEST: &str =
    "sha256:7f938b6860cf9430784996eb1e4ccd093b34d4be0e5437862c5c7aa6f1dcc584";

/// GitHub's digest of `SHA256SUMS` in the release.
const SUMS_DIGEST: &str = "sha256:2700656b8e91f46972ae4fe376bb8a855a46a3fa1dab58091747e1afb43eeb6b";

const RUN_URL: &str = "https://github.com/pecheriere/landfall/actions/runs/42409255476/attempts/1";

/// GitHub's ids of the release's assets.
const LICENSE_ID: u64 = 722_081_439;
const SUMS_ID: u64 = 722_081_432;
const BUNDLE_ID: u64 = 722_081_475;

fn tag() -> ReleaseTag {
    TAG.parse().unwrap()
}

/// Serves the release on `github`: the tag as GitHub answered, and each asset, by GitHub's
/// id, with the name it is listed under and the bytes it holds.
async fn serve(github: &MockServer, assets: &[(u64, &str, &[u8])]) {
    let repo = project::REPO;
    let json_body =
        |bytes: &[u8]| ResponseTemplate::new(200).set_body_raw(bytes, "application/json");
    Mock::given(method("GET"))
        .and(path(format!("/repos/{repo}/git/ref/tags/{TAG}")))
        .respond_with(json_body(TAG_REF))
        .mount(github)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/{repo}/git/tags/{TAG_OBJECT_SHA}")))
        .respond_with(json_body(TAG_OBJECT))
        .mount(github)
        .await;
    let listed: Vec<_> = assets
        .iter()
        .map(|(id, name, bytes)| json!({ "id": id, "name": name, "size": bytes.len() }))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!("/repos/{repo}/releases/tags/{TAG}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "tag_name": TAG, "assets": listed })),
        )
        .mount(github)
        .await;
    for (id, _, bytes) in assets {
        Mock::given(method("GET"))
            .and(path(format!("/repos/{repo}/releases/assets/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
            .mount(github)
            .await;
    }
}

/// `LICENSE-MIT` of the release served with `assets`, verified for real, with this build's
/// embedded identity and signers, against the snapshot root.
async fn verify_license(assets: &[(u64, &str, &[u8])]) -> Result<VerifiedFile, FileError> {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    serve(&github, assets).await;
    let fetcher = Fetcher::new(Endpoints::plain_http(
        Url::parse(&github.uri()).unwrap(),
        Url::parse(&registry.uri()).unwrap(),
    ))
    .unwrap();
    let root = TrustRoot::from_json(TRUSTED_ROOT).unwrap();
    let keys = project::signers().unwrap();
    let signers = signer_refs(&keys);
    let repo: RepoName = project::REPO.parse().unwrap();
    let identity = project_identity(&repo, &signers);
    let bundle = bundle_name();
    let names = ReleaseFileNames {
        file: LICENSE_NAME,
        sums: SUMS_ASSET,
        bundle: &bundle,
    };
    verify_release_file(&fetcher, &root, &identity, &tag(), &names).await
}

/// The bundle's name, as `host install` asks for it.
fn bundle_name() -> String {
    bundle_asset(&release_version(&tag()).unwrap())
}

#[tokio::test]
async fn first_release_verifies_offline() {
    let bundle = bundle_name();
    let verified = verify_license(&[
        (LICENSE_ID, LICENSE_NAME, LICENSE),
        (SUMS_ID, SUMS_ASSET, SUMS),
        (BUNDLE_ID, &bundle, BUNDLE),
    ])
    .await
    .unwrap();

    assert_eq!(verified.name, LICENSE_NAME);
    assert_eq!(verified.bytes, LICENSE);
    assert_eq!(verified.digest.as_ref() as &str, LICENSE_DIGEST);
    assert_eq!(verified.commit.as_ref() as &str, COMMIT);
    assert_eq!(verified.tag.tag, tag());
    assert_eq!(verified.tag.commit.as_ref() as &str, COMMIT);
    assert_eq!(verified.tag.fingerprint, SIGNER_FINGERPRINT);
    let attestation = &verified.attestation;
    assert_eq!(attestation.digest.as_ref() as &str, LICENSE_DIGEST);
    assert_eq!(attestation.commit.as_ref() as &str, COMMIT);
    assert_eq!(attestation.git_ref, format!("refs/tags/{TAG}"));
    assert_eq!(attestation.repo_id, project::REPO_ID);
    assert_eq!(attestation.owner_id, project::OWNER_ID);
    assert_eq!(attestation.run_url, RUN_URL);
    assert_eq!(
        attestation.san,
        format!(
            "https://github.com/{}/{}@refs/tags/{TAG}",
            project::REPO,
            project::WORKFLOW
        )
    );
    assert_eq!(attestation.rekor_log_index, 3_746_720_453);
    assert_eq!(attestation.integrated_time, 1_794_089_053);
}

/// The sums are a subject of the same bundle, so only the sums' own line can tell them from
/// the file wanted.
#[tokio::test]
async fn first_release_sums_under_the_license_name_are_refused() {
    let bundle = bundle_name();
    let error = verify_license(&[
        (LICENSE_ID, LICENSE_NAME, SUMS),
        (SUMS_ID, SUMS_ASSET, SUMS),
        (BUNDLE_ID, &bundle, BUNDLE),
    ])
    .await
    .unwrap_err();

    assert!(error.is_refusal(), "{error:?}");
    let FileError::SumsMismatch {
        name,
        expected,
        computed,
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(name, LICENSE_NAME);
    assert_eq!(expected, LICENSE_DIGEST);
    assert_eq!(computed, SUMS_DIGEST);
}
