//! Candidates against a mock registry and the real attestation fixture, which
//! verifies for one digest, tag and commit of one project.

use std::time::Duration;

use landfall_core::config::{self, Config};
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::release::{ReleaseRun, RunCandidate, select_release_run};
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{
    AttestedDigests, CandidateCache, RULED_OUT_LIFETIME, UNATTESTED_LIFETIME, attested_digests,
};
use crate::attestation::SLSA_PROVENANCE;
use crate::fetch::OCI_INDEX;
use crate::release::ReleaseError;
use crate::test_support::{fetcher, mount_bundles, mount_manifest, referrers_index, referrers_tag};
use crate::trust::TrustRoot;

const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/attestation/bundle.json");
const TRUSTED_ROOT: &str = include_str!("../../tests/fixtures/attestation/trusted_root.json");
const REPO: &str = "dani-garcia/vaultwarden";
const TAG: &str = "1.37.4";
const COMMIT: &str = "7c188967e7a467b19b2757bc3326f9cf3ccae327";
const DIGEST: &str = "sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055";
const TAGS: &str = "/v2/dani-garcia/vaultwarden/tags/list";

fn config(repo_id: u64) -> Config {
    let text = format!(
        r#"
[approvers]
operator = {{ credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }}

[[deployment]]
id = "app/prod"
repo = {{ name = "{REPO}", id = {repo_id}, owner_id = 725423 }}
host = "host-1"
compose = {{ dir = "/srv/app", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "*", signed_tags = false }}
rule = {{ approvers = ["operator"] }}
checks = ["container-healthy"]
"#
    );
    config::parse(text.as_bytes()).unwrap()
}

fn deployment() -> DeploymentId {
    "app/prod".parse().unwrap()
}

fn real_digest() -> ImageDigest {
    DIGEST.parse().unwrap()
}

/// The real digest with the run the real bundle's certificate names, as read from
/// the fixture by verifying it.
fn real_candidate() -> RunCandidate {
    let tag: ReleaseTag = TAG.parse().unwrap();
    let commit: CommitSha = COMMIT.parse().unwrap();
    let repo = REPO.parse().unwrap();
    let attestation = crate::attestation::verify_bundle(
        BUNDLE,
        &real_digest(),
        &TrustRoot::from_json(TRUSTED_ROOT),
        &crate::attestation::Expected {
            repo: &repo,
            repo_id: 121_898_717,
            owner_id: 725_423,
            workflow: ".github/workflows/release.yml",
            tag: &tag,
            commit: &commit,
        },
    )
    .unwrap();
    RunCandidate {
        digest: real_digest(),
        run_url: attestation.run_url,
    }
}

fn other_digest(c: char) -> ImageDigest {
    format!("sha256:{}", c.to_string().repeat(64))
        .parse()
        .unwrap()
}

struct Mocks {
    github: MockServer,
    registry: MockServer,
}

impl Mocks {
    /// The registry lists `digests`, with the real bundle attached to the real
    /// digest.
    async fn listing(digests: &[&ImageDigest]) -> Self {
        let registry = MockServer::start().await;
        mount_bundles(
            &registry,
            REPO,
            &real_digest(),
            &[(BUNDLE, SLSA_PROVENANCE)],
        )
        .await;
        let tags: Vec<String> = digests.iter().map(|d| referrers_tag(d)).collect();
        Mock::given(method("GET"))
            .and(path(TAGS))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "tags": tags })))
            .mount(&registry)
            .await;
        Self {
            github: MockServer::start().await,
            registry,
        }
    }

    async fn ask(
        &self,
        cache: &CandidateCache,
        tag: &str,
    ) -> Result<AttestedDigests, ReleaseError> {
        self.ask_config(&config(121_898_717), cache, tag).await
    }

    async fn ask_config(
        &self,
        config: &Config,
        cache: &CandidateCache,
        tag: &str,
    ) -> Result<AttestedDigests, ReleaseError> {
        // A version digest nothing in these tests lists.
        self.ask_for(config, cache, tag, &other_digest('9')).await
    }

    async fn ask_for(
        &self,
        config: &Config,
        cache: &CandidateCache,
        tag: &str,
        version_digest: &ImageDigest,
    ) -> Result<AttestedDigests, ReleaseError> {
        let tag: ReleaseTag = tag.parse().unwrap();
        let commit: CommitSha = COMMIT.parse().unwrap();
        attested_digests(
            &fetcher(&self.github, &self.registry),
            &TrustRoot::from_json(TRUSTED_ROOT),
            config,
            (&deployment(), &tag, &commit, version_digest),
            cache,
        )
        .await
    }

    /// How many times a bundle was downloaded.
    async fn bundle_fetches(&self) -> usize {
        self.registry
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("/blobs/"))
            .count()
    }
}

#[tokio::test]
async fn a_candidate_that_verifies_counts() {
    let mocks = Mocks::listing(&[&real_digest()]).await;
    let answer = mocks.ask(&CandidateCache::default(), TAG).await.unwrap();
    assert_eq!(answer.verified, [real_candidate()]);
    assert_eq!(answer.ignored, []);
}

#[tokio::test]
async fn a_verified_result_is_kept_and_not_verified_again() {
    let mocks = Mocks::listing(&[&real_digest()]).await;
    let cache = CandidateCache::default();
    for _ in 0..3 {
        // The cached result keeps the run it came from.
        let answer = mocks.ask(&cache, TAG).await.unwrap();
        assert_eq!(answer.verified, [real_candidate()]);
    }
    assert_eq!(mocks.bundle_fetches().await, 1);
}

#[tokio::test]
async fn a_candidate_that_does_not_verify_is_ignored_and_says_why() {
    // The real bundle, attached to a digest it does not attest.
    let wrong = other_digest('a');
    let mocks = Mocks::listing(&[&real_digest(), &wrong]).await;
    mount_bundles(&mocks.registry, REPO, &wrong, &[(BUNDLE, SLSA_PROVENANCE)]).await;

    let answer = mocks.ask(&CandidateCache::default(), TAG).await.unwrap();
    assert_eq!(answer.verified, [real_candidate()]);
    assert_eq!(answer.ignored.len(), 1, "{answer:?}");
    assert_eq!(answer.ignored[0].digest, wrong);
    assert!(answer.ignored[0].reason.contains("attests"), "{answer:?}");
}

#[tokio::test]
async fn a_candidate_with_nothing_attached_is_ignored() {
    // The referrer tag is listed and its manifest is a 404.
    let empty = other_digest('b');
    let mocks = Mocks::listing(&[&real_digest(), &empty]).await;
    let answer = mocks.ask(&CandidateCache::default(), TAG).await.unwrap();
    assert_eq!(answer.verified, [real_candidate()]);
    assert_eq!(answer.ignored.len(), 1, "{answer:?}");
}

#[tokio::test]
async fn a_candidate_with_no_provenance_bundle_is_looked_at_again_only_in_time() {
    let empty = other_digest('b');
    let mocks = Mocks::listing(&[&empty]).await;
    mount_manifest(
        &mocks.registry,
        (REPO, &referrers_tag(&empty)),
        OCI_INDEX,
        referrers_index(&[]),
        None,
    )
    .await;
    // Thousands of these must not cost a request each on every look.
    let cache = CandidateCache::default();
    assert_eq!(mocks.ask(&cache, TAG).await.unwrap().ignored.len(), 1);
    assert_eq!(mocks.ask(&cache, TAG).await.unwrap().ignored.len(), 0);

    // It may be being published right now.
    let soon = CandidateCache::with_lifetimes(RULED_OUT_LIFETIME, Duration::ZERO);
    assert_eq!(mocks.ask(&soon, TAG).await.unwrap().ignored.len(), 1);
    assert_eq!(mocks.ask(&soon, TAG).await.unwrap().ignored.len(), 1);
}

#[tokio::test]
async fn one_junk_answer_about_the_version_digest_does_not_stick() {
    let mocks = Mocks::listing(&[&real_digest()]).await;
    // A 200 that is an HTML error page, once, in place of the referrer index.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v2/{REPO}/manifests/{}",
            referrers_tag(&real_digest())
        )))
        .respond_with(ResponseTemplate::new(200).set_body_raw("<html>oops</html>", "text/html"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&mocks.registry)
        .await;
    let cache = CandidateCache::default();
    let config = config(121_898_717);

    let first = mocks
        .ask_for(&config, &cache, TAG, &real_digest())
        .await
        .unwrap();
    assert_eq!(first.verified, []);
    assert_eq!(first.ignored.len(), 1, "{first:?}");

    let second = mocks
        .ask_for(&config, &cache, TAG, &real_digest())
        .await
        .unwrap();
    assert_eq!(second.verified, [real_candidate()]);
}

#[tokio::test]
async fn the_digest_just_verified_is_looked_at_whatever_is_remembered() {
    let mocks = Mocks::listing(&[&real_digest()]).await;
    let cache = CandidateCache::default();
    cache.keep_ruled_out((deployment(), real_digest()), None, RULED_OUT_LIFETIME);
    let config = config(121_898_717);

    // Any other digest stays ruled out, this one does not.
    assert_eq!(mocks.ask(&cache, TAG).await.unwrap().verified, []);
    let answer = mocks
        .ask_for(&config, &cache, TAG, &real_digest())
        .await
        .unwrap();
    assert_eq!(answer.verified, [real_candidate()]);
}

#[tokio::test]
async fn one_token_serves_a_whole_look() {
    let (a, b) = (other_digest('a'), other_digest('b'));
    let mocks = Mocks::listing(&[&real_digest(), &a, &b]).await;
    mocks.ask(&CandidateCache::default(), TAG).await.unwrap();
    let tokens = mocks
        .registry
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/token")
        .count();
    assert_eq!(tokens, 1);
}

#[tokio::test]
async fn a_candidate_whose_material_cannot_be_read_fails_closed() {
    // It might have verified, so the answer is not "there is only one".
    let unread = other_digest('c');
    let mocks = Mocks::listing(&[&real_digest(), &unread]).await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v2/{REPO}/manifests/{}$",
            referrers_tag(&unread)
        )))
        .respond_with(ResponseTemplate::new(502))
        .mount(&mocks.registry)
        .await;

    let error = mocks
        .ask(&CandidateCache::default(), TAG)
        .await
        .unwrap_err();
    assert!(matches!(error, ReleaseError::Listing(_)), "{error:?}");
    assert!(!error.is_refusal(), "{error:?}");
}

#[tokio::test]
async fn an_unreadable_list_fails_closed() {
    let registry = MockServer::start().await;
    mount_bundles(
        &registry,
        REPO,
        &real_digest(),
        &[(BUNDLE, SLSA_PROVENANCE)],
    )
    .await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(ResponseTemplate::new(500))
        .mount(&registry)
        .await;
    let mocks = Mocks {
        github: MockServer::start().await,
        registry,
    };

    let error = mocks
        .ask(&CandidateCache::default(), TAG)
        .await
        .unwrap_err();
    assert!(matches!(error, ReleaseError::Listing(_)), "{error:?}");
}

#[tokio::test]
async fn a_bundle_for_another_release_is_fetched_once_across_releases() {
    let mocks = Mocks::listing(&[&real_digest()]).await;
    let cache = CandidateCache::default();

    // It names 1.37.4's ref, so it is not these releases'.
    for tag in ["2.0.0", "2.0.1", "2.0.2"] {
        let answer = mocks.ask(&cache, tag).await.unwrap();
        assert_eq!(answer.verified, [], "{tag}");
    }
    assert_eq!(mocks.bundle_fetches().await, 1);

    // It is still looked at for the release it names.
    let answer = mocks.ask(&cache, TAG).await.unwrap();
    assert_eq!(answer.verified, [real_candidate()]);
    assert_eq!(mocks.bundle_fetches().await, 2);
}

#[tokio::test]
async fn a_bundle_of_another_repository_is_ruled_out_for_every_release() {
    let mocks = Mocks::listing(&[&real_digest()]).await;
    let cache = CandidateCache::default();
    let other_repo_id = config(1);
    for tag in [TAG, "2.0.0"] {
        let answer = mocks.ask_config(&other_repo_id, &cache, tag).await.unwrap();
        assert_eq!(answer.verified, [], "{tag}");
    }
    assert_eq!(mocks.bundle_fetches().await, 1);
}

/// The attestation fixture's release on the real registry: every referrer tag of
/// the image is looked at, and two digests verify, since the project's one
/// workflow attests two image variants per tag: `1.37.4`, the digest the fixture
/// holds, and `1.37.4-alpine`. They come from one run and attempt, so the rule
/// passes the release.
#[tokio::test]
#[ignore = "network: runs nightly in advisories.yml"]
async fn live_the_fixture_release_has_two_variants_from_one_run() {
    let cache_dir = tempfile::tempdir().unwrap();
    let root = crate::trust::load_trusted_root(cache_dir.path(), crate::trust::Refresh::Online)
        .await
        .unwrap();
    let fetcher = crate::fetch::Fetcher::new(crate::fetch::Endpoints::public().unwrap()).unwrap();
    let tag: ReleaseTag = TAG.parse().unwrap();
    let commit: CommitSha = COMMIT.parse().unwrap();
    let cache = CandidateCache::default();
    let version_digest = real_digest();
    let target = (&deployment(), &tag, &commit, &version_digest);
    let config = config(121_898_717);

    let answer = attested_digests(&fetcher, &root, &config, target, &cache)
        .await
        .unwrap();
    let alpine: ImageDigest =
        "sha256:19ea2b669945d842dadc3d500f2d6a795866a003330f59a47b9634658bae98bb"
            .parse()
            .unwrap();
    let found: Vec<&ImageDigest> = answer.verified.iter().map(|c| &c.digest).collect();
    assert_eq!(found, [&alpine, &real_digest()]);
    let repo = REPO.parse().unwrap();
    let run = select_release_run(&repo, &answer.verified, &real_digest()).unwrap();
    assert_eq!(
        run,
        ReleaseRun {
            run: 37_388_798_451,
            attempt: 1
        }
    );
    assert_eq!(answer.verified[0].run_url, answer.verified[1].run_url);

    // What verified is known now, and what named another release is ruled out.
    let started = std::time::Instant::now();
    let again = attested_digests(&fetcher, &root, &config, target, &cache)
        .await
        .unwrap();
    assert_eq!(again.verified, answer.verified);
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[tokio::test]
async fn what_ruled_a_candidate_out_is_forgotten_in_time() {
    let mocks = Mocks::listing(&[&real_digest()]).await;
    let cache = CandidateCache::with_lifetimes(Duration::ZERO, UNATTESTED_LIFETIME);
    for tag in ["2.0.0", "2.0.1"] {
        mocks.ask(&cache, tag).await.unwrap();
    }
    assert_eq!(mocks.bundle_fetches().await, 2);
}
