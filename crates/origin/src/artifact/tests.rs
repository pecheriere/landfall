//! A release's file through every check, against a mock GitHub.

use landfall_core::config::SignerKey;
use landfall_core::ids::{CommitSha, ImageDigest, PrincipalId, ReleaseTag, RepoName};
use landfall_core::tag::TagVerifyError;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{
    FileError, OwnedExpected, ReleaseFileNames, ReleaseIdentity, VerifiedFile, check_release_file,
    parse_sums, verify_release_file,
};
use crate::attestation::{AttestationError, FileSubject, VerifiedAttestation, verify_file_bundle};
use crate::fetch::{BINARY_LIMIT, FetchError};
use crate::release::ReleaseError;
use crate::test_support::{TestSigner, fetcher, mount_ref, mount_signed_tag, mount_tag, sha256};
use crate::trust::TrustRoot;

mod live;
mod sums;

const REAL_BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/attestation-files/bundle.json");

const REAL_SUMS: &[u8] = include_bytes!("../../tests/fixtures/attestation-files/checksums.txt");

const TRUSTED_ROOT: &str = include_str!("../../tests/fixtures/attestation-files/trusted_root.json");

const REPO: &str = "nektos/act";

const REPO_ID: u64 = 163_883_279;

const OWNER_ID: u64 = 3_813_618;

const WORKFLOW: &str = ".github/workflows/release.yml";

const REAL_TAG: &str = "v0.2.94";

const REAL_COMMIT: &str = "3fde8e609623104b099747ff67166561ecb7e6be";

const REAL_FILE: &str = "act_Linux_arm64.tar.gz";

const REAL_SUMS_NAME: &str = "checksums.txt";

const TAG: &str = "v1.2.3";

const FILE: &str = "file";

const FILE_BYTES: &[u8] = b"made-up file bytes";

const SUMS: &str = "SHA256SUMS";

const BUNDLE: &str = "bundle.json";

const BUNDLE_BYTES: &[u8] = b"made-up bundle bytes";

const SIGNER_SEED: u8 = 1;

const TOO_MANY_BYTES: usize = BINARY_LIMIT + 1;

fn repo() -> RepoName {
    REPO.parse().unwrap()
}

fn tag(name: &str) -> ReleaseTag {
    name.parse().unwrap()
}

fn commit(sha: &str) -> CommitSha {
    sha.parse().unwrap()
}

fn digest(bytes: &[u8]) -> ImageDigest {
    sha256(bytes).parse().unwrap()
}

fn hex_of(bytes: &[u8]) -> String {
    sha256(bytes).strip_prefix("sha256:").unwrap().to_owned()
}

fn sums_for(bytes: &[u8]) -> Vec<u8> {
    format!("{}  {FILE}\n", hex_of(bytes)).into_bytes()
}

fn root() -> TrustRoot {
    TrustRoot::from_json(TRUSTED_ROOT).unwrap()
}

fn principal() -> PrincipalId {
    "maintainer".parse().unwrap()
}

/// Names the fake and real checks alike ask for.
fn names() -> ReleaseFileNames<'static> {
    ReleaseFileNames {
        file: FILE,
        sums: SUMS,
        bundle: BUNDLE,
    }
}

/// What the mock GitHub serves. Each test changes what it is about.
struct Release {
    /// The raw tag object, or nothing for a tag that isn't signed.
    tag_object: Option<Vec<u8>>,
    /// Each asset: its name, the size GitHub lists, and its bytes.
    assets: Vec<(&'static str, usize, Vec<u8>)>,
}

impl Release {
    /// A release that passes everything, for the tag asked for, over `sha`.
    fn good(tag: &str, sha: &str) -> Self {
        let sums = sums_for(FILE_BYTES);
        Self {
            tag_object: Some(TestSigner::new(SIGNER_SEED).tag_object(tag, sha)),
            assets: vec![
                (FILE, FILE_BYTES.len(), FILE_BYTES.to_vec()),
                (SUMS, sums.len(), sums),
                (BUNDLE, BUNDLE_BYTES.len(), BUNDLE_BYTES.to_vec()),
            ],
        }
    }

    /// With the sums replaced.
    fn with_sums(mut self, sums: &[u8]) -> Self {
        self.assets[1] = (SUMS, sums.len(), sums.to_vec());
        self
    }

    /// Mounts it on `github`.
    async fn serve(&self, github: &MockServer, tag: &str) {
        if let Some(raw) = &self.tag_object {
            mount_signed_tag(github, REPO, tag, raw).await;
        } else {
            let object = "c".repeat(40);
            mount_ref(github, REPO, tag, "tag", &object).await;
            mount_tag(github, (REPO, tag), &object, (REAL_COMMIT, "commit"), None).await;
        }
        let listed: Vec<Value> = self
            .assets
            .iter()
            .enumerate()
            .map(|(id, (name, size, _))| json!({ "id": id, "name": name, "size": size }))
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("/repos/{REPO}/releases/tags/{tag}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "tag_name": tag, "assets": listed })),
            )
            .mount(github)
            .await;
        for (id, (_, _, bytes)) in self.assets.iter().enumerate() {
            Mock::given(method("GET"))
                .and(path(format!("/repos/{REPO}/releases/assets/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
                .mount(github)
                .await;
        }
    }
}

/// A verified attestation for the file, as the fake check returns it.
fn attestation(run_url: &str) -> VerifiedAttestation {
    VerifiedAttestation {
        digest: digest(FILE_BYTES),
        san: "the san".to_owned(),
        commit: commit(REAL_COMMIT),
        git_ref: format!("refs/tags/{TAG}"),
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        run_url: run_url.to_owned(),
        rekor_log_index: 1,
        integrated_time: 2,
    }
}

const FIRST_RUN: &str = "https://github.com/nektos/act/actions/runs/1/attempts/1";

/// What a bundle check is asked about.
type Subjects = Vec<(String, ImageDigest)>;

/// What a bundle check answers.
type Checked = Result<VerifiedAttestation, AttestationError>;

/// A check that accepts anything: what is then refused, is refused by the rest.
fn accepts() -> impl FnOnce(Vec<u8>, Subjects, OwnedExpected) -> Checked + Send + 'static {
    |_, _, _| Ok(attestation(FIRST_RUN))
}

/// The real verifier on the real bundle, for a real file the fake bytes stand in for, so
/// that what is checked is `expected`, which must be right for this to pass.
fn real_identity_check() -> impl FnOnce(Vec<u8>, Subjects, OwnedExpected) -> Checked + Send + 'static
{
    |_, _, expected| {
        let sums = parse_sums(REAL_SUMS).unwrap();
        let subjects = [FileSubject {
            name: REAL_FILE,
            digest: &sums[REAL_FILE],
        }];
        verify_file_bundle(REAL_BUNDLE, &subjects, &root(), &expected.expected())
    }
}

/// Runs the checks against `release`, with these trusted keys.
async fn run<C>(
    release: &Release,
    tag_name: &str,
    trusted: &SignerKey,
    bundle_check: C,
) -> Result<VerifiedFile, FileError>
where
    C: FnOnce(
            Vec<u8>,
            Vec<(String, ImageDigest)>,
            OwnedExpected,
        ) -> Result<VerifiedAttestation, AttestationError>
        + Send
        + 'static,
{
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    release.serve(&github, tag_name).await;
    let repo = repo();
    let signers = [(principal(), trusted)];
    let identity = ReleaseIdentity {
        repo: &repo,
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        workflow: WORKFLOW,
        signers: &signers,
    };
    check_release_file(
        &fetcher(&github, &registry),
        &identity,
        &tag(tag_name),
        &names(),
        bundle_check,
    )
    .await
}

fn signer_key() -> SignerKey {
    TestSigner::new(SIGNER_SEED).key()
}

#[tokio::test]
async fn release_file_passes_with_every_check_satisfied() {
    let release = Release::good(TAG, REAL_COMMIT);
    let verified = run(
        &release,
        TAG,
        &signer_key(),
        |bundle, subjects, expected| {
            assert_eq!(bundle, BUNDLE_BYTES);
            assert_eq!(
                subjects,
                [
                    (FILE.to_owned(), digest(FILE_BYTES)),
                    (SUMS.to_owned(), digest(&sums_for(FILE_BYTES))),
                ]
            );
            let expected = expected.expected();
            assert_eq!(expected.repo, &repo());
            assert_eq!(expected.repo_id, REPO_ID);
            assert_eq!(expected.owner_id, OWNER_ID);
            assert_eq!(expected.workflow, WORKFLOW);
            assert_eq!(expected.tag, &tag(TAG));
            assert_eq!(expected.commit, &commit(REAL_COMMIT));
            Ok(attestation(FIRST_RUN))
        },
    )
    .await
    .unwrap();

    assert_eq!(verified.name, FILE);
    assert_eq!(verified.bytes, FILE_BYTES);
    assert_eq!(verified.digest, digest(FILE_BYTES));
    assert_eq!(verified.commit, commit(REAL_COMMIT));
    assert_eq!(verified.tag.tag, tag(TAG));
    assert_eq!(verified.tag.signer, principal());
    assert_eq!(verified.tag.fingerprint, signer_key().fingerprint());
    assert_eq!(verified.attestation, attestation(FIRST_RUN));
}

/// What a row of the table expects of the error.
type Expectation = fn(&FileError) -> bool;

fn is_not_signed(error: &FileError) -> bool {
    matches!(
        error,
        FileError::Tag(ReleaseError::TagSignature(TagVerifyError::NotSigned))
    )
}

fn is_signed_for_another_tag(error: &FileError) -> bool {
    matches!(
        error,
        FileError::Tag(ReleaseError::TagSignature(TagVerifyError::WrongTag { .. }))
    )
}

fn is_missing_sums(error: &FileError) -> bool {
    matches!(error, FileError::Asset { name, count: 0 } if name == SUMS)
}

fn is_doubled_file(error: &FileError) -> bool {
    matches!(error, FileError::Asset { name, count: 2 } if name == FILE)
}

fn is_not_in_sums(error: &FileError) -> bool {
    matches!(error, FileError::NotInSums { name } if name == FILE)
}

fn is_mismatch(error: &FileError) -> bool {
    let (expected, computed) = (digest(b"other").to_string(), digest(FILE_BYTES).to_string());
    matches!(
        error,
        FileError::SumsMismatch { name, expected: e, computed: c }
            if name == FILE && *e == expected && *c == computed
    )
}

fn is_duplicate(error: &FileError) -> bool {
    matches!(error, FileError::SumsDuplicate { .. })
}

fn is_malformed_sums(error: &FileError) -> bool {
    matches!(error, FileError::SumsMalformed { line: 1, .. })
}

fn is_too_large(error: &FileError) -> bool {
    matches!(
        error,
        FileError::Download { name, source: FetchError::TooLarge { .. } } if name == FILE
    )
}

/// Each way a release is wrong, on the good release: the error is its own, and no bytes
/// come back, as the answer is an error. The fake check accepts anything, so each is
/// refused by the check it is about.
#[tokio::test]
async fn verify_release_file_needs_every_check() {
    let good = || Release::good(TAG, REAL_COMMIT);
    let unsigned = Release {
        tag_object: None,
        ..good()
    };
    let another_tag_signed = Release {
        tag_object: Some(TestSigner::new(SIGNER_SEED).tag_object("v9.9.9", REAL_COMMIT)),
        ..good()
    };
    let mut no_sums = good();
    no_sums.assets.remove(1);
    let mut doubled = good();
    doubled
        .assets
        .push((FILE, FILE_BYTES.len(), FILE_BYTES.to_vec()));
    let mut too_big = good();
    too_big.assets[0].1 = TOO_MANY_BYTES;

    let other_sums = format!("{}  {FILE}\n", hex_of(b"other")).into_bytes();
    let other_name = format!("{}  another\n", hex_of(FILE_BYTES)).into_bytes();
    let line = format!("{}  {FILE}\n", hex_of(FILE_BYTES));
    let twice = format!("{line}{line}").into_bytes();
    let table: Vec<(&str, Release, Expectation, bool)> = vec![
        ("no signature", unsigned, is_not_signed, true),
        (
            "signed for another tag",
            another_tag_signed,
            is_signed_for_another_tag,
            true,
        ),
        ("missing sums", no_sums, is_missing_sums, false),
        ("the file twice", doubled, is_doubled_file, false),
        ("a file over the cap", too_big, is_too_large, false),
        (
            "name absent from sums",
            good().with_sums(&other_name),
            is_not_in_sums,
            true,
        ),
        (
            "a sums mismatch",
            good().with_sums(&other_sums),
            is_mismatch,
            true,
        ),
        (
            "duplicate names in sums",
            good().with_sums(&twice),
            is_duplicate,
            true,
        ),
        (
            "sums that don't parse",
            good().with_sums(b"nonsense\n"),
            is_malformed_sums,
            true,
        ),
    ];
    for (name, release, expected, refusal) in table {
        let error = run(&release, TAG, &signer_key(), accepts())
            .await
            .unwrap_err();
        assert!(expected(&error), "{name}: {error:?}");
        assert_eq!(error.is_refusal(), refusal, "{name}: {error:?}");
    }
}

/// A file's listed size just over its kind's cap: refused at that cap and for that file, so
/// the sums and the bundle can't be as large as a binary.
#[tokio::test]
async fn each_kind_of_file_has_its_own_cap() {
    for (index, name, cap) in [
        (0, FILE, 67_108_864),
        (1, SUMS, 65_536),
        (2, BUNDLE, 4_194_304),
    ] {
        let mut release = Release::good(TAG, REAL_COMMIT);
        release.assets[index].1 = cap + 1;
        let error = run(&release, TAG, &signer_key(), accepts())
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                FileError::Download {
                    name: found,
                    source: FetchError::TooLarge { limit, .. },
                } if found == name && *limit == cap
            ),
            "{name}: {error:?}"
        );
        assert!(!error.is_refusal());
    }
}

/// The sums must be attested too. The file here is, as it is the fixture's real
/// `checksums.txt`, and the sums that vouch for it aren't, as they are made up. No fake:
/// [`verify_release_file`] must ask about both.
#[tokio::test]
async fn unattested_sums_are_refused_though_the_file_is_attested() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let sums = format!("{}  {REAL_SUMS_NAME}\n", hex_of(REAL_SUMS)).into_bytes();
    let release = Release {
        tag_object: Some(TestSigner::new(SIGNER_SEED).tag_object(REAL_TAG, REAL_COMMIT)),
        assets: vec![
            (REAL_SUMS_NAME, REAL_SUMS.len(), REAL_SUMS.to_vec()),
            (SUMS, sums.len(), sums),
            (BUNDLE, REAL_BUNDLE.len(), REAL_BUNDLE.to_vec()),
        ],
    };
    release.serve(&github, REAL_TAG).await;
    let repo = repo();
    let key = signer_key();
    let signers = [(principal(), &key)];
    let identity = ReleaseIdentity {
        repo: &repo,
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        workflow: WORKFLOW,
        signers: &signers,
    };
    let error = verify_release_file(
        &fetcher(&github, &registry),
        &root(),
        &identity,
        &tag(REAL_TAG),
        &ReleaseFileNames {
            file: REAL_SUMS_NAME,
            sums: SUMS,
            bundle: BUNDLE,
        },
    )
    .await
    .unwrap_err();
    let FileError::Attestation(AttestationError::FileSubject { name, .. }) = &error else {
        panic!("{error:?}");
    };
    assert_eq!(name, SUMS);
    assert!(error.is_refusal());
}

#[tokio::test]
async fn an_unknown_signer_names_the_trusted_fingerprints() {
    let release = Release {
        tag_object: Some(TestSigner::new(2).tag_object(TAG, REAL_COMMIT)),
        ..Release::good(TAG, REAL_COMMIT)
    };
    let error = run(&release, TAG, &signer_key(), accepts())
        .await
        .unwrap_err();
    let fingerprint = signer_key().fingerprint();
    let FileError::UntrustedSigner { trusted } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(trusted, std::slice::from_ref(&fingerprint));
    assert!(error.to_string().contains(&fingerprint), "{error}");
    assert!(error.is_refusal());
}

#[tokio::test]
async fn nothing_is_listed_or_downloaded_before_the_tag_is_verified() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let release = Release {
        tag_object: None,
        ..Release::good(TAG, REAL_COMMIT)
    };
    release.serve(&github, TAG).await;
    let repo = repo();
    let key = signer_key();
    let signers = [(principal(), &key)];
    let identity = ReleaseIdentity {
        repo: &repo,
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        workflow: WORKFLOW,
        signers: &signers,
    };
    let result = check_release_file(
        &fetcher(&github, &registry),
        &identity,
        &tag(TAG),
        &names(),
        accepts(),
    )
    .await;
    assert!(result.is_err());
    let requested: Vec<String> = github
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| request.url.path().to_owned())
        .collect();
    assert!(
        requested.iter().all(|path| path.contains("/git/")),
        "{requested:?}"
    );
}

/// The real verifier refuses, because of what the code gave it as expected: the tag asked
/// for and the commit the signed tag names. With the right ones, the same check passes.
#[tokio::test]
async fn a_bundle_for_another_tag_or_commit_is_refused() {
    let passes = Release::good(REAL_TAG, REAL_COMMIT);
    let verified = run(&passes, REAL_TAG, &signer_key(), real_identity_check()).await;
    assert!(verified.is_ok(), "{verified:?}");

    let another_tag = Release::good(TAG, REAL_COMMIT);
    let error = run(&another_tag, TAG, &signer_key(), real_identity_check())
        .await
        .unwrap_err();
    assert!(
        matches!(
            &error,
            FileError::Attestation(AttestationError::Identity {
                field: "source_repository_ref",
                ..
            })
        ),
        "{error:?}"
    );
    assert!(error.is_refusal());

    let another_commit = Release::good(REAL_TAG, &"1".repeat(40));
    let error = run(
        &another_commit,
        REAL_TAG,
        &signer_key(),
        real_identity_check(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            &error,
            FileError::Attestation(AttestationError::Identity {
                field: "source_repository_digest",
                ..
            })
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_second_attempts_run_is_refused() {
    let release = Release::good(TAG, REAL_COMMIT);
    for run_url in [
        "https://github.com/nektos/act/actions/runs/1/attempts/2",
        "https://github.com/nektos/act/actions/runs/1/attempts/11",
        "https://github.com/nektos/act/actions/runs/1",
    ] {
        let url = run_url.to_owned();
        let error = run(&release, TAG, &signer_key(), move |_, _, _| {
            Ok(attestation(&url))
        })
        .await
        .unwrap_err();
        assert!(
            matches!(&error, FileError::NotFirstAttempt { run_url: found } if found == run_url),
            "{error:?}"
        );
        assert!(error.is_refusal());
    }
}

/// [`verify_release_file`] itself, with no fake: made-up files aren't what the real
/// bundle attests, and a bundle that doesn't parse says nothing.
#[tokio::test]
async fn the_real_verifier_is_what_verify_release_file_calls() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    let mut release = Release::good(REAL_TAG, REAL_COMMIT);
    release.assets[2] = (BUNDLE, REAL_BUNDLE.len(), REAL_BUNDLE.to_vec());
    release.serve(&github, REAL_TAG).await;
    let repo = repo();
    let key = signer_key();
    let signers = [(principal(), &key)];
    let identity = ReleaseIdentity {
        repo: &repo,
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        workflow: WORKFLOW,
        signers: &signers,
    };
    let result = verify_release_file(
        &fetcher(&github, &registry),
        &root(),
        &identity,
        &tag(REAL_TAG),
        &names(),
    )
    .await;
    let error = result.unwrap_err();
    let FileError::Attestation(AttestationError::FileSubject { name, .. }) = &error else {
        panic!("{error:?}");
    };
    assert_eq!(name, FILE);
    assert!(error.is_refusal());

    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    Release::good(REAL_TAG, REAL_COMMIT)
        .serve(&github, REAL_TAG)
        .await;
    let error = verify_release_file(
        &fetcher(&github, &registry),
        &root(),
        &identity,
        &tag(REAL_TAG),
        &names(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, FileError::Attestation(AttestationError::Bundle(_))),
        "{error:?}"
    );
    assert!(!error.is_refusal(), "junk says nothing of the release");
}

#[tokio::test]
async fn network_failure_is_not_a_refusal() {
    let release = Release::good(TAG, REAL_COMMIT);

    // Nothing is listening: the tag can't be read.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let repo = repo();
    let key = signer_key();
    let signers = [(principal(), &key)];
    let identity = ReleaseIdentity {
        repo: &repo,
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        workflow: WORKFLOW,
        signers: &signers,
    };
    let unreachable = crate::test_support::fetcher_for(&base, &base);
    let error = check_release_file(&unreachable, &identity, &tag(TAG), &names(), accepts())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, FileError::Tag(ReleaseError::TagObject(_))),
        "{error:?}"
    );
    assert!(!error.is_refusal());

    // The tag is fine, and the list of files answers 500.
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    mount_signed_tag(&github, REPO, TAG, release.tag_object.as_ref().unwrap()).await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/{REPO}/releases/tags/{TAG}")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&github)
        .await;
    let error = check_release_file(
        &fetcher(&github, &registry),
        &identity,
        &tag(TAG),
        &names(),
        accepts(),
    )
    .await
    .unwrap_err();
    assert!(matches!(&error, FileError::Assets(_)), "{error:?}");
    assert!(!error.is_refusal());

    // The list answers, and the file answers 500.
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .and(path(format!("/repos/{REPO}/releases/assets/0")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&github)
        .await;
    release.serve(&github, TAG).await;
    let error = check_release_file(
        &fetcher(&github, &registry),
        &identity,
        &tag(TAG),
        &names(),
        accepts(),
    )
    .await
    .unwrap_err();
    assert!(matches!(&error, FileError::Download { .. }), "{error:?}");
    assert!(!error.is_refusal());
}

#[test]
fn a_clock_behind_the_log_is_not_a_refusal_and_a_bad_signature_is() {
    let attested = |error| FileError::Attestation(error);
    assert!(!attested(AttestationError::ClockBehind("late".to_owned())).is_refusal());
    assert!(attested(AttestationError::Signature("no".to_owned())).is_refusal());
    assert!(attested(AttestationError::NoFileSubjects).is_refusal());
    assert!(!FileError::Interrupted.is_refusal());
}

#[test]
fn a_verified_files_debug_leaves_out_its_bytes() {
    let verified = VerifiedFile {
        name: FILE.to_owned(),
        bytes: b"do-not-print".to_vec(),
        digest: digest(FILE_BYTES),
        commit: commit(REAL_COMMIT),
        tag: landfall_core::tag::SignedTag {
            tag: tag(TAG),
            commit: commit(REAL_COMMIT),
            signer: principal(),
            fingerprint: "SHA256:x".to_owned(),
        },
        attestation: attestation(FIRST_RUN),
    };
    let shown = format!("{verified:?}");
    assert!(shown.contains(FILE), "{shown}");
    // 12 bytes, as a number, and neither their text nor their values.
    assert!(shown.contains("bytes: 12"), "{shown}");
    assert!(!shown.contains("do-not-print"), "{shown}");
    assert!(!shown.contains("100, 111"), "{shown}");
}
