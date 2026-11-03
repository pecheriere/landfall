//! The names of a release's files, and which release to ask for.

use std::io::Write as _;

use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, TagPattern};
use landfall_core::tag::SignedTag;
use landfall_origin::artifact::{FileError, VerifiedFile};
use landfall_origin::attestation::VerifiedAttestation;
use landfall_origin::fetch::{Endpoints, FetchError, Fetcher};
use landfall_origin::trust::Refresh;
use semver::Version;
use serde_json::Value;

use super::{
    AgentReleaseError, AgentSource, Arch, GitHubReleases, SUMS_ASSET, VerifiedAgent, agent_asset,
    agent_verified_by, bundle_asset, default_tag, from_verified, release_version, sha256_hex,
};
use crate::project;

/// A digest for a file that isn't hashed here, in hex.
const DIGEST_HEX: &str = "abababababababababababababababababababababababababababababababab";

fn version(text: &str) -> Version {
    text.parse().unwrap()
}

fn tag(text: &str) -> ReleaseTag {
    text.parse().unwrap()
}

/// The table in the plan, `AGENTS.md`'s "Release assets" and `assemble_release.py`.
#[test]
fn asset_names_are_exactly_the_tables() {
    let v = version("1.2.3");
    assert_eq!(
        agent_asset(&v, Arch::Arm64),
        "landfall-agent-1.2.3-linux-arm64"
    );
    assert_eq!(
        agent_asset(&v, Arch::Amd64),
        "landfall-agent-1.2.3-linux-amd64"
    );
    assert_eq!(bundle_asset(&v), "landfall-1.2.3.sigstore.json");
    assert_eq!(SUMS_ASSET, "SHA256SUMS");

    let candidate = version("0.1.0-rc.1");
    assert_eq!(
        agent_asset(&candidate, Arch::Arm64),
        "landfall-agent-0.1.0-rc.1-linux-arm64"
    );
    assert_eq!(
        bundle_asset(&candidate),
        "landfall-0.1.0-rc.1.sigstore.json"
    );
}

#[test]
fn arch_from_uname() {
    assert_eq!(Arch::from_uname("aarch64"), Some(Arch::Arm64));
    assert_eq!(Arch::from_uname("arm64"), Some(Arch::Arm64));
    assert_eq!(Arch::from_uname("x86_64"), Some(Arch::Amd64));
    for machine in ["armv7l", "i686", "", "x86_64 ", "AARCH64", "riscv64"] {
        assert_eq!(Arch::from_uname(machine), None, "{machine:?}");
    }
}

#[test]
fn dev_version_needs_a_tag() {
    let error = default_tag("0.0.0", None).unwrap_err();
    assert!(matches!(error, AgentReleaseError::NeedsTag), "{error:?}");
    assert!(error.to_string().contains("--tag"), "{error}");
    assert!(!error.is_refusal());

    assert_eq!(
        default_tag("0.0.0", Some(tag("v1.2.3"))).unwrap(),
        tag("v1.2.3")
    );
    assert_eq!(default_tag("1.2.3", None).unwrap(), tag("v1.2.3"));
    assert_eq!(
        default_tag("1.2.3", Some(tag("v1.2.2"))).unwrap(),
        tag("v1.2.2"),
        "--tag wins"
    );
    assert_eq!(default_tag("0.1.0-rc.1", None).unwrap(), tag("v0.1.0-rc.1"));
}

#[test]
fn a_release_tag_is_v_and_a_version() {
    assert_eq!(release_version(&tag("v1.2.3")).unwrap(), version("1.2.3"));
    assert_eq!(
        release_version(&tag("v0.1.0-rc.1")).unwrap(),
        version("0.1.0-rc.1")
    );
    for refused in ["1.2.3", "v1.2", "release-1.2.3", "v1.2.3+build"] {
        assert!(
            matches!(
                release_version(&tag(refused)),
                Err(AgentReleaseError::Version(_))
            ),
            "{refused}"
        );
    }
}

#[test]
fn a_new_agent_has_the_hash_of_its_bytes_and_its_debug_leaves_them_out() {
    let agent = VerifiedAgent::new(
        tag("v1.2.3"),
        version("1.2.3"),
        Arch::Arm64,
        b"do-not-print".to_vec(),
        "a fake".to_owned(),
    );
    // From `shasum -a 256`.
    assert_eq!(
        agent.sha256(),
        "82124aa1f8591e9329715e4004d8791dd0923e97c874c2c46a94c1deea2d12b5"
    );
    assert_eq!(agent.bytes(), b"do-not-print");
    assert_eq!(agent.tag(), &tag("v1.2.3"));
    assert_eq!(agent.version(), &version("1.2.3"));
    assert_eq!(agent.arch(), Arch::Arm64);
    assert_eq!(agent.summary(), "a fake");
    let shown = format!("{agent:?}");
    assert!(shown.contains("bytes: 12"), "{shown}");
    assert!(!shown.contains("do-not-print"), "{shown}");
}

fn verified_file(bytes: &[u8]) -> VerifiedFile {
    let commit: CommitSha = "1".repeat(40).parse().unwrap();
    let digest: ImageDigest = format!("sha256:{DIGEST_HEX}").parse().unwrap();
    VerifiedFile {
        name: "landfall-agent-1.2.3-linux-amd64".to_owned(),
        bytes: bytes.to_vec(),
        digest: digest.clone(),
        commit: commit.clone(),
        tag: SignedTag {
            tag: tag("v1.2.3"),
            commit: commit.clone(),
            signer: "release-1".parse().unwrap(),
            fingerprint: "SHA256:the-fingerprint".to_owned(),
        },
        attestation: VerifiedAttestation {
            digest,
            san: "the san".to_owned(),
            commit,
            git_ref: "refs/tags/v1.2.3".to_owned(),
            repo_id: project::REPO_ID,
            owner_id: project::OWNER_ID,
            run_url: "https://example.invalid/runs/1/attempts/1".to_owned(),
            rekor_log_index: 1,
            integrated_time: 2,
        },
    }
}

/// `sha256` goes into a script root runs and a comparison with a host's file, so it is bare
/// hex, and is the digest that was verified.
#[test]
fn a_verified_file_becomes_an_agent_with_what_was_verified() {
    for arch in [Arch::Arm64, Arch::Amd64] {
        let agent = from_verified(
            verified_file(b"the agent"),
            tag("v1.2.3"),
            version("1.2.3"),
            arch,
        );
        assert_eq!(agent.sha256(), DIGEST_HEX);
        assert_eq!(agent.arch(), arch);
        assert_eq!(agent.bytes(), b"the agent");
        assert_eq!(agent.tag(), &tag("v1.2.3"));
        assert_eq!(agent.version(), &version("1.2.3"));
        for part in [
            "v1.2.3",
            "SHA256:the-fingerprint",
            &"1".repeat(40),
            "https://example.invalid/runs/1/attempts/1",
        ] {
            assert!(agent.summary().contains(part), "{}", agent.summary());
        }
    }
}

/// The whole way through `agent`, but for the download and the signature checks: what root
/// is given for each architecture is what was asked for it, of this project's identity.
#[tokio::test]
async fn an_agent_is_asked_for_by_its_arch_tag_and_this_projects_identity() {
    for (arch, wanted) in [
        (Arch::Arm64, "landfall-agent-1.2.3-linux-arm64"),
        (Arch::Amd64, "landfall-agent-1.2.3-linux-amd64"),
    ] {
        let keys = project::signers().unwrap();
        let agent = agent_verified_by(&tag("v1.2.3"), arch, async |identity, names| {
            assert_eq!(names.file, wanted);
            assert_eq!(names.sums, "SHA256SUMS");
            assert_eq!(names.bundle, "landfall-1.2.3.sigstore.json");
            assert_eq!(identity.repo.as_ref() as &str, project::REPO);
            assert_eq!(identity.repo_id, project::REPO_ID);
            assert_eq!(identity.owner_id, project::OWNER_ID);
            assert_eq!(identity.workflow, project::WORKFLOW);
            assert_eq!(identity.signers.len(), keys.len());
            assert_ne!(identity.signers.len(), 0);
            Ok(verified_file(b"the agent"))
        })
        .await
        .unwrap();
        assert_eq!(agent.arch(), arch);
        assert_eq!(agent.tag(), &tag("v1.2.3"));
        assert_eq!(agent.version(), &version("1.2.3"));
        assert_eq!(agent.sha256(), DIGEST_HEX);
        assert_eq!(agent.bytes(), b"the agent");
    }
}

/// A tag that isn't a release's is refused before anything is asked of it, and what
/// verifying says comes back as it is.
#[tokio::test]
async fn an_agent_comes_of_nothing_else() {
    let error = agent_verified_by(&tag("1.2.3"), Arch::Amd64, async |_, _| {
        panic!("nothing should be asked for this tag")
    })
    .await
    .unwrap_err();
    assert!(matches!(error, AgentReleaseError::Version(_)), "{error:?}");

    let error = agent_verified_by(&tag("v1.2.3"), Arch::Amd64, async |_, _| {
        Err(AgentReleaseError::NeedsTag)
    })
    .await
    .unwrap_err();
    assert!(matches!(error, AgentReleaseError::NeedsTag), "{error:?}");
}

/// Task 7's exit status rests on this, and its message on what it says.
#[test]
fn a_file_error_says_whether_the_release_was_refused() {
    let file = |source| AgentReleaseError::File {
        tag: tag("v1.2.3"),
        source: Box::new(source),
    };
    let refused = file(FileError::NotInSums {
        name: "x".to_owned(),
    });
    assert!(refused.is_refusal());
    assert_eq!(
        refused.to_string(),
        "the agent of release v1.2.3 is refused"
    );
    let out_of_reach = file(FileError::Interrupted);
    assert!(!out_of_reach.is_refusal());
    assert_eq!(
        out_of_reach.to_string(),
        "the agent of release v1.2.3 could not be verified"
    );
}

#[test]
fn ready_says_what_the_embedded_keys_say() {
    GitHubReleases::new(None, Refresh::Offline).ready().unwrap();
}

/// Each release file's digest, as GitHub lists it, read apart from the code under test.
async fn github_digests(tag: &ReleaseTag) -> Value {
    let client = reqwest::Client::builder()
        .user_agent("landfall-test")
        .build()
        .unwrap();
    let mut request = client.get(format!(
        "https://api.github.com/repos/{}/releases/tags/{tag}",
        project::REPO
    ));
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        request = request.bearer_auth(token);
    }
    let body = request.send().await.unwrap().bytes().await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// The newest release of ours, end to end against the real GitHub and Sigstore. With no tag
/// or no release of any tag, this says so on stderr, and passes with nothing to do.
#[tokio::test]
#[ignore = "needs the network"]
async fn live_agent_release_verifies() {
    let mut fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        fetcher = fetcher.with_github_token(&token).unwrap();
    }
    let repo = project::REPO.parse().unwrap();
    let tags = fetcher.list_release_tags(&repo).await.unwrap();
    let pattern: TagPattern = "v*".parse().unwrap();
    let mut versions: Vec<(Version, &ReleaseTag)> = tags
        .iter()
        .filter_map(|listed| Some((pattern.parse_tag(&listed.tag).ok()?, &listed.tag)))
        .collect();
    versions.sort_by(|(one, _), (other, _)| other.cmp(one));
    if versions.is_empty() {
        say("this repository has no release tag yet");
        return;
    }
    // A tag can stand with no release, as a failed run leaves it, and hides no older one.
    let mut newest = None;
    for (version, tag) in versions {
        match fetcher.release_assets(&repo, tag).await {
            Err(FetchError::NotFound { .. }) => {}
            other => {
                other.unwrap();
                newest = Some((version, tag));
                break;
            }
        }
    }
    let Some((version, newest)) = newest else {
        say("no tag of this repository has a release yet");
        return;
    };

    let listed = github_digests(newest).await;
    let cache = tempfile::tempdir().unwrap();
    let source = GitHubReleases::new(Some(cache.path().to_owned()), Refresh::Online);
    for arch in [Arch::Arm64, Arch::Amd64] {
        let agent = source.agent(newest, arch).await.unwrap();
        assert_eq!(agent.tag(), newest);
        assert_eq!(agent.arch(), arch);
        assert_eq!(agent.sha256(), sha256_hex(agent.bytes()));
        let name = agent_asset(&version, arch);
        let digest = listed["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|asset| asset["name"] == name.as_str())
            .unwrap()["digest"]
            .as_str()
            .unwrap();
        assert_eq!(digest, format!("sha256:{}", agent.sha256()), "{name}");
    }
}

fn say(line: &str) {
    writeln!(std::io::stderr(), "live_agent_release_verifies: {line}").unwrap();
}
