//! The names of a release's files, and which release to ask for.

use std::io::Write as _;

use landfall_core::ids::{ReleaseTag, TagPattern};
use landfall_origin::fetch::{Endpoints, FetchError, Fetcher};
use landfall_origin::trust::Refresh;
use semver::Version;

use super::{
    AgentReleaseError, AgentSource, Arch, GitHubReleases, SUMS_ASSET, VerifiedAgent, agent_asset,
    bundle_asset, default_tag, release_version, sha256_hex,
};
use crate::project::{self, ProjectError};

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

#[test]
fn ready_says_what_the_embedded_keys_say() {
    let source = GitHubReleases::new(None, Refresh::Offline);
    match (project::signers(), source.ready()) {
        (Ok(_), Ok(()))
        | (
            Err(ProjectError::NoSigners),
            Err(AgentReleaseError::Project(ProjectError::NoSigners)),
        ) => {}
        (keys, ready) => panic!("{keys:?} and {ready:?}"),
    }
}

/// What a release of ours says, once there is one, end to end against the real GitHub and
/// Sigstore: this passes with nothing to do until then.
#[tokio::test]
#[ignore = "needs the network"]
async fn live_agent_release_verifies() {
    if project::signers().is_err() {
        say("this build has no release-signing key, so there is nothing to verify");
        return;
    }
    let mut fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        fetcher = fetcher.with_github_token(&token).unwrap();
    }
    let repo = project::REPO.parse().unwrap();
    let tags = fetcher.list_release_tags(&repo).await.unwrap();
    let pattern: TagPattern = "v*".parse().unwrap();
    let Some((_, newest)) = tags
        .iter()
        .filter_map(|listed| Some((pattern.parse_tag(&listed.tag).ok()?, &listed.tag)))
        .max_by(|(one, _), (other, _)| one.cmp(other))
    else {
        say("this repository has no release tag yet");
        return;
    };
    match fetcher.release_assets(&repo, newest).await {
        Err(FetchError::NotFound { .. }) => {
            say("the newest tag has no release yet");
            return;
        }
        other => {
            other.unwrap();
        }
    }

    let cache = tempfile::tempdir().unwrap();
    let source = GitHubReleases::new(Some(cache.path().to_owned()), Refresh::Online);
    for arch in [Arch::Arm64, Arch::Amd64] {
        let agent = source.agent(newest, arch).await.unwrap();
        assert_eq!(agent.tag(), newest);
        assert_eq!(agent.arch(), arch);
        assert_eq!(agent.sha256(), sha256_hex(agent.bytes()));
    }
}

fn say(line: &str) {
    writeln!(std::io::stderr(), "live_agent_release_verifies: {line}").unwrap();
}
