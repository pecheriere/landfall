//! The real binaries on a real release: what no other test can reach, as the source
//! and the verifier they use need the network and a release that really is signed.
//! `#[ignore]`d and run nightly with the other `live_` tests. `GITHUB_TOKEN` is used
//! if set: it takes more requests than the anonymous limit is sure to leave.
//!
//! The fixture project's container isn't worth pulling here, so its `docker` is a
//! stub: nothing runs, and `compose config` fails. A deploy that ends as
//! `nothing_changed` for that reason is one that the controller's real watcher
//! queued, and the agent verified for itself over the network.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;
use std::time::Duration;

use jiff::Timestamp;
use landfall_agent::compose::{OVERRIDE_FILE, image_ref, render_override};
use landfall_agent::state::Deployed;
use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, RepoName};

use crate::harness::{DEPLOYMENT, Fleet, FleetOptions};

const STUB: &str = "#!/bin/sh\nif [ \"$1\" = ps ]; then exit 0; fi\nexit 1\n";

/// A stub `docker` in a directory of its own, for the first place on a `PATH`. See
/// the stubs in `src/docker/tests.rs` for why `cp` makes it.
fn stub_docker(dir: &std::path::Path) -> std::path::PathBuf {
    let bin = dir.join("bin");
    fs::create_dir(&bin).unwrap();
    let script = dir.join("docker-script");
    fs::write(&script, STUB).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let copied = Command::new("cp")
        .arg(&script)
        .arg(bin.join("docker"))
        .status()
        .unwrap();
    assert!(copied.success());
    bin
}

/// The fixture project at a version with a higher patch after it, as if an operator
/// had deployed that: what the agent has on record, and an override that agrees.
fn seed_record(fleet: &Fleet, repo: &str) {
    let tag: ReleaseTag = "1.37.3".parse().unwrap();
    let digest: ImageDigest = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
    let commit: CommitSha = "a".repeat(40).parse().unwrap();
    let repo: RepoName = repo.parse().unwrap();
    let text = render_override(
        "app",
        &image_ref(&repo, &digest),
        &DEPLOYMENT.parse().unwrap(),
        &tag,
        &commit,
    );
    fs::write(fleet.compose.join(OVERRIDE_FILE), text).unwrap();
    fleet
        .deployment_state()
        .set_deployed(&Deployed {
            deploy_id: "seeded".to_owned(),
            version: semver::Version::new(1, 37, 3),
            tag,
            digest,
            commit,
            deployed_at: Timestamp::now(),
        })
        .unwrap();
}

#[tokio::test]
#[ignore = "network: GitHub, GHCR and the Sigstore TUF repository"]
async fn live_the_real_binaries_verify_a_real_release_both_ends() {
    const REPO: &str = "dani-garcia/vaultwarden";
    if !cfg!(target_os = "linux") {
        // Releases have no image for another system, so the agent doesn't start.
        return;
    }
    let fleet = Fleet::with(FleetOptions {
        repo: REPO.to_owned(),
        repo_ids: (121_898_717, 725_423),
        origin: "origin = { workflow = \".github/workflows/release.yml\", tags = \"*\", signed_tags = false }"
            .to_owned(),
        checks: "checks = [\"container-healthy\"]".to_owned(),
        compose: None,
    });
    let stubs = tempfile::tempdir().unwrap();
    let bin = stub_docker(stubs.path());
    seed_record(&fleet, REPO);

    let mut controller = fleet.real_controller(&[]).await;
    fleet.enrol();
    let mut agent = fleet.real_agent(Some(&bin));
    fleet.wait_running("1.37.3").await;
    // Its first look found no host's word yet, and the next is minutes away: a
    // controller started now looks at once.
    controller.stop().await;
    let mut controller = fleet.real_controller(&[]).await;

    let what = "the real release through both ends";
    fleet
        .wait_for(Duration::from_mins(10), what, async || {
            fleet
                .deploys()
                .await
                .iter()
                .any(|deploy| deploy.state == "finished")
        })
        .await;
    let deploy = fleet.deploys().await.remove(0);
    assert!(deploy.tag.starts_with("1.37."), "{deploy:?}");
    assert_eq!(
        deploy.outcome.as_deref(),
        Some("nothing_changed"),
        "{deploy:?}\n{}",
        fleet.log("agent")
    );
    let rows = fleet.audit().await;
    let finished = rows
        .iter()
        .find(|row| row.kind == "deploy_finished")
        .unwrap();
    assert!(
        finished.detail["reason"]
            .as_str()
            .unwrap()
            .contains("docker")
    );
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
