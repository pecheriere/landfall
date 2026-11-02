//! Scenarios that need Linux: container-set owners and the host reaching a bridge network.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use landfall_agent::deploy::Outcome;

use super::harness::{
    BACKUP, DIGEST_A, DIGEST_B, PASSES, RunAs, Stack, assert_rolled_back, etc_fingerprint,
    failed_step, image, passes_only_on, script_with,
};

/// Whether this test can run: it needs root to see another user's files
/// through a backup. Where root is required, not having it is a failure.
#[expect(
    clippy::print_stderr,
    reason = "a test skipped for lack of privileges has to say so; libtest has no runtime skip"
)]
fn has_root(test: &str) -> bool {
    if rustix::process::geteuid().is_root() {
        return true;
    }
    assert!(
        std::env::var_os("LANDFALL_TEST_REQUIRE_ROOT").is_none(),
        "{test} must run as root here"
    );
    eprintln!("{test}: skipped, it needs root to see another user's files");
    false
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_foreign_owner_survives_backup_and_restore() {
    if !has_root("docker_foreign_owner_survives_backup_and_restore") {
        return;
    }
    let etc = etc_fingerprint();
    let stack = Stack::new(RunAs::Root, &script_with("chown 3000:3000 /data/db"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack
        .in_container(
            "echo before > /data/db && chown 1000:1001 /data/db && chmod 640 /data/db \
             && ln -s /etc /data/link && chown -h 1002:1003 /data/link \
             && mkdir /data/sub && chown 1004:1005 /data/sub && chmod 2750 /data/sub",
        )
        .await;

    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let (report, b_ran) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, stack.b_started())
        .await;

    assert_rolled_back(&report);
    assert!(b_ran, "version B never ran, so the restore proves nothing");
    for base in [stack.dir.join("data"), stack.newest_backup().join("data")] {
        for (name, uid, gid, mode) in [
            ("db", 1000, 1001, Some(0o640)),
            ("link", 1002, 1003, None),
            ("sub", 1004, 1005, Some(0o2750)),
        ] {
            let meta = fs::symlink_metadata(base.join(name)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (uid, gid), "{base:?}/{name}");
            if let Some(mode) = mode {
                assert_eq!(meta.mode() & 0o7777, mode, "{base:?}/{name}");
            }
        }
    }
    assert_eq!(
        fs::read_link(stack.data("link")).unwrap(),
        Path::new("/etc")
    );
    assert_eq!(etc_fingerprint(), etc, "/etc changed");
}

/// The host reaches the container's address on a bridge network, which a Mac's
/// Docker does not offer. Only version A serves the path.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_http_check_reaches_the_container_and_a_failed_one_rolls_back() {
    const SERVE: &str = "mkdir -p /tmp/www\n        case \"$$(busybox | head -n 1)\" in *v1.36*) echo ok > /tmp/www/health ;; esac\n        exec httpd -f -p 8080 -h /tmp/www";
    let stack = Stack::new(RunAs::Agent, SERVE);
    let check = format!(
        "checks = [{{ http = \"/health\", network = \"{}-net\", port = 8080, expect = 200 }}]\n",
        stack.project.name
    );

    let first = stack.deploy(&check, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_A));

    let second = stack.deploy(&check, "v2.0.0", DIGEST_B).await;
    assert_rolled_back(&second);
    assert!(failed_step(&second, "checks"), "{second:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_A));
}
