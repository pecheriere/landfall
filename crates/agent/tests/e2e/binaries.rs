//! `landfall-server serve` and `landfall-agent run` as they are, and what they do
//! with no network: a controller with no trust root verifies nothing and says so.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

use crate::harness::{AGENT_BINARY, Fleet, HOST};

/// The stamp of a trust root just refreshed, so that the controller doesn't try the
/// network. The cache is empty, so it doesn't verify: nothing is, and every
/// deployment is held with that reason.
fn no_refresh_due(fleet: &Fleet) -> std::path::PathBuf {
    let cache = fleet.state_dir.with_file_name("trust");
    fs::create_dir(&cache).unwrap();
    fs::write(cache.join("landfall-refreshed"), "").unwrap();
    cache
}

#[tokio::test]
async fn the_real_commands_enrol_run_and_stop_on_a_signal() {
    let fleet = Fleet::new();
    let cache = no_refresh_due(&fleet);
    let mut controller = fleet
        .real_controller(&["--trust-cache", cache.to_str().unwrap()])
        .await;

    // Fail closed, and say so.
    fleet
        .wait_until("the watcher holding what it can't verify", async || {
            fleet.audit().await.iter().any(|row| {
                row.kind == "release_held"
                    && row.detail.to_string().contains("trust root is unavailable")
            })
        })
        .await;

    // And it says so where an operator is looking.
    assert!(
        fleet
            .log("controller")
            .contains("hold: app/prod everything:"),
        "{}",
        fleet.log("controller")
    );

    // A plain http URL is refused unless asked for, and nothing is sent.
    let code = fleet.enrol_code();
    let refused = Command::new(AGENT_BINARY)
        .args(["enrol", "--host", HOST, "--controller", &fleet.url()])
        .arg("--code-file")
        .arg(&code)
        .arg("--state-dir")
        .arg(&fleet.state_dir)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(!fleet.state_dir.join("agent.key").exists());

    // The code from `enrol-code` works once, for the key `enrol` made and kept.
    assert_eq!(fleet.run_enrol(&code), 0);
    let key_path = fleet.state_dir.join("agent.key");
    let key = fs::read(&key_path).unwrap();
    let mode = fs::metadata(&key_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(fleet.run_enrol(&code), 2, "the code is used up");
    assert_eq!(fs::read(&key_path).unwrap(), key);
    let rows = fleet.audit().await;
    assert!(rows.iter().any(|row| row.kind == "host_enrolled"));
    let printed = serde_json::to_string(&rows.iter().map(|r| &r.detail).collect::<Vec<_>>());
    let printed = printed.unwrap();
    assert!(!printed.contains(fs::read_to_string(&code).unwrap().trim()));
    fs::remove_file(code).unwrap();

    let mut agent = fleet.real_agent(None);
    if cfg!(target_os = "linux") {
        // Its first poll reaches the controller, signed and on its own key.
        fleet
            .wait_until("the agent's first poll", async || {
                fleet.running_tag().await.is_some()
            })
            .await;
        // Another `run` is refused while this one has the state directory.
        let second = fleet.real_agent(None).exit_status().await;
        assert_eq!(second, 2);
        assert!(fleet.log("agent").contains("agent_command_failed"));
        agent.stop().await;
        assert!(fleet.log("agent").contains("agent_stopping"));
    } else {
        // Releases have no image for another system, so it doesn't start there.
        assert_eq!(agent.exit_status().await, 2);
        assert!(fleet.log("agent").contains("no image platform"));
    }

    controller.stop().await;
    let verified = fleet.audit_verify(None);
    assert_eq!(verified.status, 0, "{:?}", verified.printed);
    let kept = verified.printed["head_seq"].as_i64().unwrap();
    assert_eq!(fleet.audit_verify(Some(kept)).printed["at_seq"], kept);

    // It starts again on the same database and stops again.
    let mut again = fleet
        .real_controller(&["--trust-cache", cache.to_str().unwrap()])
        .await;
    again.stop().await;
    assert_eq!(fleet.audit_verify(None).status, 0);
}

/// `enrol` with no CA certificates on the system, as on a slim image: an empty file
/// is all the certificates it can find. Linux reads them when the client is built; on
/// other systems the first `https` request would, so this can only fail there.
fn enrol_without_ca_certificates(fleet: &Fleet, controller: &str, code: &std::path::Path) -> i32 {
    let empty = fleet.state_dir.with_file_name("no-certificates.pem");
    fs::write(&empty, "").unwrap();
    let output = Command::new(AGENT_BINARY)
        .args(["enrol", "--allow-insecure-controller", "--host", HOST])
        .args(["--controller", controller])
        .arg("--code-file")
        .arg(code)
        .arg("--state-dir")
        .arg(&fleet.state_dir)
        .env("SSL_CERT_FILE", &empty)
        .env_remove("SSL_CERT_DIR")
        .output()
        .unwrap();
    output.status.code().unwrap_or(-1)
}

#[tokio::test]
async fn enrolling_without_ca_certificates_leaves_no_key_and_needs_none_over_loopback() {
    let fleet = Fleet::new();
    let cache = no_refresh_due(&fleet);
    let mut controller = fleet
        .real_controller(&["--trust-cache", cache.to_str().unwrap()])
        .await;
    let code = fleet.enrol_code();

    if cfg!(target_os = "linux") {
        // Port 1: this fails however far it gets, and must fail before any key.
        assert_eq!(
            enrol_without_ca_certificates(&fleet, "https://127.0.0.1:1", &code),
            2
        );
        assert!(!fleet.state_dir.join("agent.key").exists());
    }

    assert_eq!(
        enrol_without_ca_certificates(&fleet, &fleet.url(), &code),
        0
    );
    assert!(fleet.state_dir.join("agent.key").exists());
    controller.stop().await;
}

/// A controller that can't serve exits 2: its port is in use, here.
#[tokio::test]
async fn a_controller_that_cannot_serve_exits_two() {
    let fleet = Fleet::new();
    let cache = no_refresh_due(&fleet);
    let trust = ["--trust-cache", cache.to_str().unwrap()];
    let mut controller = fleet.real_controller(&trust).await;
    assert_eq!(fleet.serve_to_its_end(&trust), 2);
    assert!(controller.running());
    controller.stop().await;
}
