//! The JSON shapes, pinned.

use serde_json::{Value, json};

use super::super::{
    DeployId, DeployReportBody, DeployWork, DeployedRelease, EnrolCode, EnrolRequest, HeldBack,
    NonceResponse, Phase, Problem, ReportedCheck, ReportedDetail, ReportedOutcome, ReportedStep,
    RunningState, WorkRequest, WorkResponse,
};
use super::{host, key, nonce};
use crate::hex;

pub(super) fn code() -> EnrolCode {
    EnrolCode::from_bytes([0x5e; 32])
}

#[test]
fn debug_of_secrets_is_redacted() {
    let req = EnrolRequest {
        code: code(),
        host: host("host-1"),
        public_key: key(1).verifying_key(),
    };
    for text in [format!("{:?}", code()), format!("{req:?}")] {
        assert!(!text.contains("5e5e") && !text.contains("94, 94"), "{text}");
    }
    // The signing key's own Debug must not print the seed either.
    let seed_hex = hex::encode(&[0x42; 32]);
    let dbg = format!("{:?}", key(0x42));
    assert!(!dbg.contains(&seed_hex) && !dbg.contains("66, 66"), "{dbg}");
}

fn running_state() -> RunningState {
    RunningState {
        deployment: "app/prod".parse().unwrap(),
        deployed: Some(DeployedRelease {
            tag: "v1.2.4".parse().unwrap(),
            digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
        }),
        drift: false,
        phase: Phase::Idle,
        busy: false,
    }
}

pub(super) fn work_request() -> WorkRequest {
    WorkRequest {
        config_hash: [5; 32],
        running: vec![running_state()],
    }
}

pub(super) fn work_response() -> WorkResponse {
    WorkResponse {
        work: Some(DeployWork {
            deploy_id: DeployId(7),
            deployment: "app/prod".parse().unwrap(),
            tag: "v1.2.5".parse().unwrap(),
            digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            commit: "a".repeat(40).parse().unwrap(),
        }),
        held_back: vec![HeldBack {
            deployment: "app/stage".parse().unwrap(),
            reason: "config hash differs".to_owned(),
        }],
    }
}

pub(super) fn step(failure: Option<&str>, detail: Option<ReportedDetail>) -> ReportedStep {
    ReportedStep {
        name: "checks".to_owned(),
        millis: 9000,
        failure: failure.map(str::to_owned),
        detail,
    }
}

pub(super) fn report() -> DeployReportBody {
    DeployReportBody {
        deploy_id: DeployId(7),
        deployment: "app/prod".parse().unwrap(),
        tag: "v1.2.5".parse().unwrap(),
        digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
        outcome: ReportedOutcome::RolledBack {
            reason: "health check failed".to_owned(),
        },
        steps: vec![
            step(
                None,
                Some(ReportedDetail::Backup {
                    files: 3,
                    directories: 2,
                    symlinks: 1,
                    bytes: 4096,
                }),
            ),
            step(
                Some("unhealthy"),
                Some(ReportedDetail::Checks {
                    checks: vec![ReportedCheck {
                        check: "http 200".to_owned(),
                        attempts: 3,
                        millis: 1500,
                    }],
                }),
            ),
        ],
    }
}

pub(super) fn enrol() -> EnrolRequest {
    EnrolRequest {
        code: code(),
        host: host("host-1"),
        public_key: key(1).verifying_key(),
    }
}

pub(super) fn all_outcomes() -> Vec<(ReportedOutcome, Value)> {
    let r = || "why".to_owned();
    vec![
        (ReportedOutcome::Deployed {}, json!({"kind": "deployed"})),
        (
            ReportedOutcome::RolledBack { reason: r() },
            json!({"kind": "rolled_back", "reason": "why"}),
        ),
        (
            ReportedOutcome::NothingChanged { reason: r() },
            json!({"kind": "nothing_changed", "reason": "why"}),
        ),
        (
            ReportedOutcome::FailedNoPrevious { reason: r() },
            json!({"kind": "failed_no_previous", "reason": "why"}),
        ),
        (
            ReportedOutcome::RollbackFailed {
                reason: r(),
                rollback_reason: "again".to_owned(),
            },
            json!({"kind": "rollback_failed", "reason": "why", "rollback_reason": "again"}),
        ),
        (
            ReportedOutcome::Refused { reason: r() },
            json!({"kind": "refused", "reason": "why"}),
        ),
        (
            ReportedOutcome::Deferred { reason: r() },
            json!({"kind": "deferred", "reason": "why"}),
        ),
    ]
}

#[test]
fn round_trips_through_json() {
    fn check<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).unwrap();
        assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), value, "{json}");
    }
    check(&work_request());
    check(&work_response());
    check(&WorkResponse {
        work: None,
        held_back: Vec::new(),
    });
    check(&report());
    for (outcome, _) in all_outcomes() {
        check(&outcome);
    }
    check(&step(None, None));
    check(&NonceResponse { nonce: nonce(1) });
    check(&Problem {
        code: "bad_nonce".to_owned(),
        title: "the nonce is unknown, used or expired".to_owned(),
        status: 401,
    });

    // EnrolRequest has no equality (its code is a secret): compare the
    // wire form after a round trip.
    let wire = serde_json::to_value(enrol()).unwrap();
    let back: EnrolRequest = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(back).unwrap(), wire);
    assert_eq!(wire["code"], "5e".repeat(32));
    assert_eq!(
        wire["public_key"],
        hex::encode(key(1).verifying_key().as_bytes())
    );

    let json = serde_json::to_value(work_request()).unwrap();
    assert_eq!(json["config_hash"], "05".repeat(32));
}

#[test]
fn wire_strings_are_pinned() {
    for (outcome, want) in all_outcomes() {
        assert_eq!(serde_json::to_value(&outcome).unwrap(), want);
    }
    for (phase, want) in [
        (Phase::Idle, "idle"),
        (Phase::Preflight, "preflight"),
        (Phase::Deploying, "deploying"),
        (Phase::RollingBack, "rolling_back"),
        (Phase::Restored, "restored"),
        (Phase::RolledBack, "rolled_back"),
    ] {
        assert_eq!(serde_json::to_value(phase).unwrap(), want);
    }
    let wire = serde_json::to_value(report()).unwrap();
    assert_eq!(wire["deploy_id"], 7);
    assert_eq!(wire["deployment"], "app/prod");
    assert_eq!(wire["tag"], "v1.2.5");
    assert_eq!(wire["digest"], format!("sha256:{}", "c".repeat(64)));
    for key in ["deployment", "tag", "digest"] {
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<DeployReportBody>(missing).is_err(),
            "{key} may not be left out"
        );
    }
    let checks = ReportedDetail::Checks { checks: Vec::new() };
    assert_eq!(
        serde_json::to_value(checks).unwrap(),
        json!({"kind": "checks", "checks": []})
    );
    assert_eq!(
        serde_json::to_value(step(None, None)).unwrap(),
        json!({"name": "checks", "millis": 9000, "failure": null})
    );
}

#[test]
fn a_blocked_first_deploy_differs_from_never_deployed() {
    let never = RunningState {
        deployed: None,
        ..running_state()
    };
    let blocked = RunningState {
        deployed: None,
        phase: Phase::Preflight,
        busy: false,
        ..running_state()
    };
    assert_ne!(never, blocked);
    for state in [&never, &blocked] {
        let wire = serde_json::to_value(state).unwrap();
        assert!(wire["deployed"].is_null());
        assert_eq!(
            &serde_json::from_value::<RunningState>(wire).unwrap(),
            state
        );
    }
    // The key may not be omitted.
    let mut wire = serde_json::to_value(&blocked).unwrap();
    wire.as_object_mut().unwrap().remove("deployed");
    assert!(serde_json::from_value::<RunningState>(wire).is_err());
}
