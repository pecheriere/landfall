//! Why a deploy ended as it did: `why::explain`, a pure function over the deploy and its
//! steps, for each outcome and for a deploy not yet finished.

use landfall_api::{DeployState, NextKind, Outcome, WhyKind};
use landfall_core::protocol::DeployReportBody;
use serde_json::json;

use crate::api::why::explain;
use crate::report::BoundedReport;
use crate::store::history::{DeployRow, StepRow};

const AT: i64 = 1_800_000_000;

/// A deploy of `v1.3.0` on `app/prod` to `home-1`, asked for by `ci` and signed by
/// `operator`, in `state` with `outcome`.
fn deploy(state: DeployState, outcome: Option<Outcome>) -> DeployRow {
    let begun = state != DeployState::Queued;
    let finished = state == DeployState::Finished;
    let (reason, rollback_reason) = match outcome {
        None | Some(Outcome::Deployed) => (None, None),
        Some(Outcome::RollbackFailed) => (
            Some("\"container unhealthy\"".to_owned()),
            Some("\"previous image gone\"".to_owned()),
        ),
        Some(Outcome::Refused) => (Some("\"digest not allowed here\"".to_owned()), None),
        Some(_) => (Some("\"container unhealthy\"".to_owned()), None),
    };
    DeployRow {
        id: 7,
        deployment: "app/prod".parse().unwrap(),
        host: "home-1".parse().unwrap(),
        tag: "v1.3.0".parse().unwrap(),
        digest: format!("sha256:{}", "3".repeat(64)).parse().unwrap(),
        commit: "3".repeat(40).parse().unwrap(),
        state,
        outcome,
        reason,
        rollback_reason,
        request_id: Some(4),
        requested_by: Some("ci".parse().unwrap()),
        requested_at: Some(AT - 100),
        approved_by: Some("operator".parse().unwrap()),
        created_at: AT - 50,
        claimed_at: begun.then_some(AT - 40),
        finished_at: finished.then_some(AT),
    }
}

fn step(position: u32, name: &str, failure: Option<&str>) -> StepRow {
    StepRow {
        position,
        name: format!("{name:?}"),
        millis: 100,
        failure: failure.map(|text| format!("{text:?}")),
        detail: (name == "checks").then(|| {
            json!({
                "kind": "checks",
                "checks": [{ "check": "\"container-healthy\"", "attempts": 3, "millis": 90 }],
            })
        }),
    }
}

const ASKED: [WhyKind; 4] = [
    WhyKind::Requested,
    WhyKind::Approved,
    WhyKind::Queued,
    WhyKind::Claimed,
];

/// A row of [`explain_table`]: the state, the outcome, the steps, the kinds of the events
/// after the host took it, and the next action's kind.
type Row = (
    DeployState,
    Option<Outcome>,
    Vec<StepRow>,
    Vec<WhyKind>,
    NextKind,
);

#[test]
fn explain_table() {
    use DeployState::{Claimed, Finished, Queued};
    use WhyKind::{
        Deferred, Finished as Ended, HostRefused, RollbackFailed, RolledBack, Step, StepFailed,
    };
    let ok = |position, name| step(position, name, None);
    let failed = |position, name| step(position, name, Some("container unhealthy"));
    let rows: Vec<Row> = vec![
        (
            Finished,
            Some(Outcome::Deployed),
            vec![ok(0, "pull"), ok(1, "checks")],
            vec![Step, Step, Ended],
            NextKind::None,
        ),
        (
            Finished,
            Some(Outcome::RolledBack),
            vec![ok(0, "pull"), failed(1, "checks"), ok(2, "rollback")],
            vec![Step, StepFailed, Step, RolledBack],
            NextKind::Request,
        ),
        (
            Finished,
            Some(Outcome::NothingChanged),
            vec![failed(0, "preflight")],
            vec![StepFailed, Ended],
            NextKind::Wait,
        ),
        (
            Finished,
            Some(Outcome::FailedNoPrevious),
            vec![ok(0, "pull"), failed(1, "checks")],
            vec![Step, StepFailed, Ended],
            NextKind::Request,
        ),
        (
            Finished,
            Some(Outcome::RollbackFailed),
            vec![failed(0, "checks"), failed(1, "rollback")],
            vec![StepFailed, StepFailed, RollbackFailed],
            NextKind::Recover,
        ),
        (
            Finished,
            Some(Outcome::Refused),
            vec![],
            vec![HostRefused],
            NextKind::FixHost,
        ),
        (
            Finished,
            Some(Outcome::Deferred),
            vec![],
            vec![Deferred],
            NextKind::Wait,
        ),
        (Queued, None, vec![], vec![], NextKind::Wait),
        (Claimed, None, vec![], vec![], NextKind::Wait),
    ];
    for (state, outcome, steps, after, next) in rows {
        let row = deploy(state, outcome);
        let why = explain(&row, &steps);
        let label = format!("{state:?} {outcome:?}");
        assert_eq!(why.deploy, 7, "{label}");
        assert_eq!(why.outcome, outcome, "{label}");
        assert!(why.summary.contains("v1.3.0"), "{label}: {}", why.summary);
        assert!(why.summary.contains("home-1"), "{label}: {}", why.summary);
        let mut kinds: Vec<WhyKind> = ASKED.to_vec();
        if state == Queued {
            kinds.pop();
        }
        kinds.extend(after);
        let got: Vec<WhyKind> = why.events.iter().map(|event| event.what).collect();
        assert_eq!(got, kinds, "{label}");
        let times: Vec<i64> = why.events.iter().filter_map(|event| event.at).collect();
        assert!(times.is_sorted(), "{label}: {times:?}");
        assert_eq!(
            why.next.as_ref().map(|next| next.kind),
            Some(next),
            "{label}"
        );
    }
}

#[test]
fn next_says_what_to_run_and_where() {
    let recover = explain(
        &deploy(DeployState::Finished, Some(Outcome::RollbackFailed)),
        &[],
    );
    let detail = recover.next.unwrap().detail;
    assert!(detail.contains("landfall-agent recover"), "{detail}");
    assert!(detail.contains("home-1"), "{detail}");
    assert!(
        recover.summary.contains("rolling back"),
        "{}",
        recover.summary
    );

    let refused = explain(&deploy(DeployState::Finished, Some(Outcome::Refused)), &[]);
    let detail = refused.next.unwrap().detail;
    assert!(detail.contains("\"digest not allowed here\""), "{detail}");
    assert!(detail.contains("alert"), "{detail}");

    let rolled_back = deploy(DeployState::Finished, Some(Outcome::RolledBack));
    let steps = [step(0, "checks", Some("container unhealthy"))];
    let why = explain(&rolled_back, &steps);
    assert_eq!(
        why.summary,
        "v1.3.0 failed on home-1 at step \"checks\" and rolled back to the previous version; \
         it won't be retried automatically"
    );
    let detail = why.next.unwrap().detail;
    assert!(detail.contains("newer release"), "{detail}");
    assert!(detail.contains("approv"), "{detail}");
}

#[test]
fn a_step_failure_is_quoted_not_raw() {
    // What a hostile host sends: raw line breaks, an escape sequence and a bidi override.
    let hostile = "line one\nline two\r \u{1b}[31mred \u{202e}desrever";
    let report: DeployReportBody = serde_json::from_value(json!({
        "deploy_id": 7,
        "deployment": "app/prod",
        "tag": "v1.3.0",
        "digest": format!("sha256:{}", "3".repeat(64)),
        "outcome": { "kind": "rolled_back", "reason": hostile },
        "steps": [{ "name": hostile, "millis": 100, "failure": hostile }],
    }))
    .unwrap();
    // As the controller stores it.
    let bounded = BoundedReport::new(&report);
    let stored = &bounded.steps[0];
    let failing = StepRow {
        position: 0,
        name: stored.name.clone(),
        millis: stored.millis,
        failure: stored.failure.clone(),
        detail: None,
    };
    let mut row = deploy(DeployState::Finished, Some(Outcome::RolledBack));
    row.reason.clone_from(&bounded.reason);
    let why = explain(&row, &[failing]);
    let event = why
        .events
        .iter()
        .find(|event| event.what == WhyKind::StepFailed)
        .unwrap();
    let failure = stored.failure.as_deref().unwrap();
    assert!(event.text.contains(failure), "{}", event.text);
    let next = why.next.as_ref().unwrap();
    let shown = why
        .events
        .iter()
        .map(|event| &event.text)
        .chain([&why.summary, &next.detail]);
    for text in shown {
        for raw in ['\n', '\r', '\u{1b}', '\u{202e}'] {
            assert!(!text.contains(raw), "{raw:?} in {text}");
        }
    }
}

#[test]
fn approver_and_requester_are_named() {
    let why = explain(&deploy(DeployState::Finished, Some(Outcome::Deployed)), &[]);
    let requested = &why.events[0];
    assert_eq!(requested.what, WhyKind::Requested);
    assert_eq!(requested.at, Some(AT - 100));
    assert!(requested.text.contains("ci"), "{}", requested.text);
    let approved = &why.events[1];
    assert_eq!(approved.what, WhyKind::Approved);
    assert!(approved.text.contains("operator"), "{}", approved.text);

    // One the controller queued by itself was neither asked for nor signed.
    let mut automatic = deploy(DeployState::Finished, Some(Outcome::Deployed));
    automatic.request_id = None;
    automatic.requested_by = None;
    automatic.requested_at = None;
    automatic.approved_by = None;
    let why = explain(&automatic, &[]);
    let kinds: Vec<WhyKind> = why.events.iter().map(|event| event.what).collect();
    assert_eq!(
        kinds,
        [WhyKind::Queued, WhyKind::Claimed, WhyKind::Finished]
    );
    assert!(
        why.events[0].text.contains("by itself"),
        "{}",
        why.events[0].text
    );
}
