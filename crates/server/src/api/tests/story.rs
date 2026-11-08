//! Where a release stands: `story::status` and the decision it goes by, table-tested.

use landfall_api::{Decision as ApiDecision, DeploymentRef, NextKind, Outcome, ReleaseStatus};
use landfall_core::ids::{DeploymentId, HostId, ImageDigest, ReleaseTag};
use landfall_core::rule::{Decision, Refusal};

use crate::api::story::{RuleSaid, StoryInputs, decided, status};
use crate::store::views::RunningRow;
use crate::store::{Hold, ReleaseDecision, Store, WatchedRunning};
use semver::Version;

fn tag(text: &str) -> ReleaseTag {
    text.parse().unwrap()
}

fn digest(fill: char) -> ImageDigest {
    format!("sha256:{}", fill.to_string().repeat(64))
        .parse()
        .unwrap()
}

/// What `home-1` says runs: `running` at `fill`'s digest.
fn running(running: &str, fill: char) -> RunningRow {
    RunningRow {
        host: "home-1".parse().unwrap(),
        running: WatchedRunning {
            tag: Some(tag(running)),
            digest: Some(digest(fill)),
            drift: false,
            phase: "idle".to_owned(),
            busy: false,
        },
        healthy_secs: Some(60),
        last_report: Some(1_800_000_000),
        config_drift: false,
    }
}

/// A hold saying `reason`, as the store keeps one.
async fn hold(reason: &str) -> Hold {
    let store = Store::open_in_memory().await.unwrap();
    let deployment: DeploymentId = "app/prod".parse().unwrap();
    let host: HostId = "home-1".parse().unwrap();
    store
        .set_hold((&deployment, &host), Some(&tag("v1.3.0")), reason, false)
        .await
        .unwrap();
    let (mut holds, _) = store.holds_of(&deployment).await.unwrap();
    holds.remove("v1.3.0").unwrap()
}

/// `v1.3.0` at digest `3`, decided `auto` and nothing else known: `waiting`.
fn base<'a>(release: &'a ReleaseTag, at: &'a ImageDigest) -> StoryInputs<'a> {
    StoryInputs {
        tag: release,
        digest: Some(at),
        decision: ApiDecision::Auto,
        decision_reason: "a higher version within the rule's automatic level",
        running: None,
        active_deploy: false,
        open_request: false,
        hold: None,
        last_outcome: None,
        promotion_waits_for: None,
        lower_than_running: false,
    }
}

/// One row of the table: the inputs, the status they produce, its first reason's start and
/// its next action's kind.
type Row<'a> = (
    StoryInputs<'a>,
    ReleaseStatus,
    &'static str,
    Option<NextKind>,
);

/// What the table's rows are made of.
struct Fixture {
    release: ReleaseTag,
    at: ImageDigest,
    runs_it: RunningRow,
    runs_higher: RunningRow,
    held: Hold,
    canary: DeploymentId,
}

impl Fixture {
    async fn new() -> Self {
        Self {
            release: tag("v1.3.0"),
            at: digest('3'),
            runs_it: running("v1.3.0", '3'),
            runs_higher: running("v1.4.0", '4'),
            held: hold("the registry didn't answer").await,
            canary: "app/canary".parse().unwrap(),
        }
    }

    fn base(&self) -> StoryInputs<'_> {
        base(&self.release, &self.at)
    }
}

/// The rows of `running` to `superseded`.
fn first_rows(f: &Fixture) -> Vec<Row<'_>> {
    vec![
        (
            StoryInputs {
                running: Some(&f.runs_it),
                ..f.base()
            },
            ReleaseStatus::Running,
            "its host runs it",
            Some(NextKind::None),
        ),
        (
            StoryInputs {
                active_deploy: true,
                ..f.base()
            },
            ReleaseStatus::Deploying,
            "a deploy of it is queued or running",
            Some(NextKind::Wait),
        ),
        (
            StoryInputs {
                open_request: true,
                decision: ApiDecision::NeedsApproval,
                ..f.base()
            },
            ReleaseStatus::AwaitingApproval,
            "a request for it waits for an approver",
            Some(NextKind::Approve),
        ),
        (
            StoryInputs {
                decision: ApiDecision::Refused,
                decision_reason: "\"no attestation\"",
                ..f.base()
            },
            ReleaseStatus::Refused,
            "refused: \"no attestation\"",
            Some(NextKind::None),
        ),
        (
            StoryInputs {
                hold: Some(&f.held),
                ..f.base()
            },
            ReleaseStatus::Held,
            "held: \"the registry didn't answer\"",
            Some(NextKind::Wait),
        ),
        (
            StoryInputs {
                running: Some(&f.runs_higher),
                lower_than_running: true,
                decision: ApiDecision::Manual,
                ..f.base()
            },
            ReleaseStatus::Superseded,
            "a higher version, v1.4.0, runs",
            Some(NextKind::Rollback),
        ),
        (
            StoryInputs {
                running: Some(&f.runs_higher),
                lower_than_running: true,
                decision: ApiDecision::NeedsApproval,
                ..f.base()
            },
            ReleaseStatus::Superseded,
            "a higher version, v1.4.0, runs",
            Some(NextKind::Rollback),
        ),
    ]
}

/// The rows of `failed` to `waiting`.
fn last_rows(f: &Fixture) -> Vec<Row<'_>> {
    vec![
        (
            StoryInputs {
                last_outcome: Some((Outcome::RolledBack, "check failed")),
                ..f.base()
            },
            ReleaseStatus::Failed,
            "its last deploy failed, and its host went back to what ran before: check failed",
            Some(NextKind::Request),
        ),
        (
            StoryInputs {
                last_outcome: Some((Outcome::RollbackFailed, "")),
                ..f.base()
            },
            ReleaseStatus::Failed,
            "its last deploy failed, and so did going back to what ran before",
            Some(NextKind::Recover),
        ),
        (
            StoryInputs {
                last_outcome: Some((Outcome::Refused, "not in my configuration")),
                ..f.base()
            },
            ReleaseStatus::HostRefused,
            "its host refused it: not in my configuration",
            Some(NextKind::FixHost),
        ),
        (
            StoryInputs {
                last_outcome: Some((Outcome::Deferred, "disk busy")),
                ..f.base()
            },
            ReleaseStatus::Deferred,
            "its host said not now: disk busy",
            Some(NextKind::Wait),
        ),
        (
            StoryInputs {
                decision: ApiDecision::Deferred,
                ..f.base()
            },
            ReleaseStatus::Deferred,
            "its host said not now",
            Some(NextKind::Wait),
        ),
        (
            StoryInputs {
                promotion_waits_for: Some(DeploymentRef::Seen(f.canary.clone())),
                ..f.base()
            },
            ReleaseStatus::PromotionPending,
            "it waits to be reported healthy for long enough on app/canary",
            Some(NextKind::Wait),
        ),
        (
            StoryInputs {
                decision: ApiDecision::NeedsApproval,
                decision_reason: "a higher version that needs an approver",
                ..f.base()
            },
            ReleaseStatus::NeedsRequest,
            "a higher version that needs an approver",
            Some(NextKind::Request),
        ),
        (
            StoryInputs {
                decision: ApiDecision::Manual,
                decision_reason: "beyond the rule's levels: it needs an operator",
                ..f.base()
            },
            ReleaseStatus::NeedsRequest,
            "beyond the rule's levels: it needs an operator",
            Some(NextKind::Request),
        ),
        (
            f.base(),
            ReleaseStatus::Waiting,
            "it deploys by itself once its host can take it",
            Some(NextKind::Wait),
        ),
    ]
}

#[tokio::test]
async fn status_table() {
    let f = Fixture::new().await;
    let mut seen = std::collections::BTreeSet::new();
    for (inputs, want, first, next) in first_rows(&f).iter().chain(&last_rows(&f)) {
        let got = status(inputs);
        assert_eq!(got.status, *want, "{inputs:?}");
        let reason = got.reasons.first().unwrap();
        assert!(reason.starts_with(first), "{want:?}: {reason}");
        assert_eq!(got.next.as_ref().map(|n| n.kind), *next, "{want:?}");
        assert_ne!(got.next.unwrap().detail, "");
        seen.insert(format!("{want:?}"));
    }
    // Every status of the precedence has a row.
    assert_eq!(seen.len(), 12, "{seen:?}");
}

#[tokio::test]
async fn needs_request_always_says_request_and_superseded_says_rollback() {
    let release = tag("v1.3.0");
    let at = digest('3');
    let runs_higher = running("v1.4.0", '4');
    for decision in [ApiDecision::NeedsApproval, ApiDecision::Manual] {
        let asked = status(&StoryInputs {
            decision,
            ..base(&release, &at)
        });
        let next = asked.next.unwrap();
        assert_eq!(next.kind, NextKind::Request);
        assert!(next.detail.contains("landfall request"), "{}", next.detail);
        let older = status(&StoryInputs {
            decision,
            running: Some(&runs_higher),
            lower_than_running: true,
            ..base(&release, &at)
        });
        let next = older.next.unwrap();
        assert_eq!(next.kind, NextKind::Rollback);
        assert!(next.detail.contains("landfall rollback"), "{}", next.detail);
    }
}

#[tokio::test]
async fn precedence_holds_when_several_apply() {
    let release = tag("v1.3.0");
    let at = digest('3');
    let runs_it = running("v1.3.0", '3');
    let runs_higher = running("v1.4.0", '4');
    let held = hold("the registry didn't answer").await;
    let running_and_held = status(&StoryInputs {
        running: Some(&runs_it),
        hold: Some(&held),
        ..base(&release, &at)
    });
    assert_eq!(running_and_held.status, ReleaseStatus::Running);
    let held_and_superseded = status(&StoryInputs {
        hold: Some(&held),
        running: Some(&runs_higher),
        lower_than_running: true,
        decision: ApiDecision::Manual,
        ..base(&release, &at)
    });
    assert_eq!(held_and_superseded.status, ReleaseStatus::Held);
    let failed_and_superseded = status(&StoryInputs {
        last_outcome: Some((Outcome::RolledBack, "check failed")),
        running: Some(&runs_higher),
        lower_than_running: true,
        decision: ApiDecision::Manual,
        ..base(&release, &at)
    });
    assert_eq!(failed_and_superseded.status, ReleaseStatus::Superseded);
    // The same tag at another digest isn't what runs.
    let moved = digest('9');
    let other_digest = status(&StoryInputs {
        running: Some(&runs_it),
        ..base(&release, &moved)
    });
    assert_eq!(other_digest.status, ReleaseStatus::Waiting);
}

#[tokio::test]
async fn promotion_reason_does_not_name_an_unseen_deployment() {
    let release = tag("v1.3.0");
    let at = digest('3');
    let explained = status(&StoryInputs {
        promotion_waits_for: Some(DeploymentRef::Unseen),
        ..base(&release, &at)
    });
    assert_eq!(explained.status, ReleaseStatus::PromotionPending);
    let said = format!("{:?} {:?}", explained.reasons, explained.next);
    assert!(said.contains("a deployment you can't view"), "{said}");
    assert!(!said.contains("app/"), "{said}");
}

/// A reason the watcher stored while promotion held a release back: it names the deployment
/// promoted from, which a reader may not be allowed to view.
const PROMOTION_REASON: &str = "\"waits for promotion: not yet reported healthy for long enough \
                                on app/canary, or it has gone quiet\"";

/// How the release, `1.3.0`, compares with what runs, in a row of
/// [`the_status_goes_by_verification_then_the_rule`].
#[derive(Debug, Clone, Copy)]
enum Against {
    NothingRuns,
    Below,
    NotBelow,
}

/// One row of [`the_status_goes_by_verification_then_the_rule`]: what was stored (decision,
/// reason, refused by verification), what the rule says, and the decision and reason wanted.
type DecidedRow = (
    (ReleaseDecision, &'static str, bool),
    Option<(Decision, Against)>,
    (ApiDecision, &'static str),
);

/// The rows where a refusal decides.
fn refusal_rows() -> Vec<DecidedRow> {
    use ReleaseDecision as Stored;
    vec![
        // Refused by verification, whatever the rule says: its stored reason decided.
        (
            (Stored::Refused, "\"no attestation\"", true),
            Some((Decision::Auto, Against::NotBelow)),
            (ApiDecision::Refused, "\"no attestation\""),
        ),
        // Refused by the rule, in the rule's words.
        (
            (Stored::Refused, "\"stale\"", false),
            Some((Decision::Refused(Refusal::Prerelease), Against::NotBelow)),
            (
                ApiDecision::Refused,
                "a pre-release, and the rule does not opt in",
            ),
        ),
        // Refused by the watcher for what became of its deploys: someone must ask now, and
        // the stored reason, a fixed text, is what decided.
        (
            (
                Stored::Refused,
                "\"its deploys kept stopping before they began\"",
                false,
            ),
            Some((Decision::Auto, Against::NotBelow)),
            (
                ApiDecision::Manual,
                "\"its deploys kept stopping before they began\"",
            ),
        ),
        (
            (
                Stored::Refused,
                "\"it already rolled back on its host\"",
                false,
            ),
            Some((Decision::NeedsApproval, Against::NotBelow)),
            (
                ApiDecision::NeedsApproval,
                "a higher version that needs an approver",
            ),
        ),
    ]
}

/// The rows where the rule's word, or its absence, decides.
fn rule_rows() -> Vec<DecidedRow> {
    use ReleaseDecision as Stored;
    let promoted = PROMOTION_REASON;
    vec![
        // Held back for promotion, which the status tells by itself: the stored reason,
        // which names where it is promoted from, is never shown.
        (
            (Stored::Manual, promoted, false),
            Some((Decision::Auto, Against::NotBelow)),
            (
                ApiDecision::Auto,
                "a higher version within the rule's automatic level",
            ),
        ),
        (
            (Stored::Manual, promoted, false),
            Some((Decision::NeedsApproval, Against::NotBelow)),
            (
                ApiDecision::NeedsApproval,
                "a higher version that needs an approver",
            ),
        ),
        (
            (Stored::Manual, promoted, false),
            Some((Decision::Manual, Against::NothingRuns)),
            (
                ApiDecision::Manual,
                "nothing has been deployed yet: a first deploy needs an operator",
            ),
        ),
        (
            (Stored::Manual, promoted, false),
            Some((Decision::Manual, Against::Below)),
            (
                ApiDecision::Manual,
                "lower than the running version: a downgrade needs an operator",
            ),
        ),
        (
            (Stored::Manual, promoted, false),
            Some((Decision::Manual, Against::NotBelow)),
            (
                ApiDecision::Manual,
                "beyond the rule's levels: it needs an operator",
            ),
        ),
        // Deferred by its host, which the status tells from the deploy.
        (
            (Stored::Deferred, "\"its host said not now\"", false),
            Some((Decision::Auto, Against::NotBelow)),
            (
                ApiDecision::Auto,
                "a higher version within the rule's automatic level",
            ),
        ),
        // Without the rule's word, what was recorded, in words of its own...
        (
            (Stored::Deferred, "\"its host said not now\"", false),
            None,
            (ApiDecision::Deferred, "its host said not now"),
        ),
        (
            (Stored::Manual, promoted, false),
            None,
            (ApiDecision::Manual, "it deploys only when someone asks"),
        ),
        // ...but a refusal the rule didn't make is the watcher's, for what became of its
        // deploys: the status tells it from them, so it isn't `refused`.
        (
            (
                Stored::Refused,
                "\"it already rolled back on its host\"",
                false,
            ),
            None,
            (
                ApiDecision::Manual,
                "\"it already rolled back on its host\"",
            ),
        ),
    ]
}

#[test]
fn the_status_goes_by_verification_then_the_rule() {
    let candidate = Version::new(1, 3, 0);
    let (lower, higher) = (Version::new(1, 2, 0), Version::new(1, 4, 0));
    for ((stored, reason, origin_refused), says, (want, want_reason)) in
        refusal_rows().into_iter().chain(rule_rows())
    {
        let rule = says.map(|(decision, against)| RuleSaid {
            decision,
            running: match against {
                Against::NothingRuns => None,
                Against::Below => Some(&higher),
                Against::NotBelow => Some(&lower),
            },
            candidate: &candidate,
        });
        let got = decided(stored, reason, origin_refused, rule);
        assert_eq!(got.decision, want, "{stored:?} {origin_refused} {rule:?}");
        assert_eq!(
            got.reason, want_reason,
            "{stored:?} {origin_refused} {rule:?}"
        );
        assert!(!got.reason.contains("app/canary"), "{}", got.reason);
    }
}

#[test]
fn a_history_refusal_without_the_rules_word_still_reads_failed() {
    let release = tag("v1.3.0");
    let at = digest('3');
    let refused = "\"it already rolled back on its host\"";
    let got = decided(ReleaseDecision::Refused, refused, false, None);
    let explained = status(&StoryInputs {
        decision: got.decision,
        decision_reason: &got.reason,
        last_outcome: Some((Outcome::RolledBack, "check failed")),
        ..base(&release, &at)
    });
    assert_eq!(explained.status, ReleaseStatus::Failed);
}
