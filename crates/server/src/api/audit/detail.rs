//! What an audit row shows of its detail and its host, to one principal.
//!
//! The log is hash-chained, so a row stays as it was written, and some writers put words in
//! it that name another deployment or host: the watcher's reason for a release that waits for
//! promotion names where it waits, and a refused report names what it claimed. So nothing of
//! a detail goes out as stored. Each kind lists the fields it shows, and anything else is
//! dropped; a kind with no list shows nothing. A field naming a deployment is shown as
//! `shown_deployment` has it, and a host only if the principal may see that host. Free text is
//! shown only where its writer can't name another deployment or host; otherwise it is said
//! again from what the row records, in the controller's own words, or left out.

use std::collections::BTreeSet;

use landfall_api::DeploymentRef;
use landfall_core::config::{Config, Deployment};
use landfall_core::ids::{DeploymentId, HostId};
use landfall_core::rule::{Decision, Refusal, reason, refusal_reason};
use semver::Version;
use serde_json::{Map, Value, json};

use super::super::visible::{shown_deployment, viewable_deployments};
use crate::audit::EventKind;
use crate::auth::Principal;
use crate::store::REPORT_REFUSALS;

/// What a kind shows beyond its listed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extra {
    /// Nothing.
    None,
    /// A rule decision's reason, said again in the rule's words when the row allows it.
    RuleReason,
    /// A refused report's reason, when it is one of the controller's that name nothing.
    ReportReason,
    /// A request's `deployment` and `host`, as the principal may see them.
    RequestNames,
}

/// The fields `kind` shows as stored, and what else.
///
/// Every kind is listed, so a new one doesn't compile until it says what it shows. Rows about
/// neither a deployment nor a host never reach here, and show nothing if they did.
fn shown_fields(kind: EventKind) -> (&'static [&'static str], Extra) {
    match kind {
        // The watcher's look at a release of this deployment: its origin, or why verification
        // refused it, in the words of what verified this deployment's own repository.
        EventKind::ReleaseSeen => (
            &[
                "tag",
                "tag_object",
                "commit",
                "digest",
                "signer",
                "san",
                "run_url",
                "rekor_log_index",
                "integrated_time",
                "refused",
            ],
            Extra::None,
        ),
        // Its reason can name the deployment it is promoted from.
        EventKind::RuleDecision => (
            &["tag", "decision", "digest", "previous"],
            Extra::RuleReason,
        ),
        // Why the watcher couldn't decide: a fetch or verification of this deployment's own
        // repository, or the state of its own host.
        EventKind::ReleaseHeld => (&["tag", "reason"], Extra::None),
        EventKind::DeployQueued => (
            &["deploy_id", "tag", "digest", "commit", "request"],
            Extra::None,
        ),
        EventKind::DeployClaimed => (&["deploy_id", "tag"], Extra::None),
        // What the deployment's host said of this deploy, as `getDeploy` shows it.
        EventKind::DeployFinished | EventKind::DeployRefused => (
            &[
                "deploy_id",
                "tag",
                "outcome",
                "reason",
                "rollback_reason",
                "steps",
                "steps_dropped",
                "checks_dropped",
            ],
            Extra::None,
        ),
        EventKind::RunningChanged => (&["tag", "digest", "previous_tag"], Extra::None),
        EventKind::RunningDrift => (&["drift"], Extra::None),
        // A fixed sentence.
        EventKind::RunningInconsistent => (&["reason"], Extra::None),
        EventKind::DeployRequested => (
            &[
                "request",
                "by",
                "tag",
                "commit",
                "digest",
                "expected_running",
                "nonce",
            ],
            Extra::None,
        ),
        EventKind::RequestApproved => (
            &["request", "deploy_id", "approver", "tag", "digest", "nonce"],
            Extra::None,
        ),
        // Their reasons are fixed sentences, or name who cancelled and the tag of this
        // deployment a rollback asked for.
        EventKind::RequestStale | EventKind::RequestExpired | EventKind::RequestCancelled => (
            &[
                "request",
                "tag",
                "digest",
                "expected_running",
                "reason",
                "by",
            ],
            Extra::RequestNames,
        ),
        // Their reasons are the refusal's, which say what of this deployment stood in the way,
        // or why a passkey's assertion didn't verify. `about` is what the client wrote.
        EventKind::RequestRefused | EventKind::ApprovalRefused | EventKind::CancelRefused => {
            (&["by", "request", "tag", "problem", "reason"], Extra::None)
        }
        // Its reason can name the deployment a report claimed.
        EventKind::ReportRefused => (&["deploy_id"], Extra::ReportReason),
        EventKind::HostEnrolled => (&["public_key", "replaced_key"], Extra::None),
        EventKind::ConfigDrift => (&["drifted", "reported_hash"], Extra::None),
        // Never listed: about another host's enrolment, or about no deployment or host.
        EventKind::EnrolCodeIssued
        | EventKind::EnrolRefused
        | EventKind::TokenCreated
        | EventKind::TokenRevoked
        | EventKind::PasskeyInviteIssued
        | EventKind::AccessRefused
        | EventKind::AccessThrottled
        | EventKind::PasskeyRegistered
        | EventKind::RegistrationRefused
        | EventKind::SignedIn
        | EventKind::SignInRefused
        | EventKind::SignInBarredKey
        | EventKind::SignedOut => (&[], Extra::None),
    }
}

/// Every reason the rule gives, which name nothing but versions' order.
fn rule_reasons() -> [&'static str; 7] {
    let (lower, higher) = (Version::new(1, 0, 0), Version::new(2, 0, 0));
    [
        reason(Decision::Auto, Some(&lower), &higher),
        reason(Decision::NeedsApproval, Some(&lower), &higher),
        reason(Decision::Manual, None, &higher),
        reason(Decision::Manual, Some(&higher), &lower),
        reason(Decision::Manual, Some(&lower), &higher),
        refusal_reason(Refusal::Prerelease),
        refusal_reason(Refusal::AlreadyRunning),
    ]
}

/// The one of `allowed` that `stored` records, as the store writes a reason: quoted.
fn recorded<'a>(stored: Option<&Value>, allowed: &[&'a str]) -> Option<&'a str> {
    let stored = stored?.as_str()?;
    allowed
        .iter()
        .copied()
        .find(|text| stored == *text || stored == format!("{text:?}"))
}

/// What a principal may be told of the deployments and hosts a row names.
pub(super) struct Reader<'a> {
    config: &'a Config,
    principal: &'a Principal,
    /// The hosts the configuration puts a deployment on that the principal may view: those
    /// `getHost` shows them.
    hosts: BTreeSet<&'a HostId>,
}

impl<'a> Reader<'a> {
    pub(super) fn new(config: &'a Config, principal: &'a Principal) -> Self {
        let hosts = viewable_deployments(config, principal)
            .map(Deployment::host)
            .collect();
        Self {
            config,
            principal,
            hosts,
        }
    }

    /// The host `stored` names, if it is one and the principal may see it.
    pub(super) fn host(&self, stored: Option<&str>) -> Option<HostId> {
        stored
            .and_then(|text| text.parse::<HostId>().ok())
            .filter(|host| self.hosts.contains(host))
    }

    /// What a row of `kind`, if this version knows it, shows of `stored`.
    pub(super) fn detail(&self, kind: Option<EventKind>, stored: &Map<String, Value>) -> Value {
        let Some(kind) = kind else {
            return json!({});
        };
        let (fields, extra) = shown_fields(kind);
        let mut shown: Map<String, Value> = fields
            .iter()
            .filter_map(|field| Some(((*field).to_owned(), stored.get(*field)?.clone())))
            .collect();
        match extra {
            Extra::None => {}
            Extra::RuleReason => {
                if let Some(text) = recorded(stored.get("reason"), &rule_reasons()) {
                    shown.insert("reason".to_owned(), json!(text));
                }
            }
            Extra::ReportReason => {
                if let Some(text) = recorded(stored.get("reason"), &REPORT_REFUSALS) {
                    shown.insert("reason".to_owned(), json!(text));
                }
            }
            Extra::RequestNames => {
                if let Some(deployment) = stored.get("deployment") {
                    let id = deployment
                        .as_str()
                        .and_then(|text| text.parse::<DeploymentId>().ok());
                    let named = id.map_or(DeploymentRef::Unseen, |id| {
                        shown_deployment(self.config, self.principal, &id)
                    });
                    shown.insert("deployment".to_owned(), json!(named));
                }
                if let Some(host) = stored.get("host") {
                    let host = self.host(host.as_str());
                    shown.insert("host".to_owned(), json!(host));
                }
            }
        }
        Value::Object(shown)
    }
}
