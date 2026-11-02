//! `POST /api/v1/deployments/{name}/{stage}/requests`.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use landfall_core::config::{Deployment, Permission};
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::rule::{Decision, decide};
use semver::Version;
use serde::Deserialize;
use sqlx::{Sqlite, Transaction};

use super::{
    Stop, Subject, no_store, parsed_body, ready_host, refuse_alone, refuse_in, refused, view,
    visibility,
};
use crate::agent_api::{ApiState, json as json_answer};
use crate::audit::EventKind;
use crate::auth::{HumanProblem, Principal, can};
use crate::store::{NewRequest, StoreError};
use crate::watcher::promotion_waits_for;

/// A request is one tag, at most 128 bytes.
const MAX_REQUEST_BODY_BYTES: usize = 1024;

const NO_GRANT_TO_ASK: &str = "no grant lets this principal ask for this deployment";

/// The body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskBody {
    tag: ReleaseTag,
}

/// Whether promotion holds this release back: not for a downgrade, the manual rollback.
async fn promotion_holds(
    state: &ApiState,
    d: &Deployment,
    tag: &ReleaseTag,
    version: &Version,
) -> Result<bool, StoreError> {
    let store = state.store();
    let running = store.watch_view(d.id(), d.host()).await?.running;
    let running_version = running
        .and_then(|running| running.tag)
        .and_then(|running| d.origin().tags().parse_tag(&running).ok());
    if running_version.is_some_and(|running| *version < running) {
        return Ok(false);
    }
    let Some(digest) = store
        .release(d.id(), tag)
        .await?
        .and_then(|release| release.digest)
    else {
        return Ok(false);
    };
    Ok(
        promotion_waits_for(store, state.config(), d.id(), tag, &digest)
            .await?
            .is_some(),
    )
}

/// Everything about a request but its nonce, judged in `tx`: the intent to record. A
/// rollback by someone who may do one cancels the open request it finds, once nothing else
/// stands in its way.
async fn judge_request(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    principal: &Principal,
    (d, tag, version): (&Deployment, &ReleaseTag, &Version),
    nonce: [u8; 32],
) -> Result<DeployIntent, Stop> {
    let store = state.store();
    let snapshot = store.request_snapshot(tx, (d.id(), d.host(), tag)).await?;
    let running_tag = snapshot.running.as_ref().and_then(|r| r.tag.as_ref());
    let readable = running_tag.map(|running| d.origin().tags().parse_tag(running).ok());
    let downgrade = readable
        .as_ref()
        .and_then(Option::as_ref)
        .is_some_and(|running| version < running);
    let may_roll_back =
        downgrade && can(state.config(), principal, d.id(), Permission::Rollback);
    if snapshot.open_request && !may_roll_back {
        return Err(refused(
            HumanProblem::RequestOpen,
            "the deployment already has a request waiting for an approver",
        ));
    }
    if snapshot.active_deploy {
        return Err(refused(
            HumanProblem::DeploymentBusy,
            "the deployment has a deploy queued or running",
        ));
    }
    let running = ready_host(&snapshot)?;
    let held = store.release_held(tx, d.id(), tag).await?;
    let settled = snapshot
        .release
        .as_ref()
        .filter(|release| !held && release.verified_under(state.config().hash()))
        .and_then(|release| release.settled());
    let Some((commit, digest)) = settled else {
        return Err(refused(
            HumanProblem::ReleaseNotVerified,
            "no verified record of this release for this configuration",
        ));
    };
    if readable.as_ref().is_some_and(Option::is_none) {
        return Err(refused(
            HumanProblem::HostNotReady,
            "the running tag does not match the deployment's tag pattern",
        ));
    }
    match decide(d.rule(), readable.flatten().as_ref(), version) {
        Decision::Refused(_) => {
            return Err(refused(
                HumanProblem::ReleaseRefused,
                "the rule refuses this release",
            ));
        }
        Decision::Auto | Decision::NeedsApproval | Decision::Manual => {}
    }
    let needs = if downgrade {
        Permission::Rollback
    } else {
        Permission::Request
    };
    if !can(state.config(), principal, d.id(), needs) {
        return Err(refused(
            HumanProblem::Forbidden,
            "no grant lets this principal ask for this: a lower version takes rollback, and \
             any other takes request",
        ));
    }
    if snapshot.open_request {
        let reason = format!(
            "superseded by a rollback to {tag}, asked for by {}",
            principal.id()
        );
        store
            .cancel_open_request(tx, (d.id(), None), &principal.audited(), &reason)
            .await?;
    }
    Ok(DeployIntent {
        deployment: d.id().clone(),
        tag: tag.clone(),
        commit: commit.clone(),
        digest: digest.clone(),
        expected_running: running.digest.clone(),
        nonce,
    })
}

/// The handler.
pub(super) async fn ask(
    State(state): State<ApiState>,
    principal: Principal,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Body,
) -> Result<Response, HumanProblem> {
    let config = state.config();
    let raw = path.map_or_else(|_| String::new(), |Path((a, b))| format!("{a}/{b}"));
    let deployment = raw
        .parse::<DeploymentId>()
        .ok()
        .and_then(|id| config.deployment(&id));
    let subject = Subject {
        kind: EventKind::RequestRefused,
        deployment,
        about: Some(&raw),
        request: None,
        tag: None,
    };
    let may_ask = |d: &&Deployment| {
        can(config, &principal, d.id(), Permission::Request)
            || can(config, &principal, d.id(), Permission::Rollback)
    };
    let Some(d) = deployment.filter(may_ask) else {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            visibility(config, &principal, deployment.map(Deployment::id)),
            NO_GRANT_TO_ASK,
        )
        .await);
    };
    let asked: AskBody = match parsed_body(&state, body, MAX_REQUEST_BODY_BYTES).await {
        Ok(asked) => asked,
        Err((problem, why)) => {
            return Err(refuse_alone(&state, &principal, subject, problem, why).await);
        }
    };
    let tag = &asked.tag;
    let subject = Subject {
        tag: Some(tag),
        ..subject
    };
    let Ok(version) = d.origin().tags().parse_tag(tag) else {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            HumanProblem::ReleaseNotVerified,
            "the tag is not one of this deployment's releases",
        )
        .await);
    };
    if promotion_holds(&state, d, tag, &version).await? {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            HumanProblem::PromotionPending,
            "not yet reported healthy for long enough where it is promoted from",
        )
        .await);
    }
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(StoreError::Random)?;
    let store = state.store();
    let now = store.now()?;
    let mut tx = store.begin().await?;
    store.expire_requests(&mut tx, now).await?;
    match judge_request(&state, &mut tx, &principal, (d, tag, &version), nonce).await {
        Ok(intent) => {
            let request = NewRequest {
                host: d.host(),
                intent,
                requested_by: principal.id(),
                audited_by: principal.audited(),
            };
            let stored = store.insert_request(&mut tx, &request).await?;
            tx.commit().await.map_err(StoreError::from)?;
            let can_approve = can(config, &principal, d.id(), Permission::Approve);
            let mut answer = json_answer(&view(&stored, can_approve), &no_store());
            *answer.status_mut() = StatusCode::CREATED;
            Ok(answer)
        }
        Err(Stop::Refused(refusal)) => {
            refuse_in(&state, tx, &principal, subject, &refusal).await?;
            Err(refusal.problem)
        }
        Err(Stop::Store(error)) => Err(error.into()),
    }
}
