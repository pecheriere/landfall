//! `POST /api/v1/approvals/{id}`.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use landfall_api::{Approved, NewApproval, Problem};
use landfall_approval::{
    Assertion, CoseKey, Expect, MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES,
    MAX_SIGNATURE_BYTES, verify,
};
use landfall_core::config::{Config, Deployment, MAX_CREDENTIAL_ID_LEN, Permission};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{Approval, AssertionText, DeployId};
use landfall_core::text::quoted;
use sqlx::{Sqlite, Transaction};

use super::{
    Refused, Stop, Subject, closed, named_request, parsed_body, ready_host, refuse_alone,
    refuse_in, refused, visibility,
};
use crate::agent_api::ApiState;
use crate::api::{ApiJson, BadRequest, NotFound, RateLimited, Unauthenticated};
use crate::audit::EventKind;
use crate::auth::{HumanProblem, Principal, can};
use crate::report::REFUSAL_SHOWN_CHARS;
use crate::store::{StoreError, StoredRequest};

/// An assertion at the limits of every field, in base64url and JSON, leaves room in this.
const MAX_APPROVAL_BODY_BYTES: usize = 32 * 1024;

const _: () = assert!(
    (MAX_CREDENTIAL_ID_LEN
        + MAX_AUTHENTICATOR_DATA_BYTES
        + MAX_CLIENT_DATA_BYTES
        + MAX_SIGNATURE_BYTES)
        .div_ceil(3)
        * 4
        + 1024
        <= MAX_APPROVAL_BODY_BYTES
);

const NO_GRANT_TO_APPROVE: &str =
    "no grant lets this principal approve here, and a token never can";

/// Refuses an assertion that isn't this approver's over this intent's challenge, by what
/// the host will check. The key is the configuration's: the one the host goes by.
fn check_assertion(
    config: &Config,
    principal: &Principal,
    intent: &DeployIntent,
    text: &AssertionText,
) -> Result<(), Refused> {
    let refuse = |why: String| Refused {
        problem: HumanProblem::AssertionRefused,
        reason: quoted(&why, REFUSAL_SHOWN_CHARS),
    };
    let Some(settings) = config.approval() else {
        return Err(Refused {
            problem: HumanProblem::ApprovalsNotConfigured,
            reason: "the configuration has no [approval] settings".to_owned(),
        });
    };
    let Some(approver) = config.approver(principal.id()) else {
        return Err(refuse(
            "this principal has no key in [approvers]".to_owned(),
        ));
    };
    let key = CoseKey::parse(approver.public_key()).map_err(|error| refuse(error.to_string()))?;
    let assertion = Assertion::try_from(text).map_err(|error| refuse(error.to_string()))?;
    verify(
        &assertion,
        &Expect {
            key: &key,
            credential_id: approver.credential_id(),
            rp_id: settings.rp_id(),
            origin: settings.origin(),
            challenge: &intent.challenge(),
        },
    )
    .map_err(|error| refuse(error.to_string()))
}

/// Ends `request` as stale for `reason`, and says so to who tried it.
async fn gone_stale(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    request: &StoredRequest,
    reason: &str,
) -> Result<(), Stop> {
    state.store().stale_request(tx, request, reason).await?;
    Err(refused(HumanProblem::RequestStale, reason))
}

/// All that could stop `request` from being approved, looked at in `tx`, whose lock is
/// held from before the look until the commit: a host's report comes either before it,
/// which this sees, or after it, and is about a deploy the host will judge for itself.
async fn judge_approval(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    d: &Deployment,
    request: &StoredRequest,
) -> Result<(), Stop> {
    let store = state.store();
    store.expire_requests(tx, store.now()?).await?;
    if let Some((problem, why)) = closed(store.request_state(tx, request.id).await?) {
        return Err(refused(problem, why));
    }
    let intent = &request.intent;
    if request.host != *d.host() {
        return gone_stale(
            state,
            tx,
            request,
            "the deployment is on another host now, by the configuration",
        )
        .await;
    }
    let snapshot = store
        .request_snapshot(tx, (d.id(), d.host(), &intent.tag))
        .await?;
    let same_release = snapshot
        .release
        .as_ref()
        .and_then(|release| release.settled())
        .is_some_and(|(commit, digest)| *commit == intent.commit && *digest == intent.digest);
    if !same_release {
        return gone_stale(
            state,
            tx,
            request,
            "the release's verified record changed after the request was made",
        )
        .await;
    }
    // Both pass by themselves, or become a changed record, so the request stays open. The
    // host would refuse what they say at critical priority, so it isn't to be asked.
    let verified_now = snapshot
        .release
        .as_ref()
        .is_some_and(|release| release.verified_under(state.config().hash()));
    if !verified_now || store.release_held(tx, d.id(), &intent.tag).await? {
        return Err(refused(
            HumanProblem::ReleaseNotVerified,
            "the watcher has this release on hold, or hasn't looked at it under this \
             configuration",
        ));
    }
    if let Some(running) = &snapshot.running
        && running.digest != intent.expected_running
    {
        return gone_stale(
            state,
            tx,
            request,
            "the running digest moved after the request was made",
        )
        .await;
    }
    if snapshot.active_deploy {
        return Err(refused(
            HumanProblem::DeploymentBusy,
            "the deployment has a deploy queued or running",
        ));
    }
    ready_host(&snapshot)?;
    // Promotion is the controller's alone, so nothing after this would catch it. It stays
    // open when this refuses: the source's report may come back, or its time may yet run,
    // and whether it never will isn't known here. Time or a cancel ends it if so. Whether
    // this is a rollback was settled when it was asked for: a host calling what it runs
    // something else now, on the same digest, doesn't change what was asked.
    if !request.is_rollback
        && store
            .promotion_waits_for_on(tx, state.config(), d.id(), (&intent.tag, &intent.digest))
            .await?
            .is_some()
    {
        return Err(refused(
            HumanProblem::PromotionPending,
            "no longer reported healthy for long enough where it is promoted from",
        ));
    }
    Ok(())
}

/// The judgement and the conditional update that follows from it.
async fn approve_in(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    principal: &Principal,
    d: &Deployment,
    request: &StoredRequest,
    approval: &Approval,
) -> Result<DeployId, Stop> {
    judge_approval(state, tx, d, request).await?;
    let queued = state
        .store()
        .approve_request(tx, request, principal.id(), approval)
        .await?;
    queued.ok_or_else(|| {
        refused(
            HumanProblem::RequestClosed,
            "the request was already approved",
        )
    })
}

/// The handler.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{id}",
    operation_id = "approveRequest",
    tag = "requests",
    summary = "Approve a request",
    description = "Signs a request with a passkey's assertion over its challenge, as the \
                   controller's page does. A token never approves.",
    params(("id" = i64, Path, description = "The request's number.", example = 42)),
    request_body = NewApproval,
    security(("session" = ["approve"])),
    responses(
        (
            status = 200,
            description = "The request was approved, and its deploy is queued for its host, \
                           which checks the approval again.",
            body = Approved,
        ),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (
            status = 403,
            description = "No grant lets this principal approve here, a session's state change \
                           didn't come from the controller's origin, or the assertion isn't one by \
                           this principal for this request: `forbidden`, `bad_origin`, \
                           `assertion_refused`.",
            body = Problem,
            content_type = "application/problem+json",
        ),
        (status = 404, response = NotFound),
        (
            status = 409,
            description = "The request can't be approved now: `request_closed`, \
                           `request_stale`, `request_expired`, `request_cancelled`, \
                           `deployment_busy`, `host_not_ready` or `promotion_pending`.",
            body = Problem,
            content_type = "application/problem+json",
        ),
        (status = 429, response = RateLimited),
    ),
)]
pub(super) async fn approve(
    State(state): State<ApiState>,
    principal: Principal,
    path: Result<Path<String>, PathRejection>,
    body: Body,
) -> Result<ApiJson<Approved>, HumanProblem> {
    let config = state.config();
    let store = state.store();
    let raw = path.map_or_else(|_| String::new(), |Path(raw)| raw);
    let stored = named_request(&state, &principal, &raw, EventKind::ApprovalRefused).await?;
    let deployment = stored
        .as_ref()
        .and_then(|request| config.deployment(&request.intent.deployment));
    let subject = Subject {
        kind: EventKind::ApprovalRefused,
        deployment,
        about: stored.is_none().then_some(raw.as_str()),
        request: stored.as_ref().map(|request| request.id),
        tag: stored.as_ref().map(|request| &request.intent.tag),
    };
    let allowed = deployment.filter(|d| can(config, &principal, d.id(), Permission::Approve));
    let (Some(request), Some(d)) = (&stored, allowed) else {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            visibility(config, &principal, deployment.map(Deployment::id)),
            NO_GRANT_TO_APPROVE,
        )
        .await);
    };
    // A clear answer for what's over, whatever came with the asking. The transaction below
    // looks again, and is what counts.
    if let Some((problem, why)) = closed(request.state) {
        return Err(refuse_alone(&state, &principal, subject, problem, why).await);
    }
    let sent: NewApproval = match parsed_body(&state, body, MAX_APPROVAL_BODY_BYTES).await {
        Ok(sent) => sent,
        Err((problem, why)) => {
            return Err(refuse_alone(&state, &principal, subject, problem, why).await);
        }
    };
    let assertion = AssertionText::from(sent.assertion);
    if let Err(refusal) = check_assertion(config, &principal, &request.intent, &assertion) {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            refusal.problem,
            &refusal.reason,
        )
        .await);
    }
    let approval = Approval {
        intent: request.intent.clone(),
        assertion,
    };
    let mut tx = store.begin().await?;
    match approve_in(&state, &mut tx, &principal, d, request, &approval).await {
        Ok(deploy_id) => {
            tx.commit().await.map_err(StoreError::from)?;
            store.wake_agents();
            Ok(ApiJson(Approved {
                request: request.id,
                deploy_id,
            }))
        }
        Err(Stop::Refused(refusal)) => {
            refuse_in(&state, tx, &principal, subject, &refusal).await?;
            Err(refusal.problem)
        }
        Err(Stop::Store(error)) => Err(error.into()),
    }
}
