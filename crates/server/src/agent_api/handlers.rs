//! The four endpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::PoisonError;

use axum::Extension;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use landfall_core::config::Deployment;
use landfall_core::ids::{DeploymentId, HostId};
use landfall_core::protocol::{
    DeployReportBody, EnrolRequest, HeldBack, NonceResponse, RunningState, WorkRequest,
    WorkResponse,
};
use serde::Serialize;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use super::ApiState;
use super::problem::{ApiProblem, log};
use super::signed::{Signed, read_body};
use crate::report::BoundedReport;
use crate::store::{StoreError, WorkPick};

/// An enrolment request is a code, a host id and a key: this leaves room to
/// spare, and an unauthenticated caller gets to send no more.
const MAX_ENROL_BODY_BYTES: usize = 4 * 1024;

/// What a host with the wrong configuration is told, for each deployment.
const CONFIG_DRIFT_REASON: &str =
    "this host's configuration hash differs from the controller's configuration";

/// The peer of the connection, as `serve` provides it.
type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

/// A `200` with a JSON body.
fn json<T: Serialize>(value: &T, extra: &[(HeaderName, &'static str)]) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = Response::new(Body::from(body));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            for (name, value) in extra {
                headers.insert(name, HeaderValue::from_static(value));
            }
            response
        }
        Err(error) => {
            log(&format!("agent API: cannot serialise an answer: {error}"));
            ApiProblem::Internal.into_response()
        }
    }
}

/// Takes a token for the connection's source. A request with no peer can only
/// come from a test or a misconfigured `serve`; such requests share one
/// allowance.
fn check_source(state: &ApiState, peer: &Peer) -> Result<(), ApiProblem> {
    let source = peer
        .as_ref()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |p| p.0.0.ip());
    let now = state.store.now()?;
    let allowed = state
        .limiter
        .lock()
        // The limiter's state is valid at every step, so it is safe to go on
        // using it after a panic elsewhere.
        .unwrap_or_else(PoisonError::into_inner)
        .allow(source, now);
    if allowed {
        Ok(())
    } else {
        Err(ApiProblem::RateLimited)
    }
}

/// `POST /agent/v1/enrol`.
pub(super) async fn enrol(
    State(state): State<ApiState>,
    peer: Peer,
    request: Request,
) -> Result<StatusCode, ApiProblem> {
    check_source(&state, &peer)?;
    let (parts, body) = request.into_parts();
    let bytes = read_body(body, MAX_ENROL_BODY_BYTES, state.limits.body_timeout).await?;
    let request: EnrolRequest =
        serde_json::from_slice(&bytes).map_err(|_| ApiProblem::BadRequest)?;
    match state
        .store
        .enrol(&request.host, &request.code, &request.public_key)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(StoreError::InvalidCode) => {
            state.note_refusal(&parts.extensions, "an invalid enrolment code");
            Err(ApiProblem::InvalidCode)
        }
        Err(other) => Err(other.into()),
    }
}

/// `GET /agent/v1/nonce`. Not cacheable: a proxy serving one nonce twice would
/// make every second request fail.
pub(super) async fn nonce(
    State(state): State<ApiState>,
    peer: Peer,
) -> Result<Response, ApiProblem> {
    check_source(&state, &peer)?;
    let nonce = state
        .store
        .issue_nonce(state.limits.max_outstanding_nonces)
        .await?;
    Ok(json(
        &NonceResponse { nonce },
        &[(header::CACHE_CONTROL, "no-store")],
    ))
}

/// Ends when the server begins to stop.
async fn until_shutdown(mut shutdown: watch::Receiver<bool>) {
    drop(shutdown.wait_for(|stopping| *stopping).await);
}

/// The deployments a host with the wrong configuration is told about: those the
/// controller gives it and those it says it has, since the two configurations
/// disagree. What it says is only ever repeated back to it.
fn held_for_config_drift(state: &ApiState, host: &HostId, request: &WorkRequest) -> Vec<HeldBack> {
    let mine = state.config.deployments_for_host(host).map(Deployment::id);
    let said = request.running.iter().map(|r| &r.deployment);
    let names: BTreeSet<&DeploymentId> = mine.chain(said).collect();
    names
        .into_iter()
        .map(|deployment| HeldBack {
            deployment: deployment.clone(),
            reason: CONFIG_DRIFT_REASON.to_owned(),
        })
        .collect()
}

/// What a host says about deployments the configuration gives it. Anything else
/// it lists is ignored, so it cannot speak for another host's deployment. Each
/// counts once, the last one listed, so that repeating entries in one request
/// cannot write more than the deployment's own row and audit events.
fn own_running<'a>(
    state: &ApiState,
    host: &HostId,
    request: &'a WorkRequest,
) -> Vec<&'a RunningState> {
    let own: BTreeMap<&DeploymentId, &RunningState> = request
        .running
        .iter()
        .filter(|running| {
            state
                .config
                .deployment(&running.deployment)
                .is_some_and(|deployment| deployment.host() == host)
        })
        .map(|running| (&running.deployment, running))
        .collect();
    own.into_values().collect()
}

fn work_answer(pick: WorkPick) -> Response {
    json(
        &WorkResponse {
            work: pick.work,
            held_back: pick.held_back,
        },
        &[],
    )
}

/// `POST /agent/v1/work`: records what the host says, then hands it its next
/// deploy, waiting up to the long poll for one. The answer with nothing to do
/// comes only after that wait, also for a host with the wrong configuration, so
/// a poll loop is paced by the controller. Nothing holds a database connection
/// during the wait. A host has one long poll at a time: a new one ends the old,
/// so a host cannot pile up connections by polling, and a deploy handed to a
/// connection that died is handed out again under the same id.
pub(super) async fn work(
    State(state): State<ApiState>,
    Signed { host, body }: Signed<WorkRequest>,
) -> Result<Response, ApiProblem> {
    let mut superseded = state.take_over_poll(&host);
    let deadline = Instant::now() + state.limits.long_poll;
    let config_matches = hex::encode(body.config_hash) == state.config.hash();
    let drifted_hash = (!config_matches).then_some(&body.config_hash);
    state
        .store
        .record_host_state(&host, drifted_hash, &own_running(&state, &host, &body))
        .await?;

    let shutdown = state.shutdown.subscribe();
    if !config_matches {
        tokio::select! {
            () = sleep_until(deadline) => {}
            () = until_shutdown(shutdown) => {}
            _ = &mut superseded => {}
        }
        return Ok(work_answer(WorkPick {
            work: None,
            held_back: held_for_config_drift(&state, &host, &body),
        }));
    }

    // Subscribed before the first look: a deploy queued after that look wakes
    // this request, so none is missed in between.
    let mut queued = state.store.subscribe_to_work();
    let stopping = until_shutdown(shutdown);
    tokio::pin!(stopping);
    loop {
        let pick = state.store.next_work(&host).await?;
        if pick.work.is_some() {
            return Ok(work_answer(pick));
        }
        tokio::select! {
            () = sleep_until(deadline) => return Ok(work_answer(pick)),
            () = &mut stopping => return Ok(work_answer(pick)),
            _ = &mut superseded => return Ok(work_answer(WorkPick::default())),
            Ok(()) = queued.changed() => {}
        }
    }
}

/// `POST /agent/v1/report`: bounds the report, then records it for the signer
/// only.
pub(super) async fn report(
    State(state): State<ApiState>,
    Signed { host, body }: Signed<DeployReportBody>,
) -> Result<StatusCode, ApiProblem> {
    let report = BoundedReport::new(&body);
    state.store.finish_deploy(&host, &report).await?;
    Ok(StatusCode::NO_CONTENT)
}
