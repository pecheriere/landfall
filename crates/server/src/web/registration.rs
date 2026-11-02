//! `POST /passkeys/register/begin` and `finish`.
//!
//! The code comes in a body, from the link's fragment, so it reaches no access log. A wrong,
//! used or expired code gets one answer. `begin` spends nothing, and neither does a `finish`
//! that fails: a cancelled dialog or the wrong device shouldn't take a new link. The code
//! was good for an hour already, and one good `finish` ends it, in the transaction that
//! stores the key.
//!
//! No attestation is trusted (`landfall_approval::parse_registration`). What this gives is a key
//! for the operator to review and copy into the configuration. Registration is only as trusted
//! as the link: whoever holds it can store a key for that name. `sign_in` says what that opens.

use std::fmt;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{CoseKey, MAX_CLIENT_DATA_BYTES, parse_registration};
use landfall_core::config::Approval;
use landfall_core::ids::PrincipalId;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::ceremonies::{CHALLENGE_LIFETIME_SECS, FailureKind};
use super::{NO_STORE, admit, charge, charged, count_failure, parsed};
use crate::agent_api::{ApiState, json as json_answer};
use crate::auth::{HumanProblem, PasskeyInvite};
use crate::store::{NewPasskey, Redeemed, StoreError};

/// A code in JSON.
pub(super) const MAX_BEGIN_BODY_BYTES: usize = 1024;
/// The longest attestation object off the wire. It's short with `attestation: "none"`, which
/// some authenticators answer with a statement anyway, and certificates are a few KiB.
const MAX_ATTESTATION_BYTES: usize = 32 * 1024;
/// Both fields at their limits, in base64url and JSON.
pub(super) const MAX_FINISH_BODY_BYTES: usize = 72 * 1024;

const _: () = assert!(
    (MAX_ATTESTATION_BYTES + MAX_CLIENT_DATA_BYTES).div_ceil(3) * 4 + 1024 <= MAX_FINISH_BODY_BYTES
);

/// An invite's code as it was sent, whatever it holds: `Debug` doesn't print it.
#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct SentCode(String);

impl fmt::Debug for SentCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SentCode(<redacted>)")
    }
}

/// The body of `begin`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BeginBody {
    code: SentCode,
}

/// The body of `finish`, as the browser gives it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FinishBody {
    code: SentCode,
    attestation_object: String,
    client_data_json: String,
}

/// The invite a code names and who it is for, if it is good. All else is one answer, and
/// who sent it can't be held to anything.
async fn invite_of(
    state: &ApiState,
    parts: &Parts,
    code: &str,
) -> Result<(PasskeyInvite, PrincipalId), HumanProblem> {
    let holder = match PasskeyInvite::parse(code) {
        Some(invite) => {
            let holder = state.store().invite_holder(&invite).await?;
            holder.map(|principal| (invite, principal))
        }
        None => None,
    };
    holder.ok_or_else(|| {
        state.note_refusal(&parts.extensions, "a passkey invite that isn't good");
        HumanProblem::InviteRefused
    })
}

/// A random challenge from the operating system.
pub(super) fn new_challenge() -> Result<[u8; 32], StoreError> {
    let mut challenge = [0; 32];
    getrandom::fill(&mut challenge).map_err(StoreError::Random)?;
    Ok(challenge)
}

/// The handle a person's credential is stored under on their authenticator. It says nothing of
/// the name, as `WebAuthn` wants, and is stable so that registering again on one device replaces
/// that device's credential for this relying party rather than leaving a dead one on it.
fn user_handle(principal: &PrincipalId) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(principal.as_ref().as_bytes()))
}

/// What `navigator.credentials.create()` is asked for. ES256 and `EdDSA` are all the verifier
/// takes. The credential is discoverable, as signing in names nobody: an authenticator that
/// can't hold one can't register.
fn creation_options(
    settings: &Approval,
    principal: &PrincipalId,
    challenge: &[u8],
) -> serde_json::Value {
    json!({
        "principal": principal,
        "publicKey": {
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "rp": { "id": settings.rp_id(), "name": "landfall" },
            "user": {
                "id": user_handle(principal),
                "name": principal,
                "displayName": principal,
            },
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },
                { "type": "public-key", "alg": -8 },
            ],
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "required",
            },
            "attestation": "none",
            "timeout": CHALLENGE_LIFETIME_SECS * 1000,
        },
    })
}

/// `POST /passkeys/register/begin`.
pub(super) async fn begin(
    State(state): State<ApiState>,
    request: Request<Body>,
) -> Result<Response, HumanProblem> {
    let (parts, body) = request.into_parts();
    let settings = admit(&state, &parts)?;
    charge(&state, &parts)?;
    let sent: BeginBody = parsed(&state, body, MAX_BEGIN_BODY_BYTES).await?;
    let (invite, principal) = invite_of(&state, &parts, &sent.code.0).await?;
    let challenge = new_challenge()?;
    let now = state.store().now()?;
    state
        .ceremonies()
        .open_registration(invite.hash(), challenge, now);
    Ok(json_answer(
        &creation_options(settings, &principal, &challenge),
        &NO_STORE,
    ))
}

/// One field off the wire, its length checked before it is decoded.
fn decoded(text: &str, limit: usize) -> Option<Vec<u8>> {
    if text.len() > (limit * 4).div_ceil(3) {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// What the page shows, for the operator to copy into the configuration.
fn shown(principal: &PrincipalId, credential_id: &[u8], key: &CoseKey) -> serde_json::Value {
    let credential_id = URL_SAFE_NO_PAD.encode(credential_id);
    let public_key = URL_SAFE_NO_PAD.encode(key.as_bytes());
    json!({
        "principal": principal,
        "credential_id": credential_id,
        "public_key": public_key,
        "fingerprint": key.fingerprint(),
        "algorithm": key.algorithm().to_string(),
        "config_line": format!(
            "{principal} = {{ credential_id = \"{credential_id}\", public_key = \"{public_key}\" }}"
        ),
    })
}

/// Whether the configuration holds this credential id for anyone but this principal with this
/// key. The file is the authority on it, so no stored key may claim it.
fn claims_a_configured_credential(
    state: &ApiState,
    principal: &PrincipalId,
    credential_id: &[u8],
    key: &CoseKey,
) -> bool {
    state.config().approvers().iter().any(|(name, approver)| {
        approver.credential_id() == credential_id
            && (name != principal || approver.public_key() != key.as_bytes())
    })
}

/// `POST /passkeys/register/finish`.
pub(super) async fn finish(
    State(state): State<ApiState>,
    request: Request<Body>,
) -> Result<Response, HumanProblem> {
    let (parts, body) = request.into_parts();
    let settings = admit(&state, &parts)?;
    let sent: FinishBody = match parsed(&state, body, MAX_FINISH_BODY_BYTES).await {
        Ok(sent) => sent,
        Err(problem) => return Err(charged(&state, &parts, problem)),
    };
    let (invite, principal) = match invite_of(&state, &parts, &sent.code.0).await {
        Ok(found) => found,
        Err(problem) => return Err(charged(&state, &parts, problem)),
    };
    let store = state.store();

    let refuse = |reason: &'static str| {
        count_failure(
            &state,
            &parts,
            &principal,
            FailureKind::Registration,
            reason,
        );
        charged(&state, &parts, HumanProblem::RegistrationRefused)
    };
    let now = store.now()?;
    let waiting = state.ceremonies().take_registration(&invite.hash(), now);
    let challenge = waiting
        .ok_or_else(|| refuse("no challenge is waiting for this invite: too late, or used"))?;
    let (Some(attestation), Some(client_data)) = (
        decoded(&sent.attestation_object, MAX_ATTESTATION_BYTES),
        decoded(&sent.client_data_json, MAX_CLIENT_DATA_BYTES),
    ) else {
        return Err(refuse("a field is too long, or is not base64url"));
    };
    let registered = parse_registration(
        &attestation,
        &client_data,
        settings.rp_id(),
        settings.origin(),
        &challenge,
    )
    .map_err(|_| refuse("the attestation did not check out"))?;
    if claims_a_configured_credential(
        &state,
        &principal,
        &registered.credential_id,
        &registered.key,
    ) {
        return Err(refuse(
            "the credential id is one the configuration holds for someone or some key else",
        ));
    }

    let passkey = NewPasskey {
        credential_id: &registered.credential_id,
        key: &registered.key,
    };
    match store.redeem_invite(&invite, &passkey).await? {
        Redeemed::Registered { principal, ended } => {
            state.forget_sessions(&ended);
            Ok(json_answer(
                &shown(&principal, &registered.credential_id, &registered.key),
                &NO_STORE,
            ))
        }
        Redeemed::InviteGone => Err(charged(&state, &parts, HumanProblem::InviteRefused)),
        Redeemed::CredentialTaken => Err(refuse("another principal holds this credential id")),
    }
}
