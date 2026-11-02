//! `POST /sign-in/begin` and `finish`, and `POST /sign-out`.
//!
//! **Nobody is named.** `begin` takes no name and lists no credential: the browser offers what
//! it holds for this relying party, so an unauthenticated caller learns neither who exists nor
//! any credential id. What this costs is that a security key which can't hold a discoverable
//! credential can't be used.
//!
//! **Whose key opens a session** is decided by the credential id in the assertion:
//!
//! 1. One the configuration holds for an approver: that approver, by the file's key. It was
//!    reviewed, and it's what hosts go by. It need never have been registered on this controller.
//! 2. One stored at registration, for a principal the configuration names, who has no key in
//!    `[approvers]`: that principal, by the stored key. Without it someone with grants and no
//!    approver's key couldn't sign in at all.
//! 3. Anything else is refused, and that includes **a stored key for someone who has a different
//!    one in `[approvers]`,** and one for a principal the file doesn't name yet. A key that's
//!    registered and not yet reviewed can do nothing, then, but be read off the page and copied
//!    into a pull request. So a leaked invite for an approver gets no session. A leaked invite
//!    for someone with grants only does: it opens what those grants open, and never `approve`,
//!    which also takes a key in `[approvers]` and a fresh assertion by it, each time.
//!
//! A session holds no power of its own: every use goes through `can`, on the file's grants.
//!
//! **Every failure is one answer,** from the same order of work: a signature is checked either
//! way, against a public key nobody's challenge could ever pass for an unknown credential, as the
//! agent API does for an unknown host. A challenge is used up by any attempt that names it.
//!
//! A sign-in tap is `webauthn.get`, like an approval's. So a compromised controller could put an
//! intent's hash in a sign-in ceremony, and a person's tap would approve that. It is within the
//! residual risk of design 6.3, where a controller's page can already show one thing and have
//! another signed, and the host still only runs a maintainer-signed release on what it is told
//! to expect. `landfall approve`, computing the hash locally, is the stronger path.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{Assertion, CoseKey, Expect, verify};
use landfall_core::config::{Approval, MAX_CREDENTIAL_ID_LEN};
use landfall_core::ids::PrincipalId;
use landfall_core::protocol::AssertionText;
use serde::Deserialize;
use serde_json::json;

use super::ceremonies::{CHALLENGE_LIFETIME_SECS, FailureKind, Full};
use super::registration::new_challenge;
use super::{NO_STORE, admit, charge, charged, count_failure, parsed};
use crate::agent_api::{ApiState, json as json_answer};
use crate::audit::{AuditEvent, EventKind};
use crate::auth::{
    HumanProblem, Leaving, SESSION_COOKIE, Spender, named_in_config, session_of, spend_budget,
};
use crate::store::SESSION_LIFETIME_SECS;

/// An assertion at its limits, as an approval's body allows, and a challenge.
const MAX_FINISH_BODY_BYTES: usize = 32 * 1024;

const _: () = assert!(MAX_CREDENTIAL_ID_LEN < MAX_FINISH_BODY_BYTES);

/// A P-256 key checked against for a credential nobody knows, so that one takes the time of a
/// real check. It is the curve's generator, whose private key is 1, so a signature by it proves
/// nothing, and the result is never accepted: see [`check`].
pub(super) const NOBODYS_KEY: [u8; 77] = [
    0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c,
    0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
    0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x22, 0x58, 0x20, 0x4f, 0xe3, 0x42,
    0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33,
    0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// The body of `finish`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishBody {
    /// The challenge `begin` gave, which is what finds it again.
    challenge: String,
    assertion: AssertionText,
}

/// `POST /sign-in/begin`: options for `navigator.credentials.get()`, naming nobody. The
/// relying party is the origin's own hostname, which is the browser's default.
pub(super) async fn begin(
    State(state): State<ApiState>,
    request: Request<Body>,
) -> Result<Response, HumanProblem> {
    let (parts, _) = request.into_parts();
    admit(&state, &parts)?;
    charge(&state, &parts)?;
    let challenge = new_challenge()?;
    let opened = state
        .ceremonies()
        .open_sign_in(&challenge, state.store().now()?);
    if opened == Err(Full) {
        state.note_refusal(&parts.extensions, "a sign-in with the table full");
        return Err(HumanProblem::CeremoniesBusy);
    }
    Ok(json_answer(
        &json!({
            "publicKey": {
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "userVerification": "required",
                "allowCredentials": [],
                "timeout": CHALLENGE_LIFETIME_SECS * 1000,
            },
        }),
        &NO_STORE,
    ))
}

/// Who a credential id says is signing in, and what may come of it.
#[derive(Debug)]
struct Claimed {
    principal: PrincipalId,
    public_key: Vec<u8>,
    /// Why this key opens nothing even if it verifies, if it doesn't.
    barred: Option<&'static str>,
    /// How the audit log names the key.
    how: &'static str,
}

/// The rules at the top of this file. The database is read either way, so that a credential in
/// the file takes as long to find as any other.
async fn claimed(state: &ApiState, credential_id: &[u8]) -> Result<Option<Claimed>, HumanProblem> {
    let config = state.config();
    let stored = state.store().stored_passkey(credential_id).await?;
    let configured = config
        .approvers()
        .iter()
        .find(|(_, approver)| approver.credential_id() == credential_id);
    if let Some((name, approver)) = configured {
        return Ok(Some(Claimed {
            principal: name.clone(),
            public_key: approver.public_key().to_vec(),
            barred: None,
            how: "configured_key",
        }));
    }
    Ok(stored.map(|passkey| {
        let barred = if config.approver(&passkey.principal).is_some() {
            Some("a key other than the one the configuration holds for this approver")
        } else if named_in_config(config, &passkey.principal) {
            None
        } else {
            Some("a key for a principal the configuration does not name")
        };
        Claimed {
            principal: passkey.principal,
            public_key: passkey.public_key,
            barred,
            how: "stored_key",
        }
    }))
}

/// Verifies against the key claimed, or nobody's. Only ever true for a key that is someone's.
fn check(
    settings: &Approval,
    assertion: &Assertion,
    challenge: &[u8],
    claim: Option<&Claimed>,
) -> bool {
    let bytes = claim.map_or(NOBODYS_KEY.as_slice(), |claim| claim.public_key.as_slice());
    let Ok(key) = CoseKey::parse(bytes) else {
        return false;
    };
    let verified = verify(
        assertion,
        &Expect {
            key: &key,
            credential_id: &assertion.credential_id,
            rp_id: settings.rp_id(),
            origin: settings.origin(),
            challenge,
        },
    )
    .is_ok();
    verified && claim.is_some()
}

/// The cookie that holds a session, or with no value and no time left, that ends one.
fn cookie(value: &str, max_age: i64) -> Result<HeaderValue, HumanProblem> {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
    ))
    .map_err(|_| crate::agent_api::ApiProblem::Internal.into())
}

/// A refusal nobody can be held to, for the capped log.
fn refuse_stranger(state: &ApiState, parts: &Parts) -> HumanProblem {
    state.note_refusal(&parts.extensions, "a sign-in naming nobody known");
    charged(state, parts, HumanProblem::SignInRefused)
}

/// A refusal against who was named, to count. The answer is the same.
fn refuse_named(
    state: &ApiState,
    parts: &Parts,
    principal: &PrincipalId,
    kind: FailureKind,
    reason: &'static str,
) -> HumanProblem {
    count_failure(state, parts, principal, kind, reason);
    charged(state, parts, HumanProblem::SignInRefused)
}

/// `POST /sign-in/finish`.
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
    let store = state.store();

    let challenge = URL_SAFE_NO_PAD.decode(&sent.challenge).unwrap_or_default();
    let taken = state.ceremonies().take_sign_in(&challenge, store.now()?);
    if !taken {
        return Err(refuse_stranger(&state, &parts));
    }
    let Ok(assertion) = Assertion::try_from(&sent.assertion) else {
        return Err(refuse_stranger(&state, &parts));
    };
    let claim = claimed(&state, &assertion.credential_id).await?;
    let verified = check(settings, &assertion, &challenge, claim.as_ref());
    let Some(claim) = claim else {
        return Err(refuse_stranger(&state, &parts));
    };
    if !verified {
        let reason = "the assertion did not verify";
        let kind = FailureKind::SignIn;
        return Err(refuse_named(&state, &parts, &claim.principal, kind, reason));
    }
    if let Some(reason) = claim.barred {
        let kind = FailureKind::SignInBarred;
        return Err(refuse_named(&state, &parts, &claim.principal, kind, reason));
    }

    // They signed, so only now may this cost them anything, and from a budget nothing else
    // spends: no session's, which nobody needs a passkey to use up.
    let spender = Spender::SignIns(claim.principal.clone());
    spend_budget(&state, &parts.extensions, &spender).await?;
    let came_with = session_of(&parts.headers);
    let begun = store
        .begin_session(&claim.principal, claim.how, came_with.as_ref())
        .await?;
    state.forget_sessions(&begun.ended);
    let mut response = json_answer(&json!({ "principal": claim.principal }), &NO_STORE);
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie(&begun.session.reveal(), SESSION_LIFETIME_SECS)?,
    );
    Ok(response)
}

/// `POST /sign-out`: ends the session here, whatever the browser does with the cookie. The
/// extractor has made the `Origin` check, and charges a session nothing. A token has no session
/// to end.
pub(super) async fn sign_out(
    State(state): State<ApiState>,
    Leaving { principal, session }: Leaving,
) -> Result<Response, HumanProblem> {
    let Some(session) = session else {
        let event = AuditEvent {
            kind: EventKind::AccessRefused,
            deployment: None,
            host: None,
            detail: json!({
                "by": principal.audited(),
                "reason": "a sign-out with no session to end",
            }),
        };
        state.store().record(&event).await?;
        return Err(HumanProblem::Forbidden);
    };
    state.store().end_session(principal.id(), &session).await?;
    state.forget_sessions(&[session.hash()]);
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie("", 0)?);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}
