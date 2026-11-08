//! The audit log's events and its hash chain.
//!
//! Each row of `audit_events` holds `hash = sha256(prev_hash || canonical
//! bytes)`, where `prev_hash` is the previous row's `hash` and 32 zero bytes for
//! the first row. The canonical bytes are the ASCII bytes `landfall-audit-v1`,
//! then `seq`, `ts`, `kind`, `deployment`, `host` and `detail` in that order,
//! each as a 4-byte big-endian length and the field's bytes: `seq` and `ts` as
//! 8 big-endian bytes, text as the UTF-8 stored in the row, and `deployment` and
//! `host` preceded by one byte saying whether they are present. The encoding is
//! a storage contract: a change makes every existing log fail verification, so
//! it never changes without bumping the prefix.
//!
//! The chain finds a row edited, reordered or deleted from the middle by anyone
//! who did not also rewrite every later row. It holds no secret and nothing
//! outside the database vouches for it, so it cannot show:
//!
//! - rows removed from the end, if the sequence record is lowered to match (one
//!   more statement) or the table is dropped and made again;
//! - a rollback: an older backup of the database restored over the current one
//!   verifies clean;
//! - a complete new history forged by someone who can write the whole database.
//!
//! Only a head kept elsewhere shows these: `audit verify` prints the last row's
//! `seq` and `hash`, and `audit verify --at <seq>` later must print that hash.

use std::str::FromStr;

use landfall_core::ids::{DeploymentId, HostId};
use sha2::{Digest, Sha256};

/// Domain-separation prefix of the canonical encoding.
const DOMAIN: &[u8] = b"landfall-audit-v1";

/// `prev_hash` of the first row.
pub(crate) const GENESIS: [u8; 32] = [0; 32];

/// The longest `detail` the log accepts, in bytes of JSON. Whoever records
/// something an agent sent bounds it first; this is the backstop, so that a
/// single event cannot grow the database without limit.
pub const MAX_DETAIL_BYTES: usize = 64 * 1024;

/// Declares [`EventKind`] from one list of its variants, each with the stable name stored in
/// the log: [`EventKind::as_str`] and its `FromStr` both read this list, so a kind can't have
/// a name one way and not the other.
macro_rules! event_kinds {
    ($($(#[doc = $doc:literal])* $variant:ident = $name:literal,)*) => {
        /// What an event records.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum EventKind {
            $($(#[doc = $doc])* $variant,)*
        }

        impl EventKind {
            /// Every kind.
            const ALL: &[Self] = &[$(Self::$variant,)*];

            /// The stable name stored in the log.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }
        }
    };
}

event_kinds! {
    /// An enrolment code was issued for a host.
    EnrolCodeIssued = "enrol_code_issued",
    /// A host enrolled its key.
    HostEnrolled = "host_enrolled",
    /// A release was seen and verified or refused.
    ReleaseSeen = "release_seen",
    /// The rules decided about a release.
    RuleDecision = "rule_decision",
    /// A release or a deployment could not be decided about yet, and why.
    ReleaseHeld = "release_held",
    /// A deploy was queued for a host.
    DeployQueued = "deploy_queued",
    /// A host claimed a deploy.
    DeployClaimed = "deploy_claimed",
    /// A host reported a deploy finished, with its steps.
    DeployFinished = "deploy_finished",
    /// A host refused a deploy because its own configuration or state does not
    /// allow it, with its reason. This is the signal of a controller asking for
    /// something a host won't allow, so it has its own kind: treat it as an
    /// alert.
    DeployRefused = "deploy_refused",
    /// A host's configuration hash began or stopped differing from the
    /// controller's.
    ConfigDrift = "config_drift",
    /// A host reported that a deployment began or stopped differing from what
    /// the agent deployed.
    RunningDrift = "running_drift",
    /// A host reported a different release deployed for a deployment.
    RunningChanged = "running_changed",
    /// A host reported a state that cannot be: idle, and busy with a deploy.
    RunningInconsistent = "running_inconsistent",
    /// Someone holding a valid enrolment code was refused.
    EnrolRefused = "enrol_refused",
    /// A signed report was refused: for a deploy that is not the signer's, or
    /// one never handed out.
    ReportRefused = "report_refused",
    /// An API token was made for a principal.
    TokenCreated = "token_created",
    /// An API token was revoked.
    TokenRevoked = "token_revoked",
    /// A one-time link to register a passkey was issued.
    PasskeyInviteIssued = "passkey_invite_issued",
    /// Someone who proved who they are was refused before any particular action.
    AccessRefused = "access_refused",
    /// A principal asked for a deploy, and the intent for it was made.
    DeployRequested = "deploy_requested",
    /// A principal's request for a deploy was refused.
    RequestRefused = "request_refused",
    /// A verified assertion approved a request, and its deploy was queued.
    RequestApproved = "request_approved",
    /// A principal's approval was refused.
    ApprovalRefused = "approval_refused",
    /// A request can't be approved any more: what it was made from changed.
    RequestStale = "request_stale",
    /// A request waited too long for an approver.
    RequestExpired = "request_expired",
    /// A request was cancelled, by someone or by a rollback taking its place.
    RequestCancelled = "request_cancelled",
    /// A principal's cancelling of a request was refused.
    CancelRefused = "cancel_refused",
    /// A principal came back within its budget: this many calls were refused without a row.
    AccessThrottled = "access_throttled",
    /// A passkey was registered with an invite's code.
    PasskeyRegistered = "passkey_registered",
    /// Registering with a good code failed, this many times since the last such row.
    RegistrationRefused = "registration_refused",
    /// A person signed in, and a session began.
    SignedIn = "signed_in",
    /// Signing in as a principal failed, this many times since the last such row.
    SignInRefused = "sign_in_refused",
    /// A signature verified by a key that may not sign in, this many times since the last such
    /// row: someone holds a key registered for this principal. Treat it as an alert.
    SignInBarredKey = "sign_in_barred_key",
    /// A person signed out, and their session ended.
    SignedOut = "signed_out",
}

/// A name no [`EventKind`] has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no audit event kind has this name")]
pub struct UnknownEventKind;

impl FromStr for EventKind {
    type Err = UnknownEventKind;

    /// The kind whose stable name is `name`, exactly.
    fn from_str(name: &str) -> Result<Self, UnknownEventKind> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == name)
            .ok_or(UnknownEventKind)
    }
}

/// Something worth recording. `detail` must never hold a secret: enrolment
/// codes, keys and tokens stay out of it.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    /// What happened.
    pub kind: EventKind,
    /// The deployment it concerns, if any.
    pub deployment: Option<DeploymentId>,
    /// The host it concerns, if any.
    pub host: Option<HostId>,
    /// The particulars.
    pub detail: serde_json::Value,
}

/// The result of walking the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// How many rows the log holds.
    pub rows: u64,
    /// The `seq` of the first row that does not follow from the ones before
    /// it, or, when the rows all follow but the database's record of them
    /// disagrees, the `seq` after the last good row; `None` when the whole
    /// chain is intact.
    pub first_bad: Option<u64>,
    /// The `seq` of the last row as stored, whether or not it is good; `None`
    /// for an empty log.
    pub head_seq: Option<i64>,
    /// The `hash` of the last row as stored, in lowercase hex; `None` for an
    /// empty log.
    pub head_hash: Option<String>,
}

/// The hashed fields of a row, as stored. Bytes rather than text, so verifying
/// covers exactly what is in the file, whatever someone may have written there.
pub(crate) struct RowFields<'a> {
    pub(crate) seq: i64,
    pub(crate) ts: i64,
    pub(crate) kind: &'a [u8],
    pub(crate) deployment: Option<&'a [u8]>,
    pub(crate) host: Option<&'a [u8]>,
    pub(crate) detail: &'a [u8],
}

/// Appends `field` as a 4-byte big-endian length followed by its bytes.
///
/// `SQLite` refuses a value longer than 1,000,000,000 bytes at most (its
/// `SQLITE_MAX_LENGTH` cannot be raised further than 2^31 - 1), so the low four
/// bytes of the length are the whole length and nothing is truncated.
fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    let [.., a, b, c, d] = field.len().to_be_bytes();
    out.extend_from_slice(&[a, b, c, d]);
    out.extend_from_slice(field);
}

/// Appends a presence byte, then the field if there is one, so an absent value
/// and an empty one encode differently.
fn push_optional(out: &mut Vec<u8>, field: Option<&[u8]>) {
    match field {
        Some(field) => {
            out.push(1);
            push_field(out, field);
        }
        None => out.push(0),
    }
}

impl RowFields<'_> {
    /// The canonical encoding described in the module documentation.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = DOMAIN.to_vec();
        push_field(&mut out, &self.seq.to_be_bytes());
        push_field(&mut out, &self.ts.to_be_bytes());
        push_field(&mut out, self.kind);
        push_optional(&mut out, self.deployment);
        push_optional(&mut out, self.host);
        push_field(&mut out, self.detail);
        out
    }

    /// This row's `hash`, following `prev_hash`.
    pub(crate) fn hash(&self, prev_hash: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash);
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::{EventKind, GENESIS, RowFields, UnknownEventKind};

    #[test]
    fn every_kind_is_read_back_by_its_name_alone() {
        assert_eq!(EventKind::ALL.len(), 34);
        for kind in EventKind::ALL {
            assert_eq!(kind.as_str().parse(), Ok(*kind));
        }
        for name in [
            "",
            "teleported",
            "Deploy_Queued",
            "deploy_queued ",
            "deployqueued",
        ] {
            assert_eq!(name.parse::<EventKind>(), Err(UnknownEventKind), "{name:?}");
        }
    }

    fn fields() -> RowFields<'static> {
        RowFields {
            seq: 1,
            ts: 1_800_000_000,
            kind: b"deploy_queued",
            deployment: Some(b"app/prod"),
            host: Some(b"host-a"),
            detail: br#"{"tag":"v1.2.4"}"#,
        }
    }

    /// Pins the encoding and the hash: a change here breaks verification of
    /// every existing log.
    #[test]
    fn hash_is_stable() {
        let mut expected = b"landfall-audit-v1".to_vec();
        let mut field = |bytes: &[u8]| {
            expected.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
            expected.extend_from_slice(bytes);
        };
        field(&1_i64.to_be_bytes());
        field(&1_800_000_000_i64.to_be_bytes());
        field(b"deploy_queued");
        expected.push(1);
        expected.extend_from_slice(&8_u32.to_be_bytes());
        expected.extend_from_slice(b"app/prod");
        expected.push(1);
        expected.extend_from_slice(&6_u32.to_be_bytes());
        expected.extend_from_slice(b"host-a");
        expected.extend_from_slice(&16_u32.to_be_bytes());
        expected.extend_from_slice(br#"{"tag":"v1.2.4"}"#);

        let row = fields();
        assert_eq!(row.canonical_bytes(), expected);
        assert_eq!(hex::encode(row.hash(&GENESIS)), PINNED);
    }

    /// Computed separately from this code, from the encoding as documented.
    const PINNED: &str = "3a3285be0671836ea4f789810a0cc1b7b2b50aba309ad826350e5528e8706fc7";

    #[test]
    fn moving_bytes_between_fields_changes_the_hash() {
        let base = fields().hash(&GENESIS);
        let shifted = RowFields {
            deployment: Some(b"app/pro"),
            host: Some(b"dhost-a"),
            ..fields()
        };
        assert_ne!(shifted.hash(&GENESIS), base);
    }

    #[test]
    fn an_absent_field_differs_from_an_empty_one() {
        let absent = RowFields {
            host: None,
            ..fields()
        };
        let empty = RowFields {
            host: Some(b""),
            ..fields()
        };
        assert_ne!(absent.hash(&GENESIS), empty.hash(&GENESIS));
    }

    #[test]
    fn the_hash_depends_on_the_previous_row() {
        assert_ne!(fields().hash(&GENESIS), fields().hash(&[1; 32]));
    }
}
