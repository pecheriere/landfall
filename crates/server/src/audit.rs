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

/// What an event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind {
    /// An enrolment code was issued for a host.
    EnrolCodeIssued,
    /// A host enrolled its key.
    HostEnrolled,
    /// A release was seen and verified or refused.
    ReleaseSeen,
    /// The rules decided about a release.
    RuleDecision,
    /// A release or a deployment could not be decided about yet, and why.
    ReleaseHeld,
    /// A deploy was queued for a host.
    DeployQueued,
    /// A host claimed a deploy.
    DeployClaimed,
    /// A host reported a deploy finished, with its steps.
    DeployFinished,
    /// A host refused a deploy because its own configuration or state does not
    /// allow it, with its reason. This is the signal of a controller asking for
    /// something a host won't allow, so it has its own kind: treat it as an
    /// alert.
    DeployRefused,
    /// A host's configuration hash began or stopped differing from the
    /// controller's.
    ConfigDrift,
    /// A host reported that a deployment began or stopped differing from what
    /// the agent deployed.
    RunningDrift,
    /// A host reported a different release deployed for a deployment.
    RunningChanged,
    /// A host reported a state that cannot be: idle, and busy with a deploy.
    RunningInconsistent,
    /// Someone holding a valid enrolment code was refused.
    EnrolRefused,
    /// A signed report was refused: for a deploy that is not the signer's, or
    /// one never handed out.
    ReportRefused,
}

impl EventKind {
    /// The stable name stored in the log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnrolCodeIssued => "enrol_code_issued",
            Self::HostEnrolled => "host_enrolled",
            Self::ReleaseSeen => "release_seen",
            Self::RuleDecision => "rule_decision",
            Self::ReleaseHeld => "release_held",
            Self::DeployQueued => "deploy_queued",
            Self::DeployClaimed => "deploy_claimed",
            Self::DeployFinished => "deploy_finished",
            Self::DeployRefused => "deploy_refused",
            Self::ConfigDrift => "config_drift",
            Self::RunningDrift => "running_drift",
            Self::RunningChanged => "running_changed",
            Self::RunningInconsistent => "running_inconsistent",
            Self::EnrolRefused => "enrol_refused",
            Self::ReportRefused => "report_refused",
        }
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
    use super::*;

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
