//! Hosts and their keys, enrolment codes in use, and request nonces.

use landfall_core::ids::HostId;
use landfall_core::protocol::{EnrolCode as WireEnrolCode, Nonce, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{Store, StoreError};
use crate::audit::{AuditEvent, EventKind};

/// How long a nonce stays valid, by the controller's own clock, in seconds.
pub const NONCE_LIFETIME_SECS: i64 = 5 * 60;

impl Store {
    /// Enrols `key` for `host` with a one-time code, or replaces its key if the
    /// code was issued with `--replace`. The code is used up only if all of it
    /// succeeds. Recorded in the audit log, without the code.
    ///
    /// # Errors
    /// [`StoreError::InvalidCode`] for a code that is unknown, used, expired or
    /// bound to another host; [`StoreError::AlreadyEnrolled`] if the host has a
    /// key and the code does not allow replacing it; [`StoreError::KeyInUse`]
    /// if another host has this key; otherwise a clock or database failure.
    pub async fn enrol(
        &self,
        host: &HostId,
        code: &WireEnrolCode,
        key: &VerifyingKey,
    ) -> Result<(), StoreError> {
        let code_hash: [u8; 32] = Sha256::digest(code.as_bytes()).into();
        let now = self.clock.now()?;
        let host_id = host.as_ref();
        let public_key = key.as_bytes().as_slice();

        let mut tx = self.begin().await?;
        let replace: Option<bool> = sqlx::query_scalar(
            "DELETE FROM enrol_codes WHERE code_hash = ? AND host = ? AND expires_at > ?
             RETURNING replace",
        )
        .bind(code_hash.as_slice())
        .bind(host_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(replace) = replace else {
            return Err(StoreError::InvalidCode);
        };
        let previous: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT public_key FROM hosts WHERE id = ?")
                .bind(host_id)
                .fetch_optional(&mut *tx)
                .await?;
        if previous.is_some() && !replace {
            return Err(StoreError::AlreadyEnrolled(host.clone()));
        }
        let holder: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM hosts WHERE public_key = ? AND id <> ?")
                .bind(public_key)
                .bind(host_id)
                .fetch_optional(&mut *tx)
                .await?;
        if holder.is_some() {
            return Err(StoreError::KeyInUse);
        }
        sqlx::query(
            "INSERT INTO hosts (id, public_key, enrolled_at) VALUES (?, ?, ?)
             ON CONFLICT (id) DO UPDATE SET
                 public_key = excluded.public_key, enrolled_at = excluded.enrolled_at",
        )
        .bind(host_id)
        .bind(public_key)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let event = AuditEvent {
            kind: EventKind::HostEnrolled,
            deployment: None,
            host: Some(host.clone()),
            detail: json!({
                "public_key": hex::encode(key.as_bytes()),
                "replaced_key": previous.as_deref().map(hex::encode),
            }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The key enrolled for `host`, if there is one.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] if the stored key is not a valid key; otherwise
    /// a database failure.
    pub async fn host_key(&self, host: &HostId) -> Result<Option<VerifyingKey>, StoreError> {
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT public_key FROM hosts WHERE id = ?")
                .bind(host.as_ref())
                .fetch_optional(&self.pool)
                .await?;
        stored
            .map(|bytes| {
                VerifyingKey::try_from(bytes.as_slice())
                    .map_err(|_| StoreError::Corrupt("host public key"))
            })
            .transpose()
    }

    /// Issues a single-use nonce, valid for [`NONCE_LIFETIME_SECS`]. Nonces are
    /// not audited: anyone may ask for one, and nothing has changed until one
    /// is used by a request that is.
    ///
    /// # Errors
    /// [`StoreError::NonceTableFull`] if `max_outstanding` unexpired nonces are
    /// outstanding: a full table refuses rather than grows. Otherwise a clock,
    /// random generator or database failure.
    pub async fn issue_nonce(&self, max_outstanding: u64) -> Result<Nonce, StoreError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(StoreError::Random)?;
        let now = self.clock.now()?;

        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM nonces WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let outstanding: i64 = sqlx::query_scalar("SELECT count(*) FROM nonces")
            .fetch_one(&mut *tx)
            .await?;
        if u64::try_from(outstanding).map_err(|_| StoreError::Corrupt("nonce count"))?
            >= max_outstanding
        {
            return Err(StoreError::NonceTableFull);
        }
        sqlx::query("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)")
            .bind(nonce.as_slice())
            .bind(now.saturating_add(NONCE_LIFETIME_SECS))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Nonce::from_bytes(nonce))
    }

    /// Uses up `nonce`. Whether it was outstanding and unexpired; either way it
    /// cannot be used again.
    ///
    /// # Errors
    /// A clock or database failure.
    pub async fn consume_nonce(&self, nonce: &Nonce) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM nonces WHERE nonce = ? AND expires_at > ?")
            .bind(nonce.as_bytes().as_slice())
            .bind(self.clock.now()?)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}
