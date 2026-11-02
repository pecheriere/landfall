//! What registering and signing in leave behind: the stored passkey, and sessions.

use landfall_approval::CoseKey;
use landfall_core::ids::PrincipalId;
use serde_json::json;
use sqlx::Row as _;

use super::{Store, StoreError};
use crate::audit::{AuditEvent, EventKind};
use crate::auth::{PasskeyInvite, SessionToken};

/// How long a session lasts, in seconds: twelve hours.
pub const SESSION_LIFETIME_SECS: i64 = 12 * 60 * 60;

/// How many sessions one principal keeps. Signing in anew past this ends the oldest, so a
/// passkey signing in over and over can't grow the table.
const MAX_SESSIONS_PER_PRINCIPAL: i64 = 16;

/// A key to keep, out of a checked registration.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NewPasskey<'a> {
    pub(crate) credential_id: &'a [u8],
    pub(crate) key: &'a CoseKey,
}

/// What redeeming an invite came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Redeemed {
    /// The key is stored, and the invite is spent.
    Registered {
        /// Whose it is.
        principal: PrincipalId,
    },
    /// The code is wrong, used or expired.
    InviteGone,
    /// Another principal already holds this credential id. The invite is not spent.
    CredentialTaken,
}

/// A key registered here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredPasskey {
    pub(crate) principal: PrincipalId,
    pub(crate) public_key: Vec<u8>,
}

fn principal_from(text: &str) -> Result<PrincipalId, StoreError> {
    text.parse().map_err(|_| StoreError::Corrupt("principal"))
}

impl Store {
    /// Who this invite is for, if it is still good. Found by its hash, so the time this takes
    /// says nothing about the code.
    pub(crate) async fn invite_holder(
        &self,
        invite: &PasskeyInvite,
    ) -> Result<Option<PrincipalId>, StoreError> {
        let principal: Option<String> = sqlx::query_scalar(
            "SELECT principal FROM passkey_invites WHERE code_hash = ? AND expires_at > ?",
        )
        .bind(invite.hash().as_slice())
        .bind(self.clock.now()?)
        .fetch_optional(&self.pool)
        .await?;
        principal.as_deref().map(principal_from).transpose()
    }

    /// Spends the invite and keeps the key, with its audit row, in one transaction: of any
    /// number at once, one does it. Registering again replaces the principal's key and ends
    /// their sessions, since whoever lost the last key may be why. Keeping a key here gives
    /// nobody anything by itself: see `web::sign_in` for what it opens.
    pub(crate) async fn redeem_invite(
        &self,
        invite: &PasskeyInvite,
        passkey: &NewPasskey<'_>,
    ) -> Result<Redeemed, StoreError> {
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        let holder: Option<String> = sqlx::query_scalar(
            "DELETE FROM passkey_invites WHERE code_hash = ? AND expires_at > ?
             RETURNING principal",
        )
        .bind(invite.hash().as_slice())
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(holder) = holder else {
            return Ok(Redeemed::InviteGone);
        };
        let taken: Option<String> =
            sqlx::query_scalar("SELECT principal FROM passkeys WHERE credential_id = ?")
                .bind(passkey.credential_id)
                .fetch_optional(&mut *tx)
                .await?;
        if taken.is_some_and(|owner| owner != holder) {
            // Dropping the transaction keeps the invite.
            return Ok(Redeemed::CredentialTaken);
        }
        let replaced: Option<Vec<u8>> =
            sqlx::query_scalar("DELETE FROM passkeys WHERE principal = ? RETURNING public_key")
                .bind(&holder)
                .fetch_optional(&mut *tx)
                .await?;
        sqlx::query(
            "INSERT INTO passkeys (credential_id, principal, public_key, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(passkey.credential_id)
        .bind(&holder)
        .bind(passkey.key.as_bytes())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM sessions WHERE principal = ?")
            .bind(&holder)
            .execute(&mut *tx)
            .await?;
        let replaced = replaced
            .as_deref()
            .and_then(|bytes| CoseKey::parse(bytes).ok())
            .map(|key| key.fingerprint());
        let event = AuditEvent {
            kind: EventKind::PasskeyRegistered,
            deployment: None,
            host: None,
            detail: json!({
                "principal": holder,
                "fingerprint": passkey.key.fingerprint(),
                "replaced_fingerprint": replaced,
            }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(Redeemed::Registered {
            principal: principal_from(&holder)?,
        })
    }

    /// The key registered here under this credential id, if any.
    pub(crate) async fn stored_passkey(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, StoreError> {
        let row = sqlx::query("SELECT principal, public_key FROM passkeys WHERE credential_id = ?")
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(StoredPasskey {
                principal: principal_from(row.try_get::<&str, _>("principal")?)?,
                public_key: row.try_get("public_key")?,
            })
        })
        .transpose()
    }

    /// Begins a session for someone who just proved who they are, with its audit row. The
    /// token is always new. A session the browser came with ends here, whoever's it was: it is
    /// that browser's, and it is about to be overwritten. `how` says whose key opened it.
    pub(crate) async fn begin_session(
        &self,
        principal: &PrincipalId,
        how: &'static str,
        came_with: Option<&SessionToken>,
    ) -> Result<SessionToken, StoreError> {
        let session = SessionToken::random().map_err(StoreError::Random)?;
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        if let Some(old) = came_with {
            sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
                .bind(old.hash().as_slice())
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "INSERT INTO sessions (token_hash, principal, created_at, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(session.hash().as_slice())
        .bind(principal.as_ref())
        .bind(now)
        .bind(now.saturating_add(SESSION_LIFETIME_SECS))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM sessions WHERE principal = ?1 AND token_hash NOT IN (
                 SELECT token_hash FROM sessions WHERE principal = ?1
                 ORDER BY created_at DESC, rowid DESC LIMIT ?2
             )",
        )
        .bind(principal.as_ref())
        .bind(MAX_SESSIONS_PER_PRINCIPAL)
        .execute(&mut *tx)
        .await?;
        let event = AuditEvent {
            kind: EventKind::SignedIn,
            deployment: None,
            host: None,
            detail: json!({ "principal": principal, "how": how }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(session)
    }

    /// Ends a session server-side, with its audit row.
    pub(crate) async fn end_session(
        &self,
        principal: &PrincipalId,
        session: &SessionToken,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(session.hash().as_slice())
            .execute(&mut *tx)
            .await?;
        let event = AuditEvent {
            kind: EventKind::SignedOut,
            deployment: None,
            host: None,
            detail: json!({ "principal": principal }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Clears out sessions and invites past their time, which nothing can use any more. They
    /// end by the clock whether this runs or not, so there is nothing to audit.
    pub(crate) async fn settle_ceremonies(&self) -> Result<(), StoreError> {
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM passkey_invites WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
