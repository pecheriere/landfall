//! API tokens, passkey invites and sessions, each kept only as a SHA-256.

use landfall_core::ids::PrincipalId;
use serde_json::json;
use sqlx::Row as _;

use super::{Store, StoreError};
use crate::audit::{AuditEvent, EventKind};
use crate::auth::{ApiToken, PasskeyInvite, SessionToken};

/// How long a passkey invite stays valid, in seconds.
const PASSKEY_INVITE_LIFETIME_SECS: i64 = 60 * 60;

impl Store {
    /// Makes an API token for `principal`, with its audit row. This is the only time the
    /// token exists outside the holder's hands. Gives its id, which isn't a secret.
    ///
    /// # Errors
    /// A random generator, clock, database or audit failure.
    pub async fn create_token(
        &self,
        principal: &PrincipalId,
    ) -> Result<(i64, ApiToken), StoreError> {
        let token = ApiToken::random().map_err(StoreError::Random)?;
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (token_hash, principal, created_at) VALUES (?, ?, ?)
             RETURNING id",
        )
        .bind(token.hash().as_slice())
        .bind(principal.as_ref())
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        let event = AuditEvent {
            kind: EventKind::TokenCreated,
            deployment: None,
            host: None,
            detail: json!({ "token": id, "principal": principal }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok((id, token))
    }

    /// Revokes a token by its id, from its next use on, with its audit row. Gives whether
    /// this did it: one already revoked stays as it is and adds no row.
    ///
    /// # Errors
    /// [`StoreError::UnknownToken`] if there is no such token; otherwise a clock, database
    /// or audit failure.
    pub async fn revoke_token(&self, id: i64) -> Result<bool, StoreError> {
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        let row = sqlx::query("SELECT principal, revoked_at FROM api_tokens WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::UnknownToken)?;
        if row.try_get::<Option<i64>, _>("revoked_at")?.is_some() {
            return Ok(false);
        }
        sqlx::query("UPDATE api_tokens SET revoked_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let event = AuditEvent {
            kind: EventKind::TokenRevoked,
            deployment: None,
            host: None,
            detail: json!({ "token": id, "principal": row.try_get::<String, _>("principal")? }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// The id and principal of this token, if it exists and isn't revoked. Found by its
    /// hash, so the time this takes says nothing about the token.
    pub(crate) async fn token_holder(
        &self,
        token: &ApiToken,
    ) -> Result<Option<(i64, PrincipalId)>, StoreError> {
        let row = sqlx::query(
            "SELECT id, principal FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(token.hash().as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let id = row.try_get("id")?;
            Ok((id, stored_principal(row.try_get::<&str, _>("principal")?)?))
        })
        .transpose()
    }

    /// The principal of this session, if it exists and hasn't expired by the controller's
    /// clock. Found by its hash, like a token.
    pub(crate) async fn session_holder(
        &self,
        session: &SessionToken,
    ) -> Result<Option<PrincipalId>, StoreError> {
        let principal: Option<String> = sqlx::query_scalar(
            "SELECT principal FROM sessions WHERE token_hash = ? AND expires_at > ?",
        )
        .bind(session.hash().as_slice())
        .bind(self.clock.now()?)
        .fetch_optional(&self.pool)
        .await?;
        principal.as_deref().map(stored_principal).transpose()
    }

    /// A session row as sign-in would write it, for a test.
    #[cfg(test)]
    pub(crate) async fn begin_session_for_test(&self, principal: &str, lasts: i64) -> SessionToken {
        let session = SessionToken::random_for_test();
        let now = self.clock.now().unwrap();
        sqlx::query(
            "INSERT INTO sessions (token_hash, principal, created_at, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(session.hash().as_slice())
        .bind(principal)
        .bind(now)
        .bind(now + lasts)
        .execute(&self.pool)
        .await
        .unwrap();
        session
    }

    /// Issues a one-time code to register a passkey for `principal`, valid for an hour. It
    /// replaces any code still outstanding for them, and is in the audit log, without the
    /// code.
    ///
    /// # Errors
    /// A random generator, clock, database or audit failure.
    pub async fn issue_passkey_invite(
        &self,
        principal: &PrincipalId,
    ) -> Result<PasskeyInvite, StoreError> {
        let invite = PasskeyInvite::random().map_err(StoreError::Random)?;
        let now = self.clock.now()?;
        let expires_at = now.saturating_add(PASSKEY_INVITE_LIFETIME_SECS);
        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM passkey_invites WHERE principal = ? OR expires_at <= ?")
            .bind(principal.as_ref())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO passkey_invites (code_hash, principal, expires_at) VALUES (?, ?, ?)",
        )
        .bind(invite.hash().as_slice())
        .bind(principal.as_ref())
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        let event = AuditEvent {
            kind: EventKind::PasskeyInviteIssued,
            deployment: None,
            host: None,
            detail: json!({ "principal": principal, "expires_at": expires_at }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(invite)
    }

    /// Records one event on its own, for what changes nothing but the log.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub async fn record(&self, event: &AuditEvent) -> Result<(), StoreError> {
        let mut tx = self.begin().await?;
        self.append(&mut tx, event).await?;
        tx.commit().await?;
        Ok(())
    }
}

fn stored_principal(text: &str) -> Result<PrincipalId, StoreError> {
    text.parse().map_err(|_| StoreError::Corrupt("principal"))
}
