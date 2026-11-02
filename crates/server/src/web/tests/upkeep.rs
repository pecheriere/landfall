//! That counted failures reach the log, by the task `serve` runs, and what's past its time goes.

use std::time::{Duration, Instant};

use landfall_approval::{Ceremony, SoftwareAuthenticator};
use tokio::sync::watch;

use super::{Harness, ORIGIN, RP_ID, SIGN_IN_FINISH, sign_in_ceremony_body};
use crate::auth::keep_flushing;

/// One signature that doesn't verify, on alice's credential.
async fn fail_a_sign_in(h: &Harness) {
    let stranger = SoftwareAuthenticator::es256().unwrap();
    let challenge = h.begin_sign_in().await;
    let mut forged = Ceremony::new(RP_ID, ORIGIN, &challenge);
    forged.credential_id = Some(h.alice.credential_id().to_vec());
    let answer = h
        .post(
            SIGN_IN_FINISH,
            None,
            &sign_in_ceremony_body(&stranger, &challenge, &forged),
        )
        .await;
    assert_eq!(answer.code(), "sign_in_refused");
}

#[tokio::test]
async fn counts_are_written_each_interval() {
    let h = Harness::new().await;
    fail_a_sign_in(&h).await;
    let (stop, stopped) = watch::channel(false);
    let flushing = tokio::spawn(keep_flushing(
        h.state.clone(),
        Duration::from_millis(5),
        stopped,
    ));
    let started = Instant::now();
    while h.audited("sign_in_refused").await.is_empty() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "nothing was written"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stop.send_replace(true);
    flushing.await.unwrap();
    assert_eq!(h.audited("sign_in_refused").await[0]["attempts"], 1);
}

#[tokio::test]
async fn counts_are_written_at_stop() {
    let h = Harness::new().await;
    fail_a_sign_in(&h).await;
    let (stop, stopped) = watch::channel(false);
    let flushing = tokio::spawn(keep_flushing(
        h.state.clone(),
        Duration::from_hours(1),
        stopped,
    ));
    stop.send_replace(true);
    flushing.await.unwrap();
    assert_eq!(h.audited("sign_in_refused").await[0]["attempts"], 1);
}

#[tokio::test]
async fn a_count_that_cannot_be_written_waits_and_grows() {
    let h = Harness::new().await;
    fail_a_sign_in(&h).await;
    sqlx::query(
        "CREATE TRIGGER no_refused BEFORE INSERT ON audit_events
         WHEN NEW.kind = 'sign_in_refused'
         BEGIN SELECT RAISE(ABORT, 'not now'); END",
    )
    .execute(h.store.pool())
    .await
    .unwrap();
    crate::web::tend(&h.state).await;
    fail_a_sign_in(&h).await;
    sqlx::query("DROP TRIGGER no_refused")
        .execute(h.store.pool())
        .await
        .unwrap();
    crate::web::tend(&h.state).await;
    let rows = h.audited("sign_in_refused").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["attempts"], 2);
}

#[tokio::test]
async fn upkeep_lets_go_of_challenges_past_their_time() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    h.begin_sign_in().await;
    h.begin_registration(&code).await;
    crate::web::tend(&h.state).await;
    assert_eq!(h.state.ceremonies().held(), (1, 1));

    h.clock.advance(5 * 60);
    crate::web::tend(&h.state).await;
    assert_eq!(h.state.ceremonies().held(), (0, 0));
}
