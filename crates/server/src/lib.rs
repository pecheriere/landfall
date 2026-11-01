//! The landfall controller: watches releases, verifies their origin, keeps
//! state and the audit log, and coordinates the agents.

pub mod agent_api;
pub mod audit;
pub mod cli;
pub mod report;
pub mod serve;
pub mod store;
pub mod watcher;

use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

/// Release origin verification, which the controller runs before it decides
/// anything about a release.
pub use landfall_origin as origin;

use crate::agent_api::ApiState;
use crate::store::Store;

/// How long a health check may take: unauthenticated, and only worth anything
/// if it answers quickly.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Answers 200 when the store answers, and 503 when it does not.
async fn healthz(State(store): State<Store>) -> StatusCode {
    match tokio::time::timeout(HEALTH_TIMEOUT, store.ping()).await {
        Ok(Ok(())) => StatusCode::OK,
        Ok(Err(_)) | Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The controller's HTTP routes.
pub fn router(state: ApiState) -> Router {
    let health = Router::new()
        .route("/healthz", get(healthz))
        .with_state(state.store().clone());
    health.merge(agent_api::router(state))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use landfall_core::config;
    use tower::ServiceExt as _;

    use super::*;
    use crate::agent_api::Limits;

    const CONFIG: &str = r#"
[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }
"#;

    fn app(store: Store) -> Router {
        let config = config::parse(CONFIG.as_bytes()).unwrap();
        router(ApiState::new(store, config, Limits::default()))
    }

    fn get_healthz() -> Request<Body> {
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn healthz_follows_the_store() {
        let store = Store::open_in_memory().await.unwrap();
        let app = app(store.clone());
        let answer = app.clone().oneshot(get_healthz()).await.unwrap();
        assert_eq!(answer.status(), StatusCode::OK);

        store.close().await;
        let answer = app.oneshot(get_healthz()).await.unwrap();
        assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn other_paths_are_not_found() {
        let store = Store::open_in_memory().await.unwrap();
        let request = Request::builder()
            .uri("/nothing")
            .body(Body::empty())
            .unwrap();
        let answer = app(store).oneshot(request).await.unwrap();
        assert_eq!(answer.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_agent_api_is_served() {
        let store = Store::open_in_memory().await.unwrap();
        let request = Request::builder()
            .uri("/agent/v1/nonce")
            .body(Body::empty())
            .unwrap();
        let answer = app(store).oneshot(request).await.unwrap();
        assert_eq!(answer.status(), StatusCode::OK);
    }
}
