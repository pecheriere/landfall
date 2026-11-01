//! The landfall controller: watches releases, verifies their origin, keeps
//! state and the audit log, and coordinates the agents.

pub mod audit;
pub mod cli;
pub mod store;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

/// Release origin verification, which the controller runs before it decides
/// anything about a release.
pub use landfall_origin as origin;

use crate::store::Store;

/// Answers 200 when the store answers, and 503 when it does not.
async fn healthz(State(store): State<Store>) -> StatusCode {
    match store.ping().await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The controller's HTTP routes.
pub fn router(store: Store) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .with_state(store)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;

    fn get_healthz() -> Request<Body> {
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn healthz_follows_the_store() {
        let store = Store::open_in_memory().await.unwrap();
        let app = router(store.clone());
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
        let answer = router(store).oneshot(request).await.unwrap();
        assert_eq!(answer.status(), StatusCode::NOT_FOUND);
    }
}
