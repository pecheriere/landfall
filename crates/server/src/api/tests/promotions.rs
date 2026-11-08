//! Promotions in `getDeployment`: a deployment the reader can't view is never named, and
//! neither is how many of them there are.

use std::fmt::Write as _;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::SoftwareAuthenticator;
use serde_json::{Value, json};

use super::deployments::{deployment, grant};
use super::{WORLD_ORIGIN, answer};
use crate::agent_api::{ApiState, Limits};
use crate::store::Store;

/// `app/one`, `app/two` and `app/three` each promote to `app/target`, after one, two and three
/// hours. `peek` may view `app/target` and `app/two`; `seer` may view all four.
fn config(key: &SoftwareAuthenticator) -> String {
    let mut text = format!(
        "[approval]\nrp_id = \"landfall.example.com\"\norigin = \"{WORLD_ORIGIN}\"\n\n\
         [approvers]\noperator = {{ credential_id = \"{}\", public_key = \"{}\" }}\n",
        URL_SAFE_NO_PAD.encode(key.credential_id()),
        URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
    );
    let repo = ("example/app", 7);
    for (source, hours) in [("app/one", 1), ("app/two", 2), ("app/three", 3)] {
        text.push_str(&deployment(source, repo, "home-1", "\"operator\""));
        writeln!(
            text,
            "promote_to = {{ deployment = \"app/target\", healthy_for = \"{hours}h\" }}"
        )
        .unwrap();
    }
    text.push_str(&deployment("app/target", repo, "home-1", "\"operator\""));
    text.push_str(&grant("peek", &["app/target", "app/two"], &["view"]));
    let all = ["app/one", "app/two", "app/three", "app/target"];
    text.push_str(&grant("seer", &all, &["view"]));
    text
}

/// `getDeployment` of `app/target`, as `name`'s token reads it.
async fn target_as(name: &str) -> (Value, String) {
    let key = SoftwareAuthenticator::es256().unwrap();
    let config = landfall_approval::parse_config(config(&key).as_bytes()).unwrap();
    let store = Store::open_in_memory().await.unwrap();
    let (_, token) = store.create_token(&name.parse().unwrap()).await.unwrap();
    let app = crate::router(ApiState::new(store, config, Limits::default()));
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/deployments/app/target")
        .header(header::AUTHORIZATION, format!("Bearer {}", token.reveal()))
        .body(Body::empty())
        .unwrap();
    let answer = answer(&app, request).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let text = String::from_utf8(answer.body.clone()).unwrap();
    (answer.json(), text)
}

#[tokio::test]
async fn unseen_sources_are_one_marker_after_the_seen_ones() {
    let (body, text) = target_as("peek").await;
    // The marker carries the longest window among the sources it stands for.
    assert_eq!(
        body["promoted_from"],
        json!([
            { "deployment": "app/two", "healthy_for_secs": 7200 },
            { "deployment": null, "unseen": true, "healthy_for_secs": 10800 },
        ])
    );
    assert!(!text.contains("app/one"), "{text}");
    assert!(!text.contains("app/three"), "{text}");
}

#[tokio::test]
async fn seen_sources_are_each_named_in_id_order() {
    let (body, _) = target_as("seer").await;
    assert_eq!(
        body["promoted_from"],
        json!([
            { "deployment": "app/one", "healthy_for_secs": 3600 },
            { "deployment": "app/three", "healthy_for_secs": 10800 },
            { "deployment": "app/two", "healthy_for_secs": 7200 },
        ])
    );
}
