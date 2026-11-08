//! A deployment's deploys, one deploy with its steps, and why it ended as it did:
//! `listDeploys`, `getDeploy` and `whyDeploy`.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Answer, Caller, STAGING_VIEWER, World, deployed_steps, holder, quoted_list, run_deploy,
    world_config,
};
use crate::agent_api::{ApiState, Limits};
use crate::api::query::{Cursor, CursorList};
use crate::store::ReleaseDecision;

const PROD_DEPLOYS: &str = "/api/v1/deployments/app/prod/deploys";

fn viewer() -> String {
    holder(&["view"])
}

async fn get_as(world: &World, path: &str, reader: &str) -> Answer {
    world
        .send(Method::GET, path, Caller::Token(reader), None)
        .await
}

/// A page's deploy ids and its cursor.
fn page(answer: &Answer) -> (Vec<i64>, Option<String>) {
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    let ids = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_i64().unwrap())
        .collect();
    (ids, body["next_cursor"].as_str().map(ToOwned::to_owned))
}

#[tokio::test]
async fn deploy_has_steps_with_checks() {
    let world = World::seed().await;
    let answer = get_as(
        &world,
        &format!("/api/v1/deploys/{}", world.deploy),
        &viewer(),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    assert_eq!(body["id"], world.deploy);
    assert_eq!(body["deployment"], "app/prod");
    assert_eq!(body["host"], "home-1");
    assert_eq!(body["tag"], "v1.1.0");
    assert_eq!(body["digest"], format!("sha256:{}", "1".repeat(64)));
    assert_eq!(body["commit"], "1".repeat(40));
    assert_eq!(body["state"], "finished");
    assert_eq!(body["outcome"], "deployed");
    assert_eq!(body["reason"], Value::Null);
    assert_eq!(body["request"], Value::Null);
    assert_eq!(body["approved_by"], Value::Null);
    assert_eq!(body["created_at"], 1_800_000_000);
    assert_eq!(body["claimed_at"], 1_800_000_000);
    assert_eq!(body["finished_at"], 1_800_000_000);
    let steps = body["steps"].as_array().unwrap();
    let names: Vec<&str> = steps.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["\"backup\"", "\"pull\"", "\"checks\""]);
    let positions: Vec<i64> = steps
        .iter()
        .map(|s| s["position"].as_i64().unwrap())
        .collect();
    assert_eq!(positions, [0, 1, 2]);
    assert_eq!(steps[1]["millis"], 1200);
    assert_eq!(steps[1]["failure"], Value::Null);
    assert_eq!(steps[1]["detail"], Value::Null);
    assert_eq!(
        steps[0]["detail"],
        json!({ "kind": "backup", "files": 3, "directories": 1, "symlinks": 0, "bytes": 512 })
    );
    assert_eq!(
        steps[2]["detail"],
        json!({
            "kind": "checks",
            "checks": [{ "check": "\"container-healthy\"", "attempts": 2, "millis": 2900 }],
        })
    );

    let why = get_as(
        &world,
        &format!("/api/v1/deploys/{}/why", world.deploy),
        &viewer(),
    )
    .await;
    assert_eq!(why.status, StatusCode::OK, "{why:?}");
    let why = why.json();
    assert_eq!(why["deploy"], world.deploy);
    assert_eq!(why["outcome"], "deployed");
    assert_eq!(why["next"]["kind"], "none");
    let kinds: Vec<&str> = why["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["what"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["queued", "claimed", "step", "step", "step", "finished"]
    );
}

#[tokio::test]
async fn a_deploy_from_a_request_names_who_asked_and_who_signed() {
    let world = World::seed().await;
    let approver = holder(&["view", "approve"]);
    let answer = world
        .send(
            Method::POST,
            &format!("/api/v1/approvals/{}", world.request.0),
            Caller::Session(&approver),
            Some(world.approval_by(&approver)),
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let deploy = answer.json()["deploy_id"].as_i64().unwrap();
    let path = format!("/api/v1/deploys/{deploy}");
    let body = get_as(&world, &path, &approver).await.json();
    assert_eq!(body["deployment"], "app/staging");
    assert_eq!(body["state"], "queued");
    assert_eq!(body["outcome"], Value::Null);
    assert_eq!(body["claimed_at"], Value::Null);
    assert_eq!(body["request"], world.request.0);
    assert_eq!(body["approved_by"], approver);
    assert_eq!(body["steps"], json!([]));

    let why = get_as(&world, &format!("{path}/why"), &approver)
        .await
        .json();
    let events = why["events"].as_array().unwrap();
    assert_eq!(events[0]["what"], "requested");
    assert!(events[0]["text"].as_str().unwrap().contains("requester"));
    assert_eq!(events[1]["what"], "approved");
    assert!(events[1]["text"].as_str().unwrap().contains(&approver));
    assert_eq!(events[2]["what"], "queued");
    assert_eq!(why["next"]["kind"], "wait");
}

#[tokio::test]
async fn history_pages_newest_first() {
    let world = World::seed().await;
    let mut prod = vec![world.deploy];
    for round in 0..6 {
        let id = run_deploy(
            &world.store,
            ("app/prod", "v1.3.0", '3'),
            &json!({ "kind": "rolled_back", "reason": "unhealthy" }),
            &deployed_steps(),
        )
        .await;
        prod.push(id);
        if round % 2 == 0 {
            // Another deployment's deploys come between, and are never on this list.
            run_deploy(
                &world.store,
                ("app/staging", "v2.1.0", 'c'),
                &json!({ "kind": "deployed" }),
                &json!([]),
            )
            .await;
        }
    }
    prod.reverse();
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            None => format!("{PROD_DEPLOYS}?limit=3"),
            Some(cursor) => format!("{PROD_DEPLOYS}?limit=3&cursor={cursor}"),
        };
        let (ids, next) = page(&get_as(&world, &path, &viewer()).await);
        assert!(ids.len() <= 3);
        seen.extend(ids);
        pages += 1;
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, prod);
    assert_eq!(pages, 3);

    // Every item has its steps, read for the page at once.
    let body = get_as(&world, PROD_DEPLOYS, &viewer()).await.json();
    for item in body["items"].as_array().unwrap() {
        assert_eq!(item["deployment"], "app/prod");
        assert_eq!(item["steps"].as_array().unwrap().len(), 3, "{item}");
    }

    // A cursor of another list, or one that isn't a deploy's number, is refused.
    for bad in [
        Cursor::new(CursorList::Releases, prod[0].to_string()).encode(),
        Cursor::new(CursorList::Deploys, "v1.3.0").encode(),
        Cursor::new(CursorList::Deploys, format!("0{}", prod[0])).encode(),
    ] {
        let answer = get_as(&world, &format!("{PROD_DEPLOYS}?cursor={bad}"), &viewer()).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{bad}: {answer:?}");
    }
}

#[tokio::test]
async fn why_of_an_unseen_deploy_is_not_found() {
    let world = World::seed().await;
    let missing = get_as(&world, "/api/v1/deploys/999999/why", STAGING_VIEWER).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    for path in [
        format!("/api/v1/deploys/{}/why", world.deploy),
        format!("/api/v1/deploys/{}", world.deploy),
    ] {
        let unseen = get_as(&world, &path, STAGING_VIEWER).await;
        assert_eq!(unseen.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(unseen.body, missing.body, "{path}");
        assert_eq!(
            unseen.headers.get("content-type"),
            missing.headers.get("content-type")
        );
        // Some other grant there may know the deployment exists.
        let other = get_as(&world, &path, &holder(&["request"])).await;
        assert_eq!(other.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(other.code(), "forbidden");
    }
    for path in [
        "/api/v1/deploys/01",
        "/api/v1/deploys/+1/why",
        "/api/v1/deploys/x",
    ] {
        let answer = get_as(&world, path, &viewer()).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn deploy_of_a_deployment_no_longer_configured_is_not_found() {
    let world = World::seed().await;
    // `app/old`, once configured, with a release and a deploy the store still holds.
    world
        .store
        .record_release(
            (
                &"app/old".parse().unwrap(),
                &"home-1".parse().unwrap(),
                &"v1.0.0".parse().unwrap(),
            ),
            ReleaseDecision::Manual,
            "it deploys only when someone asks",
            None,
        )
        .await
        .unwrap();
    let old = run_deploy(
        &world.store,
        ("app/old", "v1.0.0", '0'),
        &json!({ "kind": "deployed" }),
        &deployed_steps(),
    )
    .await;
    let reader = holder(&["view", "request", "approve", "rollback"]);
    let then = format!(
        "{}
[[deployment]]
id = \"app/old\"
repo = {{ name = \"example/app\", id = 5, owner_id = 9 }}
host = \"home-1\"
compose = {{ dir = \"/srv/old\", service = \"app\" }}
origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signed_tags = false }}
rule = {{ auto = \"patch\", approvers = [{}] }}
checks = [\"container-healthy\"]

[[grant]]
principal = \"{reader}\"
deployments = [{}]
can = [\"view\"]
",
        world_config(&world.keys),
        quoted_list(&[reader.as_str()]),
        quoted_list(&["app/old"]),
    );
    let then = landfall_approval::parse_config(then.as_bytes()).unwrap();
    let paths = [
        format!("/api/v1/deploys/{old}"),
        format!("/api/v1/deploys/{old}/why"),
        "/api/v1/deployments/app/old/deploys".to_owned(),
    ];
    // While it was configured, the reader saw all of it.
    let configured = crate::router(ApiState::new(world.store.clone(), then, Limits::default()));
    let token = world.credentials.tokens[&reader].reveal();
    for path in &paths {
        let request = axum::http::Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let answer = super::answer(&configured, request).await;
        assert_eq!(answer.status, StatusCode::OK, "{path}: {answer:?}");
    }
    // Now it isn't, and nobody is told of it.
    let missing = get_as(&world, "/api/v1/deploys/999999", &reader).await;
    for path in &paths {
        let answer = get_as(&world, path, &reader).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(answer.body, missing.body, "{path}");
    }
}

/// A finished deploy of `tag` on `deployment`, sent to `host`, whose stored outcome is a name
/// this version doesn't know, as a newer controller could leave one.
async fn unreadable_deploy(world: &World, deployment: &str, tag: &str, host: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO deploys (deployment, host, tag, digest, commit_sha, state, outcome,
                              created_at, finished_at)
         VALUES (?, ?, ?, ?, ?, 'finished', 'teleported', 1800000000, 1800000000)
         RETURNING id",
    )
    .bind(deployment)
    .bind(host)
    .bind(tag)
    .bind(format!("sha256:{}", "3".repeat(64)))
    .bind("3".repeat(40))
    .fetch_one(world.store.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn an_outcome_this_version_cannot_read_is_shown_as_none() {
    let world = World::seed().await;
    let id = unreadable_deploy(&world, "app/prod", "v1.3.0", "home-1").await;
    let (ids, _) = page(&get_as(&world, PROD_DEPLOYS, &viewer()).await);
    assert_eq!(ids, [id, world.deploy]);
    let body = get_as(&world, PROD_DEPLOYS, &viewer()).await.json();
    let item = &body["items"][0];
    assert_eq!(item["state"], "finished");
    assert_eq!(item["outcome"], Value::Null);

    let one = get_as(&world, &format!("/api/v1/deploys/{id}"), &viewer()).await;
    assert_eq!(one.status, StatusCode::OK, "{one:?}");
    assert_eq!(one.json()["outcome"], Value::Null);
    let why = get_as(&world, &format!("/api/v1/deploys/{id}/why"), &viewer()).await;
    assert_eq!(why.status, StatusCode::OK, "{why:?}");
    let why = why.json();
    assert_eq!(why["outcome"], Value::Null);
    assert!(why["summary"].as_str().unwrap().contains("v1.3.0"));

    // The release's story lists it the same way.
    let story = get_as(
        &world,
        "/api/v1/deployments/app/prod/releases/v1.3.0",
        &viewer(),
    )
    .await;
    assert_eq!(story.status, StatusCode::OK, "{story:?}");
    assert_eq!(story.json()["deploys"][0]["outcome"], Value::Null);
}

#[tokio::test]
async fn an_unreadable_deploy_of_a_removed_deployment_is_not_found() {
    let world = World::seed().await;
    world
        .store
        .record_release(
            (
                &"app/old".parse().unwrap(),
                &"home-1".parse().unwrap(),
                &"v1.0.0".parse().unwrap(),
            ),
            ReleaseDecision::Manual,
            "it deploys only when someone asks",
            None,
        )
        .await
        .unwrap();
    // Neither its outcome nor its host can be read, and neither is anyone's business.
    let old = unreadable_deploy(&world, "app/old", "v1.0.0", "not a host!").await;
    let reader = holder(&["view", "request", "approve", "rollback"]);
    let missing = get_as(&world, "/api/v1/deploys/999999", &reader).await;
    for path in [
        format!("/api/v1/deploys/{old}"),
        format!("/api/v1/deploys/{old}/why"),
    ] {
        let answer = get_as(&world, &path, &reader).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}: {answer:?}");
        assert_eq!(answer.body, missing.body, "{path}");
    }
}
