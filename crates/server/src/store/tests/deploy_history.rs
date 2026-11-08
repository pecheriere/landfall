//! A deployment's deploys and their steps: read a page at a time, on indexes alone.

use super::super::Store;
use super::super::history::{DEPLOY_BY_ID, DEPLOYS_OF_DEPLOYMENT, DEPLOYS_OF_RELEASE, STEPS_OF};
use super::latest_releases::plan;
use super::{insert_deploy, insert_release};

#[tokio::test]
async fn deploy_history_reads_on_indexes_and_sorts_nothing() {
    let store = Store::open_in_memory().await.unwrap();
    // Some history over several deployments, so that the planner has something to choose
    // over.
    for (n, deployment) in ["app/prod", "app/staging", "app/other"].iter().enumerate() {
        insert_release(&store, deployment, "v1.0.0").await;
        for i in 0..40 {
            let id = i64::try_from(n * 100 + i + 1).unwrap();
            insert_deploy(
                store.pool(),
                id,
                deployment,
                "v1.0.0",
                "finished",
                Some("deployed"),
            )
            .await
            .unwrap();
        }
    }
    sqlx::query("ANALYZE").execute(store.pool()).await.unwrap();
    for (name, sql, binds, index) in [
        ("one deploy", DEPLOY_BY_ID, 1, "INTEGER PRIMARY KEY"),
        (
            "a deployment's deploys",
            DEPLOYS_OF_DEPLOYMENT,
            3,
            "deploys_by_deployment",
        ),
        (
            "a release's deploys",
            DEPLOYS_OF_RELEASE,
            3,
            "deploys_by_release",
        ),
        (
            "a page's steps",
            STEPS_OF,
            1,
            "sqlite_autoindex_deploy_steps_1",
        ),
    ] {
        let steps = plan(&store, sql, binds).await;
        for step in &steps {
            // `json_each` is the page's own list, scanned as it should be; every table is
            // searched by key.
            let fine = step.starts_with("SEARCH")
                || (step.starts_with("SCAN w") && step.contains("VIRTUAL TABLE"));
            assert!(fine, "{name}: {step}: {steps:#?}");
            assert!(!step.contains("TEMP B-TREE"), "{name} sorts: {steps:#?}");
        }
        assert!(
            steps.iter().any(|step| step.contains(index)),
            "{name} doesn't use {index}: {steps:#?}"
        );
        // The request a deploy came from is read by its key.
        if sql != STEPS_OF {
            assert!(
                steps
                    .iter()
                    .any(|step| step.starts_with("SEARCH r USING INTEGER PRIMARY KEY")),
                "{name}: {steps:#?}"
            );
        }
    }
}
