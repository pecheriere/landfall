//! Every success the grant checks get, against the schema the document gives it.

use std::collections::BTreeSet;

use axum::http::header;
use serde_json::{Value, json};

use super::grants::{documented, grant_checks, operations, served_document};

/// The schema of `operation`'s answer with this status, as a schema of its own: the
/// document's components come with it, so that its `$ref`s resolve within the document and
/// nowhere else.
fn schema_of(doc: &Value, schema: &Value) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "components": doc["components"],
        "allOf": [schema],
    })
}

#[tokio::test]
async fn every_success_answer_matches_its_documented_schema() {
    let doc = served_document().await;
    let mut validated = BTreeSet::new();
    for check in grant_checks(&doc).await {
        let answer = &check.answer;
        if !answer.status.is_success() {
            continue;
        }
        let operation = &check.operation;
        let response = documented(&doc, operation, answer.status)
            .unwrap_or_else(|| panic!("{operation}: {} is not documented", answer.status));
        assert_eq!(
            answer.headers[header::CONTENT_TYPE],
            "application/json",
            "{operation}"
        );
        let Some(schema) = response["content"]["application/json"].get("schema") else {
            // The document itself, which `served_document_is_the_same_bytes` compares whole.
            assert_eq!(operation, "getOpenApi", "{operation} documents no schema");
            continue;
        };
        let validator = jsonschema::draft202012::new(&schema_of(&doc, schema)).unwrap();
        let body: Value = answer.json();
        let errors: Vec<String> = validator
            .iter_errors(&body)
            .map(|e| e.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "{operation}, {}: {errors:#?}\n{body:#}",
            check.what
        );
        validated.insert(operation.clone());
    }
    for op in operations(&doc).iter().filter(|op| !op.public) {
        assert!(
            validated.contains(&op.id),
            "no success of {} was validated",
            op.id
        );
    }
}
