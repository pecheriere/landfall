//! Every operation in the served document against the grant its `security` lists, each check
//! on a fresh [`World`], so that what one role changed can't decide the next. The document is
//! what is tested: an operation, a role or an `x-landfall-grant` key with no row in [`CASES`]
//! fails, and so does a refusal the operation's `responses` doesn't list.

use std::collections::BTreeSet;

use axum::http::{Method, StatusCode, header};
use landfall_core::protocol::PROBLEM_CONTENT_TYPE;
use serde_json::{Value, json};

use super::{Answer, App, Caller, OUTSIDER, REQUESTER, ROLES, World, holder};

/// The role of a case for an operation any authenticated principal may call, or anyone.
pub(super) const ANYONE: &str = "anyone";

/// The concrete request a holder of `role` makes to call `operation`, built from the
/// [`World`] it is sent to.
pub(super) struct Case {
    pub(super) operation: &'static str,
    pub(super) role: &'static str,
    pub(super) method: Method,
    pub(super) path: fn(&World) -> String,
    pub(super) body: Option<fn(&World) -> String>,
}

fn document(_: &World) -> String {
    "/api/v1/openapi.json".to_owned()
}

fn approvals(_: &World) -> String {
    "/api/v1/approvals".to_owned()
}

fn me(_: &World) -> String {
    "/api/v1/me".to_owned()
}

fn deployments(_: &World) -> String {
    "/api/v1/deployments".to_owned()
}

fn prod(_: &World) -> String {
    "/api/v1/deployments/app/prod".to_owned()
}

fn prod_requests(_: &World) -> String {
    "/api/v1/deployments/app/prod/requests".to_owned()
}

fn the_approval(world: &World) -> String {
    format!("/api/v1/approvals/{}", world.request.0)
}

fn the_cancel(world: &World) -> String {
    format!("/api/v1/approvals/{}/cancel", world.request.0)
}

/// A tag above what runs on `app/prod`.
fn tag_above(_: &World) -> String {
    json!({ "tag": "v1.3.0" }).to_string()
}

/// A tag below what runs on `app/prod`.
fn tag_below(_: &World) -> String {
    json!({ "tag": "v1.1.0" }).to_string()
}

fn signed_by_the_approver(world: &World) -> String {
    world.approval_by(&holder(&["approve"]))
}

/// Each operation and role, with its request. The rows of an operation with
/// `x-landfall-grant` are also the cross cases: each role is tried against the others'.
pub(super) const CASES: &[Case] = &[
    Case {
        operation: "getOpenApi",
        role: ANYONE,
        method: Method::GET,
        path: document,
        body: None,
    },
    Case {
        operation: "listApprovals",
        role: ANYONE,
        method: Method::GET,
        path: approvals,
        body: None,
    },
    Case {
        operation: "whoAmI",
        role: ANYONE,
        method: Method::GET,
        path: me,
        body: None,
    },
    Case {
        operation: "listDeployments",
        role: ANYONE,
        method: Method::GET,
        path: deployments,
        body: None,
    },
    Case {
        operation: "getDeployment",
        role: "view",
        method: Method::GET,
        path: prod,
        body: None,
    },
    Case {
        operation: "requestDeploy",
        role: "request",
        method: Method::POST,
        path: prod_requests,
        body: Some(tag_above),
    },
    Case {
        operation: "requestDeploy",
        role: "rollback",
        method: Method::POST,
        path: prod_requests,
        body: Some(tag_below),
    },
    Case {
        operation: "approveRequest",
        role: "approve",
        method: Method::POST,
        path: the_approval,
        body: Some(signed_by_the_approver),
    },
    Case {
        operation: "cancelRequest",
        role: "requester",
        method: Method::POST,
        path: the_cancel,
        body: None,
    },
    Case {
        operation: "cancelRequest",
        role: "approve",
        method: Method::POST,
        path: the_cancel,
        body: None,
    },
    Case {
        operation: "cancelRequest",
        role: "rollback",
        method: Method::POST,
        path: the_cancel,
        body: None,
    },
];

/// An operation as the document has it.
pub(super) struct Operation {
    pub(super) id: String,
    pub(super) method: Method,
    pub(super) template: String,
    pub(super) public: bool,
    /// Each scheme's name and the roles it lists.
    pub(super) schemes: Vec<(String, Vec<String>)>,
    /// The keys of `x-landfall-grant`.
    pub(super) grant_keys: Vec<String>,
}

impl Operation {
    /// Every role any scheme lists, and every `x-landfall-grant` key, or [`ANYONE`] when it
    /// lists none.
    pub(super) fn roles(&self) -> BTreeSet<String> {
        let mut roles: BTreeSet<String> = self
            .schemes
            .iter()
            .flat_map(|(_, roles)| roles.iter().cloned())
            .chain(self.grant_keys.iter().cloned())
            .collect();
        if roles.is_empty() {
            roles.insert(ANYONE.to_owned());
        }
        roles
    }

    pub(super) fn cases(&self) -> impl Iterator<Item = &'static Case> {
        let id = self.id.clone();
        CASES.iter().filter(move |case| case.operation == id)
    }

    fn case(&self, role: &str) -> &'static Case {
        self.cases()
            .find(|case| case.role == role)
            .unwrap_or_else(|| panic!("{} has no case for {role}", self.id))
    }
}

/// The document a controller serves.
pub(super) async fn served_document() -> Value {
    App::new()
        .await
        .get("/api/v1/openapi.json", None, None)
        .await
        .json()
}

/// Every operation in `doc`.
pub(super) fn operations(doc: &Value) -> Vec<Operation> {
    let mut found = Vec::new();
    for (template, item) in doc["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let security = operation["security"].as_array().unwrap();
            let schemes: Vec<(String, Vec<String>)> = security
                .iter()
                .flat_map(|requirement| requirement.as_object().unwrap())
                .map(|(scheme, roles)| {
                    let roles = roles.as_array().unwrap();
                    let roles = roles.iter().map(|r| r.as_str().unwrap().to_owned());
                    (scheme.clone(), roles.collect())
                })
                .collect();
            let grant_keys = operation
                .get("x-landfall-grant")
                .and_then(Value::as_object)
                .map(|grant| grant.keys().cloned().collect())
                .unwrap_or_default();
            found.push(Operation {
                id: operation["operationId"].as_str().unwrap().to_owned(),
                method: Method::from_bytes(method.to_uppercase().as_bytes()).unwrap(),
                template: template.clone(),
                public: schemes.is_empty(),
                schemes,
                grant_keys,
            });
        }
    }
    found
}

/// Whether `path` is one `template` describes.
fn fits(template: &str, path: &str) -> bool {
    let (template, path): (Vec<_>, Vec<_>) =
        (template.split('/').collect(), path.split('/').collect());
    template.len() == path.len()
        && template.iter().zip(&path).all(|(want, got)| {
            if want.starts_with('{') && want.ends_with('}') {
                !got.is_empty()
            } else {
                want == got
            }
        })
}

/// Who holds `role` alone.
pub(super) fn holder_of(role: &str) -> String {
    if role == "requester" {
        REQUESTER.to_owned()
    } else {
        holder(&[role])
    }
}

/// Who sends a check, by name.
#[derive(Debug, Clone)]
enum Who {
    Nobody,
    By(String, String),
}

impl Who {
    fn by(scheme: &str, name: &str) -> Self {
        Self::By(scheme.to_owned(), name.to_owned())
    }

    fn caller(&self) -> Caller<'_> {
        match self {
            Self::Nobody => Caller::Nobody,
            Self::By(scheme, name) if scheme == "token" => Caller::Token(name),
            Self::By(scheme, name) if scheme == "session" => Caller::Session(name),
            Self::By(scheme, _) => panic!("a scheme the test doesn't know: {scheme}"),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Nobody => "no credentials".to_owned(),
            Self::By(scheme, name) => format!("{name}'s {scheme}"),
        }
    }
}

/// What a check wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Expect {
    Refused(StatusCode),
    /// A success.
    Allowed,
}

/// One request on a fresh [`World`], and what came of it.
pub(super) struct Check {
    pub(super) operation: String,
    pub(super) what: String,
    pub(super) expect: Expect,
    pub(super) answer: Answer,
    /// Whether a request or a deploy changed.
    pub(super) changed: bool,
}

/// Sends `case` as `caller` on a fresh [`World`], with `query` after its path. Gives the
/// answer, and whether a request or a deploy changed.
pub(super) async fn try_case(
    op: &Operation,
    case: &Case,
    caller: Caller<'_>,
    query: &str,
) -> (Answer, bool) {
    let world = World::seed().await;
    let path = (case.path)(&world);
    assert!(fits(&op.template, &path), "{}: {path}", op.id);
    assert_eq!(case.method, op.method, "{}", op.id);
    let before = world.rows().await;
    let body = case.body.map(|body| body(&world));
    let answer = world
        .send(case.method.clone(), &format!("{path}{query}"), caller, body)
        .await;
    let changed = world.rows().await != before;
    (answer, changed)
}

/// What to check of `op`: who sends which case, and what they should get.
fn plan(op: &Operation) -> Vec<(&'static Case, Who, Expect)> {
    let Some(first) = op.cases().next() else {
        return Vec::new();
    };
    if op.public {
        return vec![(first, Who::Nobody, Expect::Allowed)];
    }
    let unauthenticated = (
        first,
        Who::Nobody,
        Expect::Refused(StatusCode::UNAUTHORIZED),
    );
    if op.roles().contains(ANYONE) {
        // A list filtered by what each may see: anyone authenticated gets it.
        return vec![
            unauthenticated,
            (first, Who::by("token", OUTSIDER), Expect::Allowed),
            (first, Who::by("token", &holder(&ROLES)), Expect::Allowed),
        ];
    }
    let mut plan = vec![
        unauthenticated,
        (
            first,
            Who::by("token", OUTSIDER),
            Expect::Refused(StatusCode::NOT_FOUND),
        ),
    ];
    for (scheme, listed) in &op.schemes {
        let others: Vec<&str> = ROLES
            .iter()
            .copied()
            .filter(|role| !listed.iter().any(|l| l == role))
            .collect();
        if !others.is_empty() {
            let refused = Expect::Refused(StatusCode::FORBIDDEN);
            plan.extend(
                op.cases()
                    .map(|case| (case, Who::by(scheme, &holder(&others)), refused)),
            );
        }
        for role in listed {
            plan.push((
                op.case(role),
                Who::by(scheme, &holder_of(role)),
                Expect::Allowed,
            ));
        }
    }
    plan
}

/// Every check of every operation's grant.
pub(super) async fn grant_checks(doc: &Value) -> Vec<Check> {
    let mut checks = Vec::new();
    for op in operations(doc) {
        for (case, who, expect) in plan(&op) {
            let (answer, changed) = try_case(&op, case, who.caller(), "").await;
            checks.push(Check {
                operation: op.id.clone(),
                what: format!("{} on the {} case", who.describe(), case.role),
                expect,
                answer,
                changed,
            });
        }
    }
    checks
}

/// `value`, or what its `$ref` points to in `doc`.
pub(super) fn resolved<'a>(doc: &'a Value, value: &'a Value) -> &'a Value {
    match value.get("$ref").and_then(Value::as_str) {
        Some(pointer) => doc
            .pointer(pointer.trim_start_matches('#'))
            .unwrap_or_else(|| panic!("a $ref to nothing: {pointer}")),
        None => value,
    }
}

/// The documented response of `operation` for `status`.
pub(super) fn documented<'a>(
    doc: &'a Value,
    operation: &str,
    status: StatusCode,
) -> Option<&'a Value> {
    let op = doc["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|item| item.as_object().unwrap().values())
        .find(|op| op["operationId"] == operation)
        .unwrap_or_else(|| panic!("no operation {operation}"));
    op["responses"]
        .get(status.as_str())
        .map(|response| resolved(doc, response))
}

/// That `answer` is never stored, and that a refusal is one `operation`'s document lists,
/// under its status, naming its code.
pub(super) fn assert_documented(doc: &Value, operation: &str, what: &str, answer: &Answer) {
    assert_eq!(
        answer
            .headers
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap()),
        Some("no-store"),
        "{operation}, {what}: {answer:?}"
    );
    let Some(response) = documented(doc, operation, answer.status) else {
        panic!(
            "{operation} answers {} to {what}, which its document doesn't list",
            answer.status
        );
    };
    if answer.status.is_success() {
        return;
    }
    assert_eq!(
        answer.headers[header::CONTENT_TYPE],
        PROBLEM_CONTENT_TYPE,
        "{operation}, {what}"
    );
    assert!(
        response["content"].get(PROBLEM_CONTENT_TYPE).is_some(),
        "{operation}: {} isn't documented as a problem",
        answer.status
    );
    let code = answer.code();
    let description = response["description"].as_str().unwrap();
    assert!(
        description.contains(&format!("`{code}`")),
        "{operation} refuses {what} with {} `{code}`, which its document doesn't name: {description}",
        answer.status
    );
}

#[tokio::test]
async fn every_operation_enforces_its_documented_grant() {
    let doc = served_document().await;
    let checks = grant_checks(&doc).await;
    assert!(!checks.is_empty());
    for check in &checks {
        let Check {
            operation,
            what,
            expect,
            answer,
            changed,
        } = check;
        match expect {
            Expect::Refused(status) => {
                assert_eq!(answer.status, *status, "{operation}, {what}: {answer:?}");
                assert!(
                    !changed,
                    "{operation}, {what}: refused, and changed something"
                );
            }
            Expect::Allowed => {
                assert!(
                    answer.status.is_success(),
                    "{operation}, {what}: {answer:?}"
                );
            }
        }
        assert_documented(&doc, operation, what, answer);
    }
}

#[tokio::test]
async fn each_role_is_refused_the_case_it_does_not_govern() {
    let doc = served_document().await;
    let mut tried = Vec::new();
    for op in operations(&doc) {
        for role in &op.grant_keys {
            for other in op.grant_keys.iter().filter(|other| *other != role) {
                let name = holder_of(role);
                let (answer, changed) =
                    try_case(&op, op.case(other), Caller::Token(&name), "").await;
                let what = format!("{role} asking for the {other} case");
                assert_eq!(
                    answer.status,
                    StatusCode::FORBIDDEN,
                    "{}, {what}: {answer:?}",
                    op.id
                );
                assert_eq!(answer.code(), "forbidden");
                assert!(!changed, "{}, {what}", op.id);
                assert_documented(&doc, &op.id, &what, &answer);
                tried.push(format!("{}: {what}", op.id));
            }
        }
    }
    // `request` asking for a tag below what runs, and `rollback` for one above it.
    assert!(
        tried.contains(&"requestDeploy: request asking for the rollback case".to_owned()),
        "{tried:?}"
    );
    assert!(
        tried.contains(&"requestDeploy: rollback asking for the request case".to_owned()),
        "{tried:?}"
    );
}

#[tokio::test]
async fn every_documented_operation_and_role_has_a_case() {
    let doc = served_document().await;
    let operations = operations(&doc);
    let mut missing = Vec::new();
    for op in &operations {
        for role in op.roles() {
            if !op.cases().any(|case| case.role == role) {
                missing.push(format!("{} has no case for {role}", op.id));
            }
        }
    }
    for case in CASES {
        let known = operations
            .iter()
            .find(|op| op.id == case.operation)
            .is_some_and(|op| op.roles().contains(case.role));
        if !known {
            missing.push(format!(
                "{} has a case for {}, which the document doesn't list",
                case.operation, case.role
            ));
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
}

#[tokio::test]
async fn a_token_never_approves_even_with_the_grant() {
    let world = World::seed().await;
    let path = format!("/api/v1/approvals/{}", world.request.0);
    let before = world.rows().await;
    for name in [holder(&["approve"]), holder(&ROLES)] {
        let body = world.approval_by(&name);
        let answer = world
            .send(Method::POST, &path, Caller::Token(&name), Some(body))
            .await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{name}: {answer:?}");
        assert_eq!(answer.code(), "forbidden");
    }
    assert_eq!(world.rows().await, before);
    // The same passkey's assertion, with a session.
    let name = holder(&["approve"]);
    let body = world.approval_by(&name);
    let answer = world
        .send(Method::POST, &path, Caller::Session(&name), Some(body))
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn a_body_over_its_limit_is_refused_as_documented() {
    let doc = served_document().await;
    let mut tried = Vec::new();
    for op in operations(&doc) {
        let method = op.method.as_str().to_lowercase();
        if doc["paths"][&op.template][&method]
            .get("requestBody")
            .is_none()
        {
            continue;
        }
        let (scheme, roles) = op
            .schemes
            .iter()
            .find(|(_, roles)| !roles.is_empty())
            .unwrap();
        let name = holder_of(&roles[0]);
        let world = World::seed().await;
        let path = (op.case(&roles[0]).path)(&world);
        let before = world.rows().await;
        let who = Who::by(scheme, &name);
        let body = Some("x".repeat(64 * 1024));
        let answer = world
            .send(op.method.clone(), &path, who.caller(), body)
            .await;
        let what = format!("a body of 64 KiB from {}", who.describe());
        assert_eq!(
            answer.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{}, {what}: {answer:?}",
            op.id
        );
        assert_eq!(answer.code(), "body_too_large");
        assert_eq!(world.rows().await, before, "{}", op.id);
        assert_documented(&doc, &op.id, &what, &answer);
        tried.push(op.id);
    }
    assert_eq!(tried, ["approveRequest", "requestDeploy"]);
}
