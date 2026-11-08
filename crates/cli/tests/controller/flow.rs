//! What an agent and a person do with `landfall`, from a release waiting to why its deploy
//! ended as it did.

use landfall_api::{
    ApprovalsView, AuditEntry, DeployView, DeploymentSummary, DeploymentView, HostView, HostsView,
    MeView, Page, ReleaseStory, ReleaseView, RequestView, Why,
};
use serde::de::DeserializeOwned;

use crate::harness::{APPROVAL_ORIGIN, Controller, RUNNING, WAITING};

/// The line `request deploy` and `approvals` print under an open request.
fn where_to_sign() -> String {
    format!(
        "An approver signs this at {APPROVAL_ORIGIN}/approvals with their passkey. Agents can't \
         approve."
    )
}

/// `ci` asks for [`WAITING`] and gives the request, read from `--json`.
async fn ci_asks(controller: &Controller) -> RequestView {
    let asked = controller
        .landfall(
            Some(controller.ci()),
            &["request", "deploy", "app/prod", WAITING, "--json"],
        )
        .await;
    assert_eq!(asked.status, 0, "{asked:?}");
    serde_json::from_str(&asked.out).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_finds_a_waiting_release_and_asks() {
    let controller = Controller::start().await;
    let ci = Some(controller.ci());

    let status = controller.landfall(ci, &["status"]).await;
    assert_eq!(status.status, 0, "{status:?}");
    assert_eq!(
        status.out,
        format!("app/prod on home-1: runs {RUNNING} (idle), latest {WAITING} needs_request\n")
    );

    let release = controller
        .landfall(ci, &["release", "app/prod", WAITING])
        .await;
    assert_eq!(release.status, 0, "{release:?}");
    assert!(
        release.out.starts_with(&format!(
            "{WAITING}: needs_request (decision needs_approval)"
        )),
        "{}",
        release.out
    );
    assert!(
        release
            .out
            .contains("commits: the first verified release, with none below to compare with\n"),
        "{}",
        release.out
    );

    let asked = controller
        .landfall(ci, &["request", "deploy", "app/prod", WAITING])
        .await;
    assert_eq!(asked.status, 0, "{asked:?}");
    assert!(asked.out.contains(&where_to_sign()), "{}", asked.out);
    assert_eq!(asked.err, "");

    let approvals = controller.landfall(ci, &["approvals", "--json"]).await;
    assert_eq!(approvals.status, 0, "{approvals:?}");
    let approvals: ApprovalsView = serde_json::from_str(&approvals.out).unwrap();
    let [waiting] = approvals.approvals.as_slice() else {
        panic!("one request waits: {approvals:?}");
    };
    assert_eq!(waiting.intent.tag.as_ref(), WAITING);
    assert_eq!(waiting.requested_by.as_ref(), "ci");
    assert!(!waiting.can_approve, "a token never approves");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_operator_approves_and_why_explains() {
    let controller = Controller::start().await;
    let ci = Some(controller.ci());
    let request = ci_asks(&controller).await;

    let session = controller.operator_signs_in().await;
    let deploy = controller.operator_approves(&session, &request).await;
    controller.rolled_back(deploy, WAITING).await;

    let history = controller.landfall(ci, &["history", "app/prod"]).await;
    assert_eq!(history.status, 0, "{history:?}");
    assert!(
        history.out.starts_with(&format!(
            "deploy {deploy}: {WAITING} on home-1, finished, rolled_back, queued "
        )),
        "{}",
        history.out
    );
    assert!(
        history.out.contains(&format!(
            "  from request {}, approved by operator\n",
            request.id
        )),
        "{}",
        history.out
    );

    let why = controller.landfall(ci, &["why", &deploy.to_string()]).await;
    assert_eq!(why.status, 0, "{why:?}");
    assert!(
        why.out
            .starts_with(&format!("deploy {deploy}: rolled_back\n")),
        "{}",
        why.out
    );
    assert!(why.out.contains("\nnext: request: "), "{}", why.out);

    let release = controller
        .landfall(ci, &["release", "app/prod", WAITING])
        .await;
    assert_eq!(release.status, 0, "{release:?}");
    assert!(
        release.out.starts_with(&format!("{WAITING}: failed ")),
        "{}",
        release.out
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reader_can_read_and_not_ask() {
    let controller = Controller::start().await;
    let reader = Some(controller.reader());

    let status = controller.landfall(reader, &["status"]).await;
    assert_eq!(status.status, 0, "{status:?}");
    assert!(status.out.starts_with("app/prod on home-1: "), "{status:?}");

    let asked = controller
        .landfall(reader, &["request", "deploy", "app/prod", WAITING])
        .await;
    assert_eq!(asked.status, 1, "{asked:?}");
    assert_eq!(asked.out, "");
    assert!(
        asked
            .err
            .starts_with("landfall: the controller refused (403): forbidden: "),
        "{}",
        asked.err
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rollback_of_a_higher_tag_exits_1_with_not_a_rollback() {
    let controller = Controller::start().await;

    let rollback = controller
        .landfall(Some(controller.ci()), &["rollback", "app/prod", WAITING])
        .await;

    assert_eq!(rollback.status, 1, "{rollback:?}");
    assert_eq!(rollback.out, "");
    assert!(
        rollback
            .err
            .starts_with("landfall: the controller refused (409): not_a_rollback: "),
        "{}",
        rollback.err
    );
    let approvals = controller
        .landfall(Some(controller.ci()), &["approvals"])
        .await;
    assert_eq!(approvals.out, "nothing waits for an approver\n");
}

/// Why `landfall rollback` can only say that a `400` may be an older controller: the
/// controller's answer to a field it doesn't know is the one it gives any body it can't read.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_field_is_refused_as_any_unreadable_body() {
    let controller = Controller::start().await;
    let path = "/api/v1/deployments/app/prod/requests";

    let unknown = controller
        .refusal_of_post(
            controller.ci(),
            path,
            r#"{"tag":"v1.1.0","rollback":true,"from_a_newer_cli":true}"#,
        )
        .await;
    let cut_short = controller
        .refusal_of_post(controller.ci(), path, r#"{"tag":"v1.1.0""#)
        .await;

    assert_eq!(unknown.0, 400, "{unknown:?}");
    assert_eq!(unknown.1["code"], "bad_request");
    assert_eq!(unknown, cut_short);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_token_exits_2() {
    let controller = Controller::start().await;
    let before = controller
        .landfall(Some(controller.ci()), &["whoami"])
        .await;
    assert_eq!(before.status, 0, "{before:?}");

    controller.revoke_ci().await;

    assert_eq!(
        controller.problem_code(controller.ci(), "/api/v1/me").await,
        (401, "unauthenticated".to_owned())
    );
    for args in [&["whoami"][..], &["status", "--json"]] {
        let refused = controller.landfall(Some(controller.ci()), args).await;
        assert_eq!(refused.status, 2, "{refused:?}");
        assert_eq!(refused.out, "");
        assert_eq!(
            refused.err,
            "landfall: the controller did not accept the token from LANDFALL_TOKEN: check it, \
             or ask for a new one\n"
        );
    }
}

/// `landfall <args> --json` as `ci`, read as `T`.
async fn json_of<T: DeserializeOwned>(controller: &Controller, args: &[&str]) -> T {
    let mut args = args.to_vec();
    args.push("--json");
    let ran = controller.landfall(Some(controller.ci()), &args).await;
    assert_eq!(ran.status, 0, "{ran:?}");
    serde_json::from_str(&ran.out).unwrap_or_else(|error| panic!("{args:?}: {error}: {ran:?}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn json_output_parses_as_the_api_types() {
    let controller = Controller::start().await;
    let request = ci_asks(&controller).await;
    let session = controller.operator_signs_in().await;
    let deploy = controller.operator_approves(&session, &request).await;
    controller.rolled_back(deploy, WAITING).await;
    let deploy = deploy.to_string();

    let me: MeView = json_of(&controller, &["whoami"]).await;
    assert_eq!(me.principal.as_ref(), "ci");
    let listed: Page<DeploymentSummary> = json_of(&controller, &["status"]).await;
    assert_eq!(listed.items.len(), 1);
    let one: DeploymentView = json_of(&controller, &["status", "app/prod"]).await;
    assert_eq!(one.summary.id.as_ref(), "app/prod");
    let history: Page<DeployView> = json_of(&controller, &["history", "app/prod"]).await;
    assert_eq!(history.items.len(), 1);
    let releases: Page<ReleaseView> = json_of(&controller, &["releases", "app/prod"]).await;
    assert_eq!(releases.items.len(), 1);
    let story: ReleaseStory = json_of(&controller, &["release", "app/prod", WAITING]).await;
    assert_eq!(story.release.tag.as_ref(), WAITING);
    let why: Why = json_of(&controller, &["why", &deploy]).await;
    assert_eq!(why.deploy.to_string(), deploy);
    let hosts: HostsView = json_of(&controller, &["hosts"]).await;
    assert_eq!(hosts.hosts.len(), 1);
    let host: HostView = json_of(&controller, &["hosts", "home-1"]).await;
    assert_eq!(host.id.as_ref(), "home-1");
    let audit: Page<AuditEntry> = json_of(&controller, &["audit"]).await;
    assert!(
        audit
            .items
            .iter()
            .any(|entry| entry.kind == "deploy_finished"),
        "{audit:?}"
    );
    let approvals: ApprovalsView = json_of(&controller, &["approvals"]).await;
    assert_eq!(approvals.approvals, []);
}
