//! The watcher against a fake source, a real store and a clock moved by hand.

mod decisions;
mod failures;
mod hosts;
mod promotion;
mod running;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use landfall_core::config;
use landfall_core::protocol::{
    DeployReportBody, DeployedRelease, Phase, ReportedOutcome, RunningState,
};
use landfall_origin::attestation::VerifiedAttestation;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;

use super::*;
use crate::report::BoundedReport;
use crate::store::ManualClock;

const PROD: &str = "app/prod";
const OTHER: &str = "other/prod";
const HOST: &str = "host-a";
/// The run every release of the fake comes from, unless a test says otherwise.
const RUN_1: &str = "https://github.com/example/app/actions/runs/1/attempts/1";
const RUN_1_ATTEMPT_2: &str = "https://github.com/example/app/actions/runs/1/attempts/2";
const RUN_2: &str = "https://github.com/example/app/actions/runs/2/attempts/1";

/// `app/prod` with `rule`, and `other/prod` of another repository on auto `any`.
fn config_text(rule: &str) -> String {
    format!(
        r#"
[approvers]
operator = {{ credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }}

[[deployment]]
id = "app/prod"
repo = {{ name = "example/app", id = 1, owner_id = 2 }}
host = "host-a"
compose = {{ dir = "/srv/app", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {rule}
checks = ["container-healthy"]

[[deployment]]
id = "other/prod"
repo = {{ name = "example/other", id = 3, owner_id = 2 }}
host = "host-b"
compose = {{ dir = "/srv/other", service = "other" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "any", approvers = ["operator"] }}
checks = ["container-healthy"]
"#
    )
}

const PATCH_RULE: &str = r#"{ auto = "patch", approve = "minor", approvers = ["operator"] }"#;

fn hashed(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn digest(tag: &str) -> ImageDigest {
    format!("sha256:{}", hashed(tag)).parse().unwrap()
}

/// The digest named by `name`, attested by the run at `run_url`.
fn candidate(name: &str, run_url: &str) -> RunCandidate {
    RunCandidate {
        digest: digest(name),
        run_url: run_url.to_owned(),
    }
}

fn commit(tag: &str) -> CommitSha {
    hashed(&format!("commit {tag}"))[..40].parse().unwrap()
}

fn tag(text: &str) -> ReleaseTag {
    text.parse().unwrap()
}

fn id(text: &str) -> DeploymentId {
    text.parse().unwrap()
}

fn origin(text: &str) -> ReleaseOrigin {
    ReleaseOrigin {
        commit: commit(text),
        tag: None,
        attestation: VerifiedAttestation {
            digest: digest(text),
            san: format!(
                "https://github.com/example/app/.github/workflows/release.yml@refs/tags/{text}"
            ),
            commit: commit(text),
            git_ref: format!("refs/tags/{text}"),
            repo_id: 1,
            owner_id: 2,
            run_url: RUN_1.to_owned(),
            rekor_log_index: 7,
            integrated_time: 1_800_000_000,
        },
        platforms: Vec::new(),
    }
}

type MakeError = Box<dyn Fn() -> ReleaseError + Send + Sync>;

/// What the fake is set to answer, by deployment and tag.
#[derive(Default)]
struct FakeState {
    prepare_fails: Option<String>,
    prepare_panics: bool,
    listed: HashMap<String, Vec<ListedTag>>,
    tags_fail: HashMap<String, MakeError>,
    tags_panic: HashSet<String>,
    tags_hang: HashSet<String>,
    verify_fails: HashMap<String, MakeError>,
    attested_fails: HashMap<String, MakeError>,
    /// What else verified for a tag, beside its own digest.
    more_candidates: HashMap<String, Vec<RunCandidate>>,
    /// Tags whose own digest the enumeration does not find.
    own_digest_unlisted: HashSet<String>,
    /// Asked in the middle of each call, to see that nothing is holding it up.
    store: Option<Store>,
}

#[derive(Default)]
struct Fake {
    state: Mutex<FakeState>,
    prepares: AtomicUsize,
    tag_lists: AtomicUsize,
    verifies: Mutex<Vec<String>>,
    enumerations: AtomicUsize,
}

impl Fake {
    fn locked(&self) -> std::sync::MutexGuard<'_, FakeState> {
        // A panic it was set to raise is no reason for every later call to raise one.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `deployment`'s repository now has these tags, each its own tag object.
    fn tags(&self, deployment: &str, tags: &[&str]) {
        let listed = tags
            .iter()
            .map(|t| ListedTag {
                tag: tag(t),
                object: hashed(t)[..40].to_owned(),
            })
            .collect();
        self.locked().listed.insert(deployment.to_owned(), listed);
    }

    fn verify_count(&self) -> usize {
        self.verifies.lock().unwrap().len()
    }

    async fn nothing_in_the_way(&self) {
        let store = self.locked().store.clone();
        if let Some(store) = store {
            tokio::time::timeout(Duration::from_secs(2), store.ping())
                .await
                .expect("the only connection is taken")
                .unwrap();
        }
    }
}

impl ReleaseSource for Fake {
    fn prepare(&self) -> impl Future<Output = Result<(), String>> + Send {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        let state = self.locked();
        assert!(!state.prepare_panics, "the prepare panic");
        std::future::ready(state.prepare_fails.clone().map_or(Ok(()), Err))
    }

    async fn tags(&self, deployment: &DeploymentId) -> Result<Vec<ListedTag>, ReleaseError> {
        self.nothing_in_the_way().await;
        self.tag_lists.fetch_add(1, Ordering::SeqCst);
        let key = deployment.as_ref();
        let hang = self.locked().tags_hang.contains(key);
        if hang {
            std::future::pending::<()>().await;
        }
        let state = self.locked();
        assert!(!state.tags_panic.contains(key), "the tags panic");
        if let Some(fail) = state.tags_fail.get(key) {
            return Err(fail());
        }
        Ok(state.listed.get(key).cloned().unwrap_or_default())
    }

    async fn verify(
        &self,
        _deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> Result<ReleaseOrigin, ReleaseError> {
        self.nothing_in_the_way().await;
        self.verifies.lock().unwrap().push(tag.to_string());
        if let Some(fail) = self.locked().verify_fails.get(tag.as_ref()) {
            return Err(fail());
        }
        Ok(origin(tag.as_ref()))
    }

    async fn attested_digests(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
        _commit: &CommitSha,
    ) -> Result<Vec<RunCandidate>, ReleaseError> {
        self.nothing_in_the_way().await;
        self.enumerations.fetch_add(1, Ordering::SeqCst);
        let state = self.locked();
        if let Some(fail) = state.attested_fails.get(tag.as_ref()) {
            return Err(fail());
        }
        let mut candidates = Vec::new();
        if !state.own_digest_unlisted.contains(tag.as_ref()) {
            let run = if deployment.as_ref() == OTHER {
                "https://github.com/example/other/actions/runs/1/attempts/1"
            } else {
                RUN_1
            };
            candidates.push(candidate(tag.as_ref(), run));
        }
        candidates.extend(
            state
                .more_candidates
                .get(tag.as_ref())
                .cloned()
                .unwrap_or_default(),
        );
        Ok(candidates)
    }
}

struct Harness {
    store: Store,
    clock: Arc<ManualClock>,
    config: Arc<Config>,
    fake: Arc<Fake>,
    state: Arc<WatcherState>,
}

impl Harness {
    async fn new(config_text: &str) -> Self {
        let clock = ManualClock::at(1_800_000_000);
        let store = Store::open_in_memory()
            .await
            .unwrap()
            .with_clock(clock.clone());
        Self {
            store,
            clock,
            config: Arc::new(config::parse(config_text.as_bytes()).unwrap()),
            fake: Arc::new(Fake::default()),
            state: Arc::new(WatcherState::default()),
        }
    }

    /// `app/prod` under the patch rule, with `running` deployed and idle.
    async fn running(running: &str) -> Self {
        let h = Self::new(&config_text(PATCH_RULE)).await;
        h.report(PROD, HOST, Some(running)).await;
        h
    }

    async fn tick(&self) -> TickSummary {
        tick(&self.store, &self.config, &self.fake, &self.state).await
    }

    async fn report_state(&self, host: &str, state: RunningState) {
        let host: landfall_core::ids::HostId = host.parse().unwrap();
        self.store
            .record_host_state(&host, None, &[&state])
            .await
            .unwrap();
    }

    fn state_of(deployment: &str, deployed: Option<&str>) -> RunningState {
        RunningState {
            deployment: id(deployment),
            deployed: deployed.map(|t| DeployedRelease {
                tag: tag(t),
                digest: digest(t),
            }),
            drift: false,
            phase: Phase::Idle,
            busy: false,
        }
    }

    /// `host` says `deployed` is running, idle and without drift.
    async fn report(&self, deployment: &str, host: &str, deployed: Option<&str>) {
        self.report_state(host, Self::state_of(deployment, deployed))
            .await;
    }

    /// `host` says a deploy is under way, with `running` still what is deployed.
    async fn report_busy(&self, deployment: &str, host: &str, running: &str) {
        let mut busy = Self::state_of(deployment, Some(running));
        busy.phase = Phase::Deploying;
        busy.busy = true;
        self.report_state(host, busy).await;
    }

    async fn decision(&self, deployment: &str, tag: &str) -> (String, String) {
        let row =
            sqlx::query("SELECT decision, reason FROM releases WHERE deployment = ? AND tag = ?")
                .bind(deployment)
                .bind(tag)
                .fetch_one(self.store.pool())
                .await
                .unwrap();
        (row.get("decision"), row.get("reason"))
    }

    async fn decided_count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM releases")
            .fetch_one(self.store.pool())
            .await
            .unwrap()
    }

    /// The deployment's deploys, `(tag, state)`, in order.
    async fn deploys(&self, deployment: &str) -> Vec<(String, String)> {
        sqlx::query("SELECT tag, state FROM deploys WHERE deployment = ? ORDER BY id")
            .bind(deployment)
            .fetch_all(self.store.pool())
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get("tag"), row.get("state")))
            .collect()
    }

    /// The audit details of this kind.
    async fn audit(&self, kind: &str) -> Vec<Value> {
        sqlx::query_scalar::<_, String>(
            "SELECT detail FROM audit_events WHERE kind = ? ORDER BY seq",
        )
        .bind(kind)
        .fetch_all(self.store.pool())
        .await
        .unwrap()
        .iter()
        .map(|detail| serde_json::from_str(detail).unwrap())
        .collect()
    }

    async fn hold_reason(&self, deployment: &str, tag: &str) -> Option<String> {
        sqlx::query_scalar("SELECT reason FROM release_holds WHERE deployment = ? AND tag = ?")
            .bind(deployment)
            .bind(tag)
            .fetch_optional(self.store.pool())
            .await
            .unwrap()
    }

    /// The host claims its queued deploy, and reports `outcome`.
    async fn finish(&self, host: &str, outcome: ReportedOutcome) {
        let host: landfall_core::ids::HostId = host.parse().unwrap();
        let work = self.store.next_work(&host).await.unwrap().work.unwrap();
        let body = DeployReportBody {
            deploy_id: work.deploy_id,
            outcome,
            steps: Vec::new(),
        };
        self.store
            .finish_deploy(&host, &BoundedReport::new(&body))
            .await
            .unwrap();
    }

    async fn chain_is_intact(&self) {
        assert_eq!(self.store.verify_audit().await.unwrap().first_bad, None);
    }
}

fn no_bundle(release: &'static str) -> MakeError {
    Box::new(move || {
        ReleaseError::Bundle(FetchError::Bundles {
            digest: digest(release),
            count: 0,
        })
    })
}

fn not_signed() -> MakeError {
    Box::new(|| ReleaseError::TagSignature(landfall_core::tag::TagVerifyError::NotSigned))
}

fn rate_limited(reset: RateLimitReset) -> MakeError {
    Box::new(move || {
        ReleaseError::Listing(FetchError::RateLimited {
            service: landfall_origin::fetch::Service::GitHubApi,
            url: "https://example.test/x".to_owned(),
            status: 403,
            reset,
        })
    })
}

fn server_error() -> MakeError {
    Box::new(|| {
        ReleaseError::Listing(FetchError::Status {
            url: "https://example.test/x".to_owned(),
            status: 502,
        })
    })
}

fn list_cap() -> MakeError {
    Box::new(|| {
        ReleaseError::Listing(FetchError::ListCap {
            url: "https://example.test/x".to_owned(),
            limit: 5000,
            what: "tags",
        })
    })
}
