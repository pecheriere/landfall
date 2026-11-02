//! What the processes see of the world outside them, kept in files: the releases
//! that exist, and a Docker that remembers what runs across restarts of the agent.

use std::collections::BTreeMap;
use std::fs;
use std::future::{Future, ready};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jiff::Timestamp;
use landfall_agent::compose::{self, OVERRIDE_FILE, Pin};
use landfall_agent::daemon::{Verifier, VerifyFailure};
use landfall_agent::docker::{
    ContainerId, ContainerInfo, Docker, DockerError, ServiceConfig, ServiceContainer,
};
use landfall_core::config::Config;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::release::RunCandidate;
use landfall_origin::attestation::VerifiedAttestation;
use landfall_origin::fetch::ListedTag;
use landfall_origin::release::{ReleaseError, ReleaseOrigin};
use landfall_server::watcher::ReleaseSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const RELEASES: &str = "releases.json";
const IMAGE: &str = "image";
const STARTED_AT: &str = "started-at";
const STOPPED: &str = "stopped";
const FAILING: &str = "failing";
const HOLD_UP: &str = "hold-up";
const AT_UP: &str = "at-up";
const UPS: &str = "ups";
const VERIFY_FAILS: &str = "verify-fails";

/// How often a held `up` looks whether it may go on.
const HOLD_POLL: Duration = Duration::from_millis(20);

/// A release, as the fakes report it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub tag: ReleaseTag,
    pub digest: ImageDigest,
    pub commit: CommitSha,
}

/// The digest a test release has, its own for each tag.
pub fn digest_of(tag: &str) -> ImageDigest {
    format!("sha256:{}", hex::encode(Sha256::digest(tag)))
        .parse()
        .unwrap()
}

fn commit_of(tag: &str) -> CommitSha {
    hex::encode(Sha256::digest(tag))[..40].parse().unwrap()
}

/// Replaces a file whole, so that another process reads the old or the new.
fn write_whole(path: &Path, bytes: &[u8]) {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    fs::write(&tmp, bytes).unwrap();
    fs::rename(&tmp, path).unwrap();
}

/// The directory of what the processes see. Cloning names the same one.
#[derive(Debug, Clone)]
pub struct World(pub PathBuf);

impl World {
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn releases(&self) -> Vec<Release> {
        match fs::read(self.file(RELEASES)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap(),
            Err(_) => Vec::new(),
        }
    }

    /// A new tag on the repository, with the digest given.
    pub fn publish_digest(&self, tag: &str, digest: &ImageDigest) -> Release {
        let release = Release {
            tag: tag.parse().unwrap(),
            digest: digest.clone(),
            commit: commit_of(tag),
        };
        let mut releases = self.releases();
        releases.push(release.clone());
        write_whole(
            &self.file(RELEASES),
            &serde_json::to_vec(&releases).unwrap(),
        );
        release
    }

    /// A new tag on the repository, with a digest of its own.
    pub fn publish(&self, tag: &str) -> Release {
        self.publish_digest(tag, &digest_of(tag))
    }

    fn origin_of(&self, tag: &ReleaseTag) -> Option<ReleaseOrigin> {
        let release = self.releases().into_iter().find(|r| r.tag == *tag)?;
        Some(origin(&release))
    }

    /// The checks fail on this release from now on.
    pub fn fail_checks_on(&self, tag: &str) {
        let digest = digest_of(tag);
        write_whole(&self.file(FAILING), digest.as_ref().as_bytes());
    }

    /// `up` waits, from now on, until [`release_up`](Self::release_up).
    pub fn hold_up(&self) {
        fs::write(self.file(HOLD_UP), "").unwrap();
        let _ = fs::remove_file(self.file(AT_UP));
    }

    pub fn release_up(&self) {
        fs::remove_file(self.file(HOLD_UP)).unwrap();
    }

    /// Whether a held `up` has been reached.
    pub fn at_up(&self) -> bool {
        self.file(AT_UP).exists()
    }

    /// The host's verification fails, from now on, in the way `how` says: `missing`,
    /// `shape` or `clock`.
    pub fn fail_verification(&self, how: &str) {
        write_whole(&self.file(VERIFY_FAILS), how.as_bytes());
    }

    /// The host's verification goes by the releases again.
    pub fn pass_verification(&self) {
        fs::remove_file(self.file(VERIFY_FAILS)).unwrap();
    }

    /// How many `up`s have gone through.
    pub fn ups(&self) -> usize {
        fs::read(self.file(UPS)).map_or(0, |bytes| bytes.len())
    }

    /// What runs now.
    pub fn image(&self) -> Option<String> {
        fs::read_to_string(self.file(IMAGE)).ok()
    }
}

/// What a verified release says.
pub fn origin(release: &Release) -> ReleaseOrigin {
    ReleaseOrigin {
        commit: release.commit.clone(),
        tag: None,
        attestation: VerifiedAttestation {
            digest: release.digest.clone(),
            san: String::new(),
            commit: release.commit.clone(),
            git_ref: String::new(),
            repo_id: 1,
            owner_id: 2,
            run_url: String::new(),
            rekor_log_index: 0,
            integrated_time: 0,
        },
        platforms: Vec::new(),
    }
}

/// The releases in a [`World`], for the controller's watcher.
#[derive(Debug)]
pub struct FileSource {
    pub world: World,
    pub repo: String,
}

impl FileSource {
    fn origin(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> Result<ReleaseOrigin, ReleaseError> {
        self.world
            .origin_of(tag)
            .ok_or_else(|| ReleaseError::UnknownDeployment(deployment.clone()))
    }
}

impl ReleaseSource for FileSource {
    fn prepare(&self) -> impl Future<Output = Result<(), String>> + Send {
        ready(Ok(()))
    }

    fn tags(
        &self,
        _: &DeploymentId,
    ) -> impl Future<Output = Result<Vec<ListedTag>, ReleaseError>> + Send {
        ready(Ok(self
            .world
            .releases()
            .into_iter()
            .map(|release| ListedTag {
                object: release.commit.as_ref().to_owned(),
                tag: release.tag,
            })
            .collect()))
    }

    fn verify(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> impl Future<Output = Result<ReleaseOrigin, ReleaseError>> + Send {
        ready(self.origin(deployment, tag))
    }

    fn attested_digests(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
        _: &CommitSha,
        _: &ImageDigest,
    ) -> impl Future<Output = Result<Vec<RunCandidate>, ReleaseError>> + Send {
        ready(self.origin(deployment, tag).map(|origin| {
            vec![RunCandidate {
                digest: origin.attestation.digest,
                run_url: format!("https://github.com/{}/actions/runs/1/attempts/1", self.repo),
            }]
        }))
    }
}

/// The releases in a [`World`], for the agent's own verification.
#[derive(Debug)]
pub struct FileVerifier(pub World);

impl Verifier for FileVerifier {
    fn verify(
        &self,
        _: &Config,
        _: &DeploymentId,
        tag: &ReleaseTag,
    ) -> impl Future<Output = Result<ReleaseOrigin, VerifyFailure>> + Send {
        if let Ok(how) = fs::read_to_string(self.0.file(VERIFY_FAILS)) {
            return ready(Err(match how.as_str() {
                "missing" => VerifyFailure::Missing("the registry says 404".to_owned()),
                "clock" => VerifyFailure::ClockBehind("the log is ahead".to_owned()),
                _ => VerifyFailure::Unavailable("expected exactly one bundle, found 2".to_owned()),
            }));
        }
        ready(
            self.0
                .origin_of(tag)
                .ok_or_else(|| VerifyFailure::Missing(format!("no release {tag}"))),
        )
    }
}

/// A Docker with one service in it, which keeps what it does in a [`World`]: what
/// `up` starts is what the override pins, the way real compose goes by it. Its checks
/// pass unless the image is the one the world says fails.
#[derive(Debug)]
pub struct SimDocker(pub World);

impl SimDocker {
    fn id() -> ContainerId {
        "0123456789ab".parse().unwrap()
    }

    fn up_now(&self) -> bool {
        self.0.image().is_some() && !self.0.file(STOPPED).exists()
    }

    fn found(&self) -> Option<ContainerId> {
        self.up_now().then(Self::id)
    }

    fn pinned(dir: &Path, service: &str) -> Option<String> {
        let file = fs::read(dir.join(OVERRIDE_FILE)).ok()?;
        match compose::pinned_image(&file, service) {
            Pin::Image(image) => Some(image.to_owned()),
            _ => None,
        }
    }

    fn service(dir: &Path, service: &str) -> ServiceConfig {
        ServiceConfig {
            image: Self::pinned(dir, service),
            has_build: false,
            replicas: 1,
        }
    }
}

impl Docker for SimDocker {
    fn pull(&self, _: &str) -> impl Future<Output = Result<(), DockerError>> + Send {
        ready(Ok(()))
    }

    fn compose_service(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<ServiceConfig, DockerError>> + Send {
        ready(Ok(Self::service(dir, service)))
    }

    fn compose_service_checked(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<ServiceConfig, DockerError>> + Send {
        ready(Ok(Self::service(dir, service)))
    }

    async fn compose_up(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        if self.0.file(HOLD_UP).exists() {
            fs::write(self.0.file(AT_UP), "").unwrap();
            while self.0.file(HOLD_UP).exists() {
                tokio::time::sleep(HOLD_POLL).await;
            }
        }
        let image = Self::pinned(dir, service).ok_or(DockerError::BadOutput {
            command: "compose up",
            reason: "nothing pinned",
        })?;
        write_whole(&self.0.file(IMAGE), image.as_bytes());
        write_whole(
            &self.0.file(STARTED_AT),
            Timestamp::now().to_string().as_bytes(),
        );
        let _ = fs::remove_file(self.0.file(STOPPED));
        let ups = "x".repeat(self.0.ups() + 1);
        write_whole(&self.0.file(UPS), ups.as_bytes());
        Ok(())
    }

    fn compose_stop(
        &self,
        _: &Path,
        _: &str,
    ) -> impl Future<Output = Result<(), DockerError>> + Send {
        fs::write(self.0.file(STOPPED), "").unwrap();
        ready(Ok(()))
    }

    fn container(
        &self,
        _: &Path,
        _: &str,
    ) -> impl Future<Output = Result<Option<ContainerId>, DockerError>> + Send {
        ready(Ok(self.found()))
    }

    fn container_at(
        &self,
        _: &Path,
        _: &str,
    ) -> impl Future<Output = Result<Option<ContainerId>, DockerError>> + Send {
        ready(Ok(self.found()))
    }

    fn inspect(
        &self,
        _: &ContainerId,
    ) -> impl Future<Output = Result<ContainerInfo, DockerError>> + Send {
        let started = fs::read_to_string(self.0.file(STARTED_AT)).unwrap();
        ready(Ok(ContainerInfo {
            image: self.0.image().unwrap(),
            status: "running".to_owned(),
            health: None,
            started_at: started.parse().unwrap(),
            networks: BTreeMap::new(),
        }))
    }

    fn service_containers(
        &self,
        dir: &Path,
        _: &str,
    ) -> impl Future<Output = Result<Vec<ServiceContainer>, DockerError>> + Send {
        let found = self.0.image().map(|_| ServiceContainer {
            id: Self::id(),
            running: self.up_now(),
            in_project: true,
            working_dir: Some(dir.to_string_lossy().into_owned()),
        });
        ready(Ok(found.into_iter().collect()))
    }

    fn exec(
        &self,
        _: &ContainerId,
        _: &[String],
    ) -> impl Future<Output = Result<bool, DockerError>> + Send {
        let failing = fs::read_to_string(self.0.file(FAILING)).unwrap_or_default();
        let image = self.0.image().unwrap_or_default();
        ready(Ok(failing.is_empty() || !image.ends_with(&failing)))
    }

    fn logs_contain(
        &self,
        _: &ContainerId,
        _: Timestamp,
        _: Timestamp,
        _: &str,
    ) -> impl Future<Output = Result<bool, DockerError>> + Send {
        ready(Ok(false))
    }
}
