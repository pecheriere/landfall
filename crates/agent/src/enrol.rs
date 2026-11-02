//! Enrolment: the host's key, and the one request that tells the controller
//! about it. The key and the code are secrets: neither reaches an error, the
//! journal or stdout.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use landfall_core::ids::HostId;
use landfall_core::protocol::{EnrolCode, EnrolRequest, SigningKey};
use reqwest::header::CONTENT_TYPE;
use rustix::fs::{Mode, OFlags};
use serde::Serialize;

use crate::client::{self, ControllerError, ControllerUrl};
use crate::state::{StateDir, StateError};

/// The private key's file in the state directory: its 32 raw bytes.
pub const KEY_FILE: &str = "agent.key";
const KEY_LEN: usize = 32;
/// The most of a code file that is read: a code is 64 hex digits and a newline.
const CODE_FILE_CAP: u64 = 256;

/// Why enrolment did not go through, or the key can't be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnrolError {
    /// The state directory can't be used.
    #[error(transparent)]
    State(#[from] StateError),
    /// A file operation on the key failed.
    #[error("key file {}: {op}: {source}", .path.display())]
    Key {
        /// What was being done.
        op: &'static str,
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The host has no key yet.
    #[error("no key at {}: enrol this host first with `landfall-agent enrol`", .0.display())]
    NotEnrolled(PathBuf),
    /// The key file is not a private, regular file of the agent's.
    #[error(
        "key file {} must be a regular file owned by the agent's user, readable by nobody else: {reason}",
        .path.display()
    )]
    KeyNotPrivate {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// The key file does not hold a key. What it does hold is not repeated.
    #[error("key file {} does not hold a key of {KEY_LEN} bytes", .0.display())]
    KeyInvalid(PathBuf),
    /// The operating system's generator failed.
    #[error("cannot generate a key: {0}")]
    Random(getrandom::Error),
    /// The code file could not be read.
    #[error("code file {}: {source}", .path.display())]
    CodeFile {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The code file is not a regular file.
    #[error("code file {} must be a regular file", .0.display())]
    CodeNotRegular(PathBuf),
    /// The code file does not hold a code. What it does hold is not repeated.
    #[error("code file {} does not hold an enrolment code of 64 lowercase hex digits", .0.display())]
    CodeInvalid(PathBuf),
    /// The request did not go through.
    #[error(transparent)]
    Controller(#[from] ControllerError),
}

/// What `enrol` prints: nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Enrolled {
    /// The host the key is enrolled for.
    pub host: HostId,
    /// The public key, 64 hex digits.
    pub public_key: String,
}

fn key_error(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> EnrolError {
    let path = path.to_owned();
    move |source| EnrolError::Key { op, path, source }
}

/// Reads the host's key, after checking that nobody else can read it. The state
/// directory is private to the agent, so a look before opening is enough.
///
/// # Errors
///
/// [`EnrolError::NotEnrolled`] without a key, and [`EnrolError`] for a key
/// file that is not private or holds no key.
pub fn load_key(state: &StateDir) -> Result<SigningKey, EnrolError> {
    let path = state.path().join(KEY_FILE);
    let not_private = |reason: String| EnrolError::KeyNotPrivate {
        path: path.clone(),
        reason,
    };
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(EnrolError::NotEnrolled(path));
        }
        Err(e) => return Err(key_error("inspect", &path)(e)),
    };
    if !meta.is_file() {
        return Err(not_private("not a regular file".to_owned()));
    }
    let agent = rustix::process::geteuid().as_raw();
    if meta.uid() != agent {
        return Err(not_private(format!(
            "owned by uid {}, not {agent}",
            meta.uid()
        )));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(not_private(format!("mode {mode:o}")));
    }
    let mut bytes = Vec::with_capacity(KEY_LEN);
    File::open(&path)
        .map_err(key_error("open", &path))?
        .take(u64::try_from(KEY_LEN).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(key_error("read", &path))?;
    let seed: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EnrolError::KeyInvalid(path.clone()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The host's key, generated if it has none. An existing key is never
/// overwritten: it is read and used, so a retry after a failed request, or a
/// re-enrolment, keeps it. The key appears under its name whole, or not at all:
/// a temporary file (0600) is written, synced and linked, and a link never
/// replaces what is there.
///
/// # Errors
///
/// [`EnrolError`] if a key can't be read or written.
pub fn load_or_create_key(state: &StateDir) -> Result<SigningKey, EnrolError> {
    match load_key(state) {
        Err(EnrolError::NotEnrolled(_)) => {}
        result => return result,
    }
    let mut seed = [0_u8; KEY_LEN];
    getrandom::fill(&mut seed).map_err(EnrolError::Random)?;
    let path = state.path().join(KEY_FILE);
    let tmp = state.path().join(format!(".{KEY_FILE}.tmp"));
    // A stale file could have any mode, or be a link to anywhere: it goes, and
    // this one is new or nothing.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(key_error("remove stale", &tmp)(e)),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(key_error("create", &tmp))?;
    file.write_all(&seed).map_err(key_error("write", &tmp))?;
    file.sync_all().map_err(key_error("sync", &tmp))?;
    drop(file);
    let linked = fs::hard_link(&tmp, &path);
    fs::remove_file(&tmp).map_err(key_error("remove", &tmp))?;
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return load_key(state),
        Err(e) => return Err(key_error("link", &path)(e)),
    }
    File::open(state.path())
        .and_then(|dir| dir.sync_all())
        .map_err(key_error("sync directory", state.path()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Reads an enrolment code from its file, without any of its content reaching
/// an error. It must be a regular file itself: a link is not followed, and a
/// FIFO or a device neither blocks the open nor gets read.
///
/// # Errors
///
/// [`EnrolError::CodeFile`], [`EnrolError::CodeNotRegular`] or
/// [`EnrolError::CodeInvalid`].
pub fn read_code(path: &Path) -> Result<EnrolCode, EnrolError> {
    let code_file = |source| EnrolError::CodeFile {
        path: path.to_owned(),
        source,
    };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = File::from(
        rustix::fs::open(path, flags, Mode::empty()).map_err(|e| code_file(io::Error::from(e)))?,
    );
    if !file.metadata().map_err(code_file)?.is_file() {
        return Err(EnrolError::CodeNotRegular(path.to_owned()));
    }
    let mut text = String::new();
    file.take(CODE_FILE_CAP)
        .read_to_string(&mut text)
        .map_err(code_file)?;
    text.trim()
        .parse()
        .map_err(|_| EnrolError::CodeInvalid(path.to_owned()))
}

/// Enrols this host: makes sure it has a key, and sends the public key with the
/// code from `code_file`.
///
/// # Errors
///
/// [`EnrolError`] if the state, the key, the code or the request fail. The key
/// stays, so the command can be run again with a new code.
pub async fn enrol(
    url: &ControllerUrl,
    host: &HostId,
    state_dir: &Path,
    code_file: &Path,
) -> Result<Enrolled, EnrolError> {
    let state = StateDir::open(state_dir)?;
    let _lock = state.lock_daemon()?;
    let code = read_code(code_file)?;
    // Before the key: a host that can't make a request, for want of CA certificates
    // say, is told so with nothing left behind.
    let http = client::http_client(url)?;
    let key = load_or_create_key(&state)?;
    let public_key = key.verifying_key();
    let request = EnrolRequest {
        code,
        host: host.clone(),
        public_key,
    };
    let body = serde_json::to_vec(&request)
        .map_err(|error| ControllerError::Serialise(error.to_string()))?;
    let response = http
        .post(url.enrol_url())
        .timeout(client::REQUEST_TIMEOUT)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|error| ControllerError::Transport(client::error_chain(&error)))?;
    client::answer(response).await?;
    Ok(Enrolled {
        host: host.clone(),
        public_key: hex::encode(public_key.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use landfall_core::protocol::{EnrolRequest, SigningKey};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{EnrolError, KEY_FILE, enrol, load_key, load_or_create_key, read_code};
    use crate::client::{ControllerError, ControllerUrl};
    use crate::state::{StateDir, StateError};

    const CODE: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

    struct Fixture {
        tmp: tempfile::TempDir,
        code_file: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let code_file = tmp.path().join("code");
        fs::write(&code_file, format!("{CODE}\n")).unwrap();
        Fixture { tmp, code_file }
    }

    impl Fixture {
        fn state_dir(&self) -> &Path {
            self.tmp.path()
        }

        fn state(&self) -> StateDir {
            StateDir::open(self.state_dir()).unwrap()
        }

        fn key_path(&self) -> PathBuf {
            self.state_dir().join(KEY_FILE)
        }

        async fn enrol(&self, server: &MockServer) -> Result<super::Enrolled, EnrolError> {
            let url = ControllerUrl::parse(&server.uri(), true).unwrap();
            enrol(
                &url,
                &"home-1".parse().unwrap(),
                self.state_dir(),
                &self.code_file,
            )
            .await
        }
    }

    async fn controller(status: u16, body: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/agent/v1/enrol"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        server
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn key_file_is_private_and_never_overwritten() {
        let f = fixture();
        let key = load_or_create_key(&f.state()).unwrap();
        assert_eq!(mode(&f.key_path()), 0o600);
        let bytes = fs::read(f.key_path()).unwrap();
        assert_eq!(bytes.len(), 32);

        let again = load_or_create_key(&f.state()).unwrap();
        assert_eq!(fs::read(f.key_path()).unwrap(), bytes);
        assert_eq!(again.to_bytes(), key.to_bytes());
        assert_eq!(load_key(&f.state()).unwrap().to_bytes(), key.to_bytes());
        assert!(!f.state_dir().join(".agent.key.tmp").exists());
    }

    #[test]
    fn a_stale_temporary_file_cannot_loosen_or_redirect_the_key() {
        let f = fixture();
        let tmp = f.state_dir().join(".agent.key.tmp");
        // Left by something else, readable by everyone.
        fs::write(&tmp, b"stale").unwrap();
        fs::set_permissions(&tmp, Permissions::from_mode(0o644)).unwrap();
        load_or_create_key(&f.state()).unwrap();
        assert_eq!(mode(&f.key_path()), 0o600);
        assert!(!tmp.exists());

        // A link: the seed must not go through it.
        let g = fixture();
        let target = g.state_dir().join("elsewhere");
        fs::write(&target, b"untouched").unwrap();
        let tmp = g.state_dir().join(".agent.key.tmp");
        std::os::unix::fs::symlink(&target, &tmp).unwrap();
        load_or_create_key(&g.state()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        assert_eq!(mode(&g.key_path()), 0o600);
        assert!(fs::symlink_metadata(g.key_path()).unwrap().is_file());
    }

    #[test]
    fn a_code_file_that_is_not_a_regular_file_is_refused() {
        let f = fixture();
        let dir = f.state_dir().join("dir");
        fs::create_dir(&dir).unwrap();
        let err = read_code(&dir).err().unwrap();
        assert!(matches!(err, EnrolError::CodeNotRegular(_)), "{err}");

        // Would block a plain open for ever.
        let fifo = f.state_dir().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let err = read_code(&fifo).err().unwrap();
        assert!(matches!(err, EnrolError::CodeNotRegular(_)), "{err}");

        // A link to a good code is still not followed.
        let link = f.state_dir().join("link");
        std::os::unix::fs::symlink(&f.code_file, &link).unwrap();
        let err = read_code(&link).err().unwrap();
        assert!(matches!(err, EnrolError::CodeFile { .. }), "{err}");
    }

    #[test]
    fn keys_differ_from_host_to_host() {
        let (a, b) = (fixture(), fixture());
        assert_ne!(
            load_or_create_key(&a.state()).unwrap().to_bytes(),
            load_or_create_key(&b.state()).unwrap().to_bytes()
        );
    }

    #[test]
    fn a_key_others_can_read_is_refused() {
        let f = fixture();
        load_or_create_key(&f.state()).unwrap();
        for loose in [0o640, 0o604, 0o644] {
            fs::set_permissions(f.key_path(), Permissions::from_mode(loose)).unwrap();
            let err = load_key(&f.state()).err().unwrap();
            assert!(matches!(err, EnrolError::KeyNotPrivate { .. }), "{err}");
        }
    }

    #[test]
    fn a_link_for_a_key_is_refused_and_left_alone() {
        let f = fixture();
        let elsewhere = f.state_dir().join("elsewhere");
        fs::write(&elsewhere, [7_u8; 32]).unwrap();
        fs::set_permissions(&elsewhere, Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, f.key_path()).unwrap();
        for attempt in [load_key(&f.state()), load_or_create_key(&f.state())] {
            let err = attempt.err().unwrap();
            assert!(matches!(err, EnrolError::KeyNotPrivate { .. }), "{err}");
        }
        assert_eq!(fs::read(&elsewhere).unwrap(), [7_u8; 32]);
    }

    #[test]
    fn a_damaged_key_is_refused_without_repeating_it_and_not_replaced() {
        let f = fixture();
        fs::write(f.key_path(), b"sekret-half-a-key").unwrap();
        fs::set_permissions(f.key_path(), Permissions::from_mode(0o600)).unwrap();
        let err = load_or_create_key(&f.state()).err().unwrap();
        assert!(matches!(err, EnrolError::KeyInvalid(_)), "{err}");
        assert!(!err.to_string().contains("sekret"), "{err}");
        assert_eq!(fs::read(f.key_path()).unwrap(), b"sekret-half-a-key");
    }

    #[test]
    fn running_without_a_key_says_to_enrol() {
        let f = fixture();
        let err = load_key(&f.state()).err().unwrap();
        assert!(matches!(err, EnrolError::NotEnrolled(_)), "{err}");
        assert!(err.to_string().contains("landfall-agent enrol"), "{err}");
    }

    #[test]
    fn a_bad_code_file_is_refused_without_repeating_it() {
        let f = fixture();
        // One digit short and uppercase: both near enough to be a real code.
        for bad in [&CODE[1..], &CODE.to_uppercase()] {
            fs::write(&f.code_file, bad).unwrap();
            let err = read_code(&f.code_file).err().unwrap();
            assert!(matches!(err, EnrolError::CodeInvalid(_)), "{err}");
            assert!(!err.to_string().contains(bad), "{err}");
        }
        let err = read_code(&f.state_dir().join("absent")).err().unwrap();
        assert!(matches!(err, EnrolError::CodeFile { .. }), "{err}");
    }

    #[test]
    fn a_huge_code_file_is_not_read_whole() {
        let f = fixture();
        fs::write(&f.code_file, "a".repeat(10_000_000)).unwrap();
        let err = read_code(&f.code_file).err().unwrap();
        assert!(matches!(err, EnrolError::CodeInvalid(_)), "{err}");
    }

    #[tokio::test]
    async fn enrol_sends_the_public_key_with_the_code_and_prints_no_secret() {
        let f = fixture();
        let server = controller(200, "").await;

        let enrolled = f.enrol(&server).await.unwrap();

        let key = SigningKey::from_bytes(&fs::read(f.key_path()).unwrap().try_into().unwrap());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let sent: EnrolRequest = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(sent.code.to_hex(), CODE);
        assert_eq!(sent.host.as_ref(), "home-1");
        assert_eq!(sent.public_key, key.verifying_key());

        assert_eq!(
            enrolled.public_key,
            hex::encode(key.verifying_key().as_bytes())
        );
        let printed = serde_json::to_string(&enrolled).unwrap();
        assert!(!printed.contains(CODE), "{printed}");
        assert!(!printed.contains(&hex::encode(key.to_bytes())), "{printed}");
    }

    #[tokio::test]
    async fn a_refused_enrolment_keeps_the_key_for_a_retry_and_shows_no_secret() {
        let f = fixture();
        let server = controller(403, "code\nalready used").await;

        let err = f.enrol(&server).await.unwrap_err();

        let text = err.to_string();
        assert!(
            matches!(err, EnrolError::Controller(ControllerError::Status { .. })),
            "{text}"
        );
        assert!(text.contains("403") && !text.contains('\n'), "{text}");
        assert!(!text.contains(CODE), "{text}");
        let bytes = fs::read(f.key_path()).unwrap();
        assert!(!text.contains(&hex::encode(&bytes)), "{text}");

        let server = controller(200, "").await;
        f.enrol(&server).await.unwrap();
        assert_eq!(fs::read(f.key_path()).unwrap(), bytes, "the same key");
    }

    #[tokio::test]
    async fn the_apis_refusal_is_told_by_its_code_and_title_not_as_raw_json() {
        let f = fixture();
        let server = MockServer::start().await;
        let body = r#"{"code":"invalid_code","title":"the code\nis refused","status":403}"#;
        Mock::given(method("POST"))
            .and(path("/agent/v1/enrol"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("content-type", "application/problem+json")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;

        let text = f.enrol(&server).await.unwrap_err().to_string();

        assert!(text.contains("403"), "{text}");
        assert!(text.contains("invalid_code: "), "{text}");
        assert!(text.contains("the code"), "{text}");
        assert!(!text.contains('{') && !text.contains('\n'), "{text}");
    }

    #[tokio::test]
    async fn a_bad_code_generates_no_key() {
        let f = fixture();
        fs::write(&f.code_file, "not a code").unwrap();
        let server = controller(200, "").await;
        let err = f.enrol(&server).await.unwrap_err();
        assert!(matches!(err, EnrolError::CodeInvalid(_)), "{err}");
        assert!(!f.key_path().exists());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn enrol_waits_for_nobody_while_a_daemon_runs() {
        let f = fixture();
        let _daemon = f.state().lock_daemon().unwrap();
        let server = controller(200, "").await;
        let err = f.enrol(&server).await.unwrap_err();
        assert!(
            matches!(err, EnrolError::State(StateError::DaemonBusy(_))),
            "{err}"
        );
    }
}
