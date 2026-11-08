//! Where the controller is and which token goes to it.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::{
    Env, Files, SettingsError, SystemFiles, TokenFileError, TokenSource, judge_token_file, resolve,
};
use crate::cli::ApiArgs;

const TOKEN: &str = "lf_Secret-token_0123456789";

/// An environment holding only what a test sets.
#[derive(Default)]
struct FakeEnv(HashMap<&'static str, OsString>);

impl FakeEnv {
    fn with(mut self, name: &'static str, value: impl Into<OsString>) -> Self {
        self.0.insert(name, value.into());
        self
    }
}

impl Env for FakeEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        self.0.get(name).cloned()
    }
}

/// Configuration files and token files in memory, the token file's checks taken as passed.
#[derive(Default)]
struct FakeFiles {
    configs: HashMap<PathBuf, String>,
    tokens: HashMap<PathBuf, Vec<u8>>,
}

impl FakeFiles {
    fn config(mut self, path: &str, text: &str) -> Self {
        self.configs.insert(PathBuf::from(path), text.to_owned());
        self
    }

    fn token(mut self, path: &str, bytes: &[u8]) -> Self {
        self.tokens.insert(PathBuf::from(path), bytes.to_vec());
        self
    }
}

impl Files for FakeFiles {
    fn config(&self, path: &Path) -> io::Result<String> {
        self.configs
            .get(path)
            .cloned()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn token_file(&self, path: &Path) -> Result<Vec<u8>, TokenFileError> {
        self.tokens
            .get(path)
            .cloned()
            .ok_or_else(|| TokenFileError::Open(io::ErrorKind::NotFound.into()))
    }
}

fn args() -> ApiArgs {
    ApiArgs::default()
}

fn with_controller(controller: &str) -> ApiArgs {
    ApiArgs {
        controller: Some(controller.to_owned()),
        ..ApiArgs::default()
    }
}

/// The environment of someone with a home and no configuration.
fn home() -> FakeEnv {
    FakeEnv::default().with("HOME", "/home/operator")
}

#[test]
fn flag_beats_env_beats_file() {
    let files = FakeFiles::default().config(
        "/home/operator/.config/landfall/cli.toml",
        "controller = \"https://file.example\"\n",
    );
    let env = home().with("LANDFALL_CONTROLLER", "https://env.example");

    let flagged = resolve(&with_controller("https://flag.example"), &env, &files).unwrap();
    assert_eq!(flagged.controller.as_str(), "https://flag.example");
    let from_env = resolve(&args(), &env, &files).unwrap();
    assert_eq!(from_env.controller.as_str(), "https://env.example");
    let from_file = resolve(&args(), &home(), &files).unwrap();
    assert_eq!(from_file.controller.as_str(), "https://file.example");

    // XDG_CONFIG_HOME comes before HOME, and a relative one is ignored.
    let files = files.config(
        "/xdg/landfall/cli.toml",
        "controller = \"https://xdg.example\"\n",
    );
    let xdg = home().with("XDG_CONFIG_HOME", "/xdg");
    assert_eq!(
        resolve(&args(), &xdg, &files).unwrap().controller.as_str(),
        "https://xdg.example"
    );
    let relative = home().with("XDG_CONFIG_HOME", "xdg");
    assert_eq!(
        resolve(&args(), &relative, &files)
            .unwrap()
            .controller
            .as_str(),
        "https://file.example"
    );

    // --cli-config names another file, which replaces the default one.
    let files = files.config(
        "/elsewhere.toml",
        "controller = \"https://named.example\"\n",
    );
    let named = ApiArgs {
        cli_config: Some(PathBuf::from("/elsewhere.toml")),
        ..ApiArgs::default()
    };
    assert_eq!(
        resolve(&named, &home(), &files)
            .unwrap()
            .controller
            .as_str(),
        "https://named.example"
    );

    // No controller anywhere: say where one goes.
    let error = resolve(&args(), &home(), &FakeFiles::default()).unwrap_err();
    assert!(matches!(error, SettingsError::NoController), "{error:?}");
    assert!(error.to_string().contains("LANDFALL_CONTROLLER"), "{error}");
}

#[test]
fn token_sources_in_order() {
    let files = FakeFiles::default()
        .token("/flag-token", b"from-flag\n")
        .token("/env-token", b"from-env-file")
        .token("/config-token", b"from-config\n")
        .config(
            "/home/operator/.config/landfall/cli.toml",
            "token_file = \"/config-token\"\n",
        );
    let base = with_controller("https://controller.example");

    let from_env = resolve(
        &base,
        &home().with("LANDFALL_TOKEN", "from-env"),
        &FakeFiles::default(),
    )
    .unwrap();
    let from_config = resolve(&base, &home(), &files).unwrap();
    for (settings, want, source) in [
        (&from_env, "from-env", TokenSource::Env),
        (
            &from_config,
            "from-config",
            TokenSource::Config(PathBuf::from("/config-token")),
        ),
    ] {
        let token = settings.token.as_ref().unwrap();
        assert_eq!(token.header().to_str().unwrap(), format!("Bearer {want}"));
        assert!(token.header().is_sensitive());
        assert_eq!(token.source(), &source);
    }

    let empty_files = FakeFiles::default()
        .token("/flag-token", b"from-flag\n")
        .token("/env-token", b"from-env-file");
    let flag = ApiArgs {
        token_file: Some(PathBuf::from("/flag-token")),
        ..base.clone()
    };
    let settings = resolve(&flag, &home().with("LANDFALL_TOKEN", ""), &empty_files).unwrap();
    let token = settings.token.unwrap();
    assert_eq!(token.header().to_str().unwrap(), "Bearer from-flag");
    assert_eq!(
        token.source(),
        &TokenSource::Flag(PathBuf::from("/flag-token"))
    );

    let env = home().with("LANDFALL_TOKEN_FILE", "/env-token");
    let token = resolve(&base, &env, &empty_files).unwrap().token.unwrap();
    assert_eq!(token.header().to_str().unwrap(), "Bearer from-env-file");
    assert_eq!(
        token.source(),
        &TokenSource::EnvFile(PathBuf::from("/env-token"))
    );
}

#[test]
fn two_token_sources_are_refused_naming_both() {
    let files = FakeFiles::default().token("/token", b"abc").config(
        "/home/operator/.config/landfall/cli.toml",
        "token_file = \"/token\"\n",
    );
    let base = with_controller("https://controller.example");
    let flag = ApiArgs {
        token_file: Some(PathBuf::from("/token")),
        ..base.clone()
    };
    for (args, env, first, second) in [
        (
            &base,
            home().with("LANDFALL_TOKEN", "abc"),
            "LANDFALL_TOKEN",
            "token_file",
        ),
        (
            &flag,
            home().with("LANDFALL_TOKEN", "abc"),
            "LANDFALL_TOKEN",
            "--token-file",
        ),
        (&flag, home(), "--token-file", "token_file"),
        (
            &base,
            home().with("LANDFALL_TOKEN_FILE", "/token"),
            "LANDFALL_TOKEN_FILE",
            "token_file",
        ),
    ] {
        let error = resolve(args, &env, &files).unwrap_err();
        assert!(
            matches!(error, SettingsError::TwoTokenSources { .. }),
            "{error:?}"
        );
        let text = error.to_string();
        assert!(text.contains(first) && text.contains(second), "{text}");
        assert!(!text.contains("abc"), "{text}");
    }
}

#[test]
fn no_token_is_allowed_for_a_proxy_that_adds_one() {
    let settings = resolve(
        &with_controller("https://controller.example"),
        &home(),
        &FakeFiles::default(),
    )
    .unwrap();
    assert!(settings.token.is_none());
}

#[test]
fn insecure_url_is_refused() {
    let files = FakeFiles::default();
    for (url, flag, allowed) in [
        ("http://controller.example", false, false),
        ("http://controller.example", true, false),
        ("http://127.0.0.1:8080", false, false),
        ("http://127.0.0.1:8080", true, true),
        ("http://landfall.example.ts.net", false, false),
        ("http://landfall.example.ts.net", true, true),
        ("https://controller.example", false, true),
    ] {
        let args = ApiArgs {
            allow_insecure_controller: flag,
            ..with_controller(url)
        };
        let result = resolve(&args, &home(), &files);
        if allowed {
            assert!(result.is_ok(), "{url} with {flag}: {result:?}");
            continue;
        }
        let error = result.unwrap_err();
        assert!(matches!(error, SettingsError::Controller(_)), "{error:?}");
        let text = error.to_string();
        assert!(text.contains("token"), "{url} with {flag}: {text}");
        assert!(!text.contains(url), "the URL is not repeated: {text}");
    }

    // The configuration file can allow it too.
    let files = FakeFiles::default().config(
        "/home/operator/.config/landfall/cli.toml",
        "controller = \"http://127.0.0.1:8080\"\nallow_insecure_controller = true\n",
    );
    assert!(resolve(&args(), &home(), &files).is_ok());
}

#[test]
fn unknown_config_key_is_refused() {
    let files = FakeFiles::default().config(
        "/home/operator/.config/landfall/cli.toml",
        "controller = \"https://controller.example\"\ntoken = \"abc\"\n",
    );
    let error = resolve(&args(), &home(), &files).unwrap_err();
    assert!(
        matches!(error, SettingsError::ConfigSyntax { .. }),
        "{error:?}"
    );
}

#[test]
fn relative_token_file_in_config_is_refused() {
    let files = FakeFiles::default().config(
        "/home/operator/.config/landfall/cli.toml",
        "controller = \"https://controller.example\"\ntoken_file = \"token\"\n",
    );
    let error = resolve(&args(), &home(), &files).unwrap_err();
    assert!(
        matches!(error, SettingsError::RelativeTokenFile { .. }),
        "{error:?}"
    );
}

#[test]
fn named_config_file_must_exist() {
    let named = ApiArgs {
        cli_config: Some(PathBuf::from("/missing.toml")),
        ..with_controller("https://controller.example")
    };
    let error = resolve(&named, &home(), &FakeFiles::default()).unwrap_err();
    assert!(
        matches!(error, SettingsError::ConfigMissing { .. }),
        "{error:?}"
    );
    // A missing default file is fine.
    assert!(
        resolve(
            &with_controller("https://controller.example"),
            &home(),
            &FakeFiles::default()
        )
        .is_ok()
    );
}

#[test]
fn token_debug_is_redacted() {
    let settings = resolve(
        &with_controller("https://controller.example"),
        &home().with("LANDFALL_TOKEN", TOKEN),
        &FakeFiles::default(),
    )
    .unwrap();
    let debug = format!("{settings:?}");
    assert!(!debug.contains(TOKEN), "{debug}");
    assert!(debug.contains("redacted"), "{debug}");
}

#[test]
fn token_with_odd_characters_is_refused() {
    let base = with_controller("https://controller.example");
    for bad in [
        &b"two\nlines"[..],
        b"trailing\n\n",
        b"space inside",
        b"",
        b"\n",
        b"caf\xc3\xa9",
        b"\xff",
        b"crlf\r\n",
        b"quote\"",
    ] {
        let files = FakeFiles::default().token("/token", bad);
        let flag = ApiArgs {
            token_file: Some(PathBuf::from("/token")),
            ..base.clone()
        };
        let error = resolve(&flag, &home(), &files).unwrap_err();
        assert!(
            matches!(error, SettingsError::Token { .. }),
            "{bad:?}: {error:?}"
        );
    }
    let error = resolve(
        &base,
        &home().with("LANDFALL_TOKEN", "a b"),
        &FakeFiles::default(),
    )
    .unwrap_err();
    assert!(matches!(error, SettingsError::Token { .. }), "{error:?}");
    assert!(!error.to_string().contains("a b"), "{error}");
}

/// A token file in a directory of its own, with `mode`.
fn token_file(dir: &Path, bytes: &[u8], mode: u32) -> PathBuf {
    let path = dir.join("token");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn readable_token_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = token_file(dir.path(), b"abc\n", 0o644);
    let error = SystemFiles.token_file(&path).unwrap_err();
    assert!(
        matches!(error, TokenFileError::Readable { mode: 0o644 }),
        "{error:?}"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(SystemFiles.token_file(&path).is_err());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(SystemFiles.token_file(&path).unwrap(), b"abc\n");

    // Through resolve, the error names the file and says why.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o604)).unwrap();
    let flag = ApiArgs {
        token_file: Some(path.clone()),
        ..with_controller("https://controller.example")
    };
    let error = resolve(&flag, &home(), &SystemFiles).unwrap_err();
    assert!(
        matches!(error, SettingsError::TokenFile { .. }),
        "{error:?}"
    );
}

#[test]
fn linked_token_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = token_file(dir.path(), b"abc", 0o600);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let error = SystemFiles.token_file(&link).unwrap_err();
    assert!(matches!(error, TokenFileError::Linked), "{error:?}");

    // A directory, or anything but a regular file, is refused too.
    let error = SystemFiles.token_file(dir.path()).unwrap_err();
    assert!(matches!(error, TokenFileError::NotRegular), "{error:?}");
}

#[test]
fn token_file_over_256_bytes_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = token_file(dir.path(), &[b'a'; 257], 0o600);
    let error = SystemFiles.token_file(&path).unwrap_err();
    assert!(matches!(error, TokenFileError::TooLarge), "{error:?}");

    let path = token_file(dir.path(), &[b'a'; 256], 0o600);
    assert_eq!(SystemFiles.token_file(&path).unwrap().len(), 256);

    // The same limit holds whatever reads the file.
    let files = FakeFiles::default().token("/token", &[b'a'; 257]);
    let flag = ApiArgs {
        token_file: Some(PathBuf::from("/token")),
        ..with_controller("https://controller.example")
    };
    assert!(resolve(&flag, &home(), &files).is_err());
}

#[test]
fn token_file_owned_by_another_is_refused() {
    // Another user's file can't be made without root, so the judgement is tested on what the
    // descriptor says, and the real file of this user passes it above.
    let error = judge_token_file(true, 0o100_600, 0, 1000).unwrap_err();
    assert!(
        matches!(error, TokenFileError::NotOwned { owner: 0 }),
        "{error:?}"
    );
    assert!(error.to_string().contains("uid 0"), "{error}");
    assert!(judge_token_file(true, 0o100_600, 1000, 1000).is_ok());
    assert!(matches!(
        judge_token_file(false, 0o40_700, 1000, 1000),
        Err(TokenFileError::NotRegular)
    ));
    assert!(matches!(
        judge_token_file(true, 0o100_660, 1000, 1000),
        Err(TokenFileError::Readable { mode: 0o660 })
    ));

    // A real file owned by someone else, where one exists that isn't this user's: refused
    // whatever its mode, as not owned comes first.
    // `/etc/hosts` is a link on macOS: the file itself is what is opened.
    if let Ok(root_owned) = fs::canonicalize("/etc/hosts")
        && rustix::process::geteuid().as_raw() != 0
    {
        let error = SystemFiles.token_file(&root_owned).unwrap_err();
        assert!(
            matches!(error, TokenFileError::NotOwned { .. }),
            "{error:?}"
        );
    }
}
