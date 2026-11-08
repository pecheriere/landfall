//! Where the controller is and which token goes to it, from the API commands' flags, the
//! environment and the CLI's configuration file.
//!
//! The token never comes from argv, which other users of the machine can read. It comes from
//! `LANDFALL_TOKEN`, or from a file only its owner can read. With none configured, no token
//! is sent, which is how a proxy that adds one is used.

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use landfall_core::controller_url::{ControllerUrl, UrlError};
use reqwest::header::HeaderValue;
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::Deserialize;
use thiserror::Error;

use crate::cli::ApiArgs;

#[cfg(test)]
mod tests;

/// The longest token file, or `LANDFALL_TOKEN`, taken.
const TOKEN_CAP: usize = 256;

/// The longest configuration file read.
const CONFIG_CAP: u64 = 64 * 1024;

/// Where the API commands go, and with what.
#[derive(Debug)]
pub struct Settings {
    /// The controller, as the transport rule allows it.
    pub controller: ControllerUrl,
    /// The token to send, if one is configured.
    pub token: Option<Token>,
}

/// A bearer token. Its `Debug` shows only where it came from, and it has no `Display`.
pub struct Token {
    /// `Bearer <token>`, marked sensitive.
    header: HeaderValue,
    source: TokenSource,
}

impl Token {
    /// The `Authorization` header's value, marked sensitive so that the HTTP stack keeps it
    /// out of what it shows.
    pub(crate) fn header(&self) -> HeaderValue {
        self.header.clone()
    }

    /// Where it was read from.
    #[must_use]
    pub fn source(&self) -> &TokenSource {
        &self.source
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The header is the token: only where it came from is shown.
        let Self { header: _, source } = self;
        f.debug_struct("Token")
            .field("value", &"<redacted>")
            .field("source", source)
            .finish()
    }
}

/// Where a token was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenSource {
    /// `LANDFALL_TOKEN`.
    Env,
    /// The file `--token-file` names.
    Flag(PathBuf),
    /// The file `LANDFALL_TOKEN_FILE` names.
    EnvFile(PathBuf),
    /// The file `token_file` names in the configuration.
    Config(PathBuf),
}

impl TokenSource {
    /// The setting's own name.
    fn setting(&self) -> &'static str {
        match self {
            Self::Env => "LANDFALL_TOKEN",
            Self::Flag(_) => "--token-file",
            Self::EnvFile(_) => "LANDFALL_TOKEN_FILE",
            Self::Config(_) => "token_file",
        }
    }
}

impl fmt::Display for TokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env => f.write_str("LANDFALL_TOKEN"),
            Self::Flag(path) | Self::EnvFile(path) | Self::Config(path) => {
                write!(f, "{} ({})", path.display(), self.setting())
            }
        }
    }
}

/// The process's environment, or a test's.
pub trait Env {
    /// The variable `name`, if set.
    fn var_os(&self, name: &str) -> Option<OsString>;
}

/// The environment of this process.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

/// The files settings are read from: the real file system, or a test's.
pub trait Files {
    /// The configuration file at `path`, as text: [`io::ErrorKind::NotFound`] when there is
    /// none.
    ///
    /// # Errors
    ///
    /// Why it could not be read.
    fn config(&self, path: &Path) -> io::Result<String>;

    /// The bytes of the token file at `path`, once it is known to be a regular file, not a
    /// link, that no one but its owner can read, of at most 256 bytes.
    ///
    /// # Errors
    ///
    /// Which of those it isn't, or why it could not be read.
    fn token_file(&self, path: &Path) -> Result<Vec<u8>, TokenFileError>;
}

/// The real file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemFiles;

impl Files for SystemFiles {
    fn config(&self, path: &Path) -> io::Result<String> {
        let mut text = String::new();
        File::open(path)?
            .take(CONFIG_CAP + 1)
            .read_to_string(&mut text)?;
        if u64::try_from(text.len()).is_ok_and(|len| len > CONFIG_CAP) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("it is over {CONFIG_CAP} bytes"),
            ));
        }
        Ok(text)
    }

    fn token_file(&self, path: &Path) -> Result<Vec<u8>, TokenFileError> {
        // No-follow, so a link is refused rather than read; non-blocking, so a FIFO put in its
        // place can't hold the open. What the descriptor is decides the rest.
        let flags =
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY;
        let fd = match rustix::fs::open(path, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::LOOP) => return Err(TokenFileError::Linked),
            Err(errno) => return Err(TokenFileError::Open(errno.into())),
        };
        let stat = rustix::fs::fstat(&fd).map_err(|errno| TokenFileError::Read(errno.into()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(TokenFileError::NotRegular);
        }
        let mode = u32::from(stat.st_mode) & 0o777;
        if mode & 0o077 != 0 {
            return Err(TokenFileError::Readable { mode });
        }
        let mut bytes = Vec::with_capacity(TOKEN_CAP + 1);
        File::from(fd)
            .take(u64::try_from(TOKEN_CAP + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(TokenFileError::Read)?;
        if bytes.len() > TOKEN_CAP {
            return Err(TokenFileError::TooLarge);
        }
        Ok(bytes)
    }
}

/// Why a token file was refused. Its contents are never shown.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenFileError {
    /// It could not be opened.
    #[error("cannot open it")]
    Open(#[source] io::Error),
    /// It is a symbolic link.
    #[error("it is a symbolic link: name the file itself")]
    Linked,
    /// It is a directory, a FIFO or anything else but a regular file.
    #[error("it is not a regular file")]
    NotRegular,
    /// Its group or others may read or write it.
    #[error("its mode is {mode:o}, which lets others than its owner at it: chmod 600 it")]
    Readable {
        /// Its permission bits.
        mode: u32,
    },
    /// It is over 256 bytes.
    #[error("it is over {TOKEN_CAP} bytes")]
    TooLarge,
    /// It could not be read.
    #[error("cannot read it")]
    Read(#[source] io::Error),
}

/// What is wrong with a token, which is never shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TokenProblem {
    /// Nothing, or only a newline.
    #[error("it is empty")]
    Empty,
    /// Over 256 bytes.
    #[error("it is over {TOKEN_CAP} bytes")]
    TooLong,
    /// Something outside `[A-Za-z0-9_-]`, or more than one line.
    #[error("it holds something other than one line of letters, digits, '_' and '-'")]
    Characters,
}

/// Why the settings can't be had.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SettingsError {
    /// No controller anywhere.
    #[error(
        "no controller: pass --controller, set LANDFALL_CONTROLLER, or set controller in the CLI's configuration file"
    )]
    NoController,
    /// `LANDFALL_CONTROLLER` is not text.
    #[error("LANDFALL_CONTROLLER is not valid UTF-8 text")]
    ControllerNotText,
    /// The controller breaks the transport rule.
    #[error("{}", controller_message(*.0))]
    Controller(UrlError),
    /// The configuration file `--cli-config` names does not exist.
    #[error("the configuration file {} does not exist", .path.display())]
    ConfigMissing {
        /// The file.
        path: PathBuf,
    },
    /// The configuration file could not be read.
    #[error("cannot read the configuration file {}", .path.display())]
    Config {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// The configuration file is not the TOML this CLI reads.
    #[error("the configuration file {} is not valid", .path.display())]
    ConfigSyntax {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// `token_file` in the configuration is relative, which would depend on where the
    /// command runs.
    #[error("token_file in {} must be an absolute path", .path.display())]
    RelativeTokenFile {
        /// The configuration file.
        path: PathBuf,
    },
    /// Two of the token's sources are set, and nothing should have to choose between them.
    #[error("both {first} and {second} are set: keep one of them")]
    TwoTokenSources {
        /// The first in order of precedence.
        first: &'static str,
        /// The second.
        second: &'static str,
    },
    /// A token file was refused.
    #[error("token file {}", .path.display())]
    TokenFile {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: TokenFileError,
    },
    /// The token itself can't be sent.
    #[error("the token from {from} is refused")]
    Token {
        /// Where it came from.
        from: &'static str,
        /// What is wrong with it.
        #[source]
        problem: TokenProblem,
    },
}

/// The CLI's own words for each way a controller breaks the rule: it would carry a bearer
/// token, which is what is at stake.
fn controller_message(error: UrlError) -> &'static str {
    match error {
        UrlError::NotAUrl => "the controller is not a URL",
        UrlError::NeedsFlag => {
            "the controller is http://, which would send the bearer token in clear: that needs \
             --allow-insecure-controller (or allow_insecure_controller = true), and is allowed only \
             for a loopback address, localhost or a *.ts.net name"
        }
        UrlError::NotPrivate => {
            "the controller is http:// to a host that is not a loopback address, localhost or a \
             *.ts.net name: the bearer token would cross the network in clear, and \
             --allow-insecure-controller does not cover that"
        }
        UrlError::NotABase => {
            "the controller must be only a scheme, a host and a port, so that no credential or \
             path goes with the token"
        }
        UrlError::Scheme => "the controller must be https://, so that the token goes encrypted",
        _ => "the controller's URL is refused, so that the token goes nowhere it shouldn't",
    }
}

/// The CLI's configuration file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    controller: Option<String>,
    token_file: Option<PathBuf>,
    #[serde(default)]
    allow_insecure_controller: bool,
}

/// The settings from `flags`, then `env`, then the configuration file.
///
/// # Errors
///
/// A [`SettingsError`] saying which setting is missing, refused or set twice.
pub fn resolve(
    flags: &ApiArgs,
    env: &dyn Env,
    files: &dyn Files,
) -> Result<Settings, SettingsError> {
    let (config_path, config) = config_file(flags, env, files)?;

    let controller = match (&flags.controller, env.var_os("LANDFALL_CONTROLLER")) {
        (Some(flag), _) => flag.clone(),
        (None, Some(value)) if !value.is_empty() => value
            .into_string()
            .map_err(|_| SettingsError::ControllerNotText)?,
        (None, _) => config
            .controller
            .clone()
            .ok_or(SettingsError::NoController)?,
    };
    let allow_insecure = flags.allow_insecure_controller || config.allow_insecure_controller;
    let controller =
        ControllerUrl::parse(&controller, allow_insecure).map_err(SettingsError::Controller)?;

    let token = token(flags, env, files, config_path.as_deref(), config.token_file)?;
    Ok(Settings { controller, token })
}

/// The configuration file's path, if there is one to read, and what it says. A missing
/// default file is an empty configuration; a missing named one is an error.
fn config_file(
    flags: &ApiArgs,
    env: &dyn Env,
    files: &dyn Files,
) -> Result<(Option<PathBuf>, ConfigFile), SettingsError> {
    let (path, named) = match &flags.cli_config {
        Some(path) => (path.clone(), true),
        None => match default_config_path(env) {
            Some(path) => (path, false),
            None => return Ok((None, ConfigFile::default())),
        },
    };
    let text = match files.config(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return if named {
                Err(SettingsError::ConfigMissing { path })
            } else {
                Ok((None, ConfigFile::default()))
            };
        }
        Err(source) => return Err(SettingsError::Config { path, source }),
    };
    let config = toml::from_str(&text).map_err(|source| SettingsError::ConfigSyntax {
        path: path.clone(),
        source: Box::new(source),
    })?;
    Ok((Some(path), config))
}

/// `$XDG_CONFIG_HOME/landfall/cli.toml`, or `$HOME/.config/landfall/cli.toml`. A relative or
/// empty value is ignored, as the XDG base directory specification requires.
fn default_config_path(env: &dyn Env) -> Option<PathBuf> {
    let absolute = |name| {
        env.var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    absolute("XDG_CONFIG_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".config")))
        .map(|base| base.join("landfall").join("cli.toml"))
}

/// Where the token is to come from, before anything is read.
enum Wanted {
    Value(OsString),
    File(PathBuf),
}

/// The token from the one source that is set, or none.
fn token(
    flags: &ApiArgs,
    env: &dyn Env,
    files: &dyn Files,
    config_path: Option<&Path>,
    config_token_file: Option<PathBuf>,
) -> Result<Option<Token>, SettingsError> {
    let non_empty = |name| env.var_os(name).filter(|value| !value.is_empty());
    if let (Some(file), Some(config)) = (&config_token_file, config_path)
        && !file.is_absolute()
    {
        return Err(SettingsError::RelativeTokenFile {
            path: config.to_path_buf(),
        });
    }
    let file = |source: fn(PathBuf) -> TokenSource, path: PathBuf| {
        (source(path.clone()), Wanted::File(path))
    };
    let mut wanted = [
        non_empty("LANDFALL_TOKEN").map(|value| (TokenSource::Env, Wanted::Value(value))),
        flags
            .token_file
            .clone()
            .map(|path| file(TokenSource::Flag, path)),
        non_empty("LANDFALL_TOKEN_FILE").map(|value| file(TokenSource::EnvFile, value.into())),
        config_token_file.map(|path| file(TokenSource::Config, path)),
    ]
    .into_iter()
    .flatten();
    let Some((source, first)) = wanted.next() else {
        return Ok(None);
    };
    if let Some((second, _)) = wanted.next() {
        return Err(SettingsError::TwoTokenSources {
            first: source.setting(),
            second: second.setting(),
        });
    }
    let bytes = match first {
        Wanted::Value(value) => value.into_encoded_bytes(),
        Wanted::File(path) => {
            let mut bytes = files
                .token_file(&path)
                .map_err(|source| SettingsError::TokenFile { path, source })?;
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            bytes
        }
    };
    let header = bearer(&bytes).map_err(|problem| SettingsError::Token {
        from: source.setting(),
        problem,
    })?;
    Ok(Some(Token { header, source }))
}

/// `Bearer <token>`, marked sensitive, if `token` is one line of `[A-Za-z0-9_-]` of at most
/// 256 bytes.
fn bearer(token: &[u8]) -> Result<HeaderValue, TokenProblem> {
    if token.is_empty() {
        return Err(TokenProblem::Empty);
    }
    if token.len() > TOKEN_CAP {
        return Err(TokenProblem::TooLong);
    }
    if !token
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(TokenProblem::Characters);
    }
    let mut value = Vec::with_capacity(token.len() + 7);
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(token);
    let mut header = HeaderValue::from_bytes(&value).map_err(|_| TokenProblem::Characters)?;
    header.set_sensitive(true);
    Ok(header)
}
