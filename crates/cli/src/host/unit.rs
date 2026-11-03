//! The agent's systemd units, as `docs/operations.md` gives them.

use std::borrow::Cow;
use std::fmt::Write as _;

use landfall_core::controller_url::ControllerUrl;
use landfall_core::ids::HostId;
use landfall_core::text::shown;

/// Why a value can't go in a unit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UnitError {
    /// A directory that isn't absolute, or holds what a unit can't say safely.
    #[error(
        "compose directory {} can't go in a systemd unit: it must be absolute, with no whitespace, quote, %, $, \\ or control character",
        shown(.0)
    )]
    UnsafePath(String),
}

/// Checks that a unit can name `path`.
///
/// # Errors
///
/// [`UnitError::UnsafePath`] if it can't.
pub fn check_path(path: &str) -> Result<(), UnitError> {
    let unsafe_char =
        |c: char| c.is_whitespace() || c.is_control() || matches!(c, '\'' | '"' | '%' | '$' | '\\');
    if path.starts_with('/') && !path.contains(unsafe_char) {
        Ok(())
    } else {
        Err(UnitError::UnsafePath(path.to_owned()))
    }
}

/// What the agent's unit says about this host.
#[derive(Debug, Clone, Copy)]
pub struct UnitInput<'a> {
    /// The controller it polls.
    pub controller: &'a ControllerUrl,
    /// The host it runs as.
    pub host: &'a HostId,
    /// Whether the controller is `http://`, which the agent needs told.
    pub allow_insecure: bool,
    /// Its deployments' compose directories, each through [`check_path`].
    pub compose_dirs: &'a [&'a str],
}

/// `landfall-agent.service`.
#[must_use]
pub fn agent_unit(input: &UnitInput<'_>) -> String {
    let controller = unit_word(input.controller.as_str());
    let host = input.host;
    let insecure = if input.allow_insecure {
        " --allow-insecure-controller"
    } else {
        ""
    };
    let read_write = read_write_paths(input.compose_dirs);
    format!(
        "[Unit]
Description=landfall-agent
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
User=landfall-agent
SupplementaryGroups=docker
EnvironmentFile=-/etc/landfall/agent.env
ExecStart=/usr/local/bin/landfall-agent run --config /etc/landfall/fleet.toml --controller {controller} --host {host}{insecure}
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=3h
AmbientCapabilities=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=landfall-agent
StateDirectoryMode=0700
{read_write}
[Install]
WantedBy=multi-user.target
"
    )
}

/// `landfall-agent-recover@.service`. `compose_dirs` go through [`check_path`] first.
#[must_use]
pub fn recover_unit(compose_dirs: &[&str]) -> String {
    let read_write = read_write_paths(compose_dirs);
    format!(
        "[Unit]
Description=landfall-agent recover %I
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
User=landfall-agent
SupplementaryGroups=docker
ExecStart=/usr/local/bin/landfall-agent recover --config /etc/landfall/fleet.toml --deployment %I
AmbientCapabilities=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=landfall-agent
StateDirectoryMode=0700
{read_write}"
    )
}

/// The line that lets a unit write to `dirs`, in a settled order so that the same directories
/// are the same unit, and with its comment. Nothing if there are none.
fn read_write_paths(dirs: &[&str]) -> String {
    let mut sorted = dirs.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut line = String::new();
    if !sorted.is_empty() {
        // Writing to a `String` can't fail.
        let _ = writeln!(
            line,
            "# Every managed compose directory on this host.\nReadWritePaths={}",
            sorted.join(" ")
        );
    }
    line
}

/// `text` as one word of an `ExecStart`, where a unit reads quotes, `$` and `%` itself. The URL
/// parser lets some of those through in a host name, however unlikely such a name is.
fn unit_word(text: &str) -> Cow<'_, str> {
    let plain = text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '[' | ']' | '-' | '_'));
    if plain {
        return Cow::Borrowed(text);
    }
    let escaped = text
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    Cow::Owned(format!("\"{escaped}\""))
}
