//! What a target says about itself, and whether an agent can run there.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use landfall_core::controller_url::ControllerUrl;
use landfall_core::text::shown;

use super::plan::{AGENT_PATH, UNIT_PATH};
use super::shell::{QUOTE_CHECK, SYSTEM_PATH, quote};
use crate::agent_release::Arch;

/// The line before a probe's facts. Anything before it, as from a `.bashrc`, isn't read.
const BEGIN: &str = "landfall-probe-begin";

/// The line after a probe's facts.
const END: &str = "landfall-probe-end";

/// The most output that is read at all.
const MAX_OUTPUT: usize = 64 * 1024;

/// The longest value.
const MAX_VALUE: usize = 256;

/// Where a CA bundle is, on the distributions that have one.
const CA_BUNDLES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// What holds a command the probe can't vouch for to a time limit, so that a hung one can't hang
/// the probe: 10 s, then a kill 5 s later if it ignored that.
const BOUNDED: &str = "timeout -k 5 10";

/// The keys a probe prints, other than `dir_exists:<n>`.
const KEYS: [&str; 21] = [
    "os",
    "machine",
    "kernel",
    "uid",
    "has_sudo",
    "has_systemctl",
    "systemd_version",
    "has_sha256sum",
    "has_runuser",
    "has_diff",
    "has_timeout",
    "docker_client",
    "compose",
    "docker_group",
    "docker_service",
    "ca_bundle",
    "clock",
    "agent_version",
    "agent_sha256",
    "unit_present",
    "quote_check",
];

const DIR_KEY: &str = "dir_exists:";

/// Linux 5.8: see "Requirements" in the guide.
const MIN_KERNEL: (u32, u32) = (5, 8);

/// systemd 235, for `NRestarts`.
const MIN_SYSTEMD: u32 = 235;

/// Docker 20.10, the oldest a compose v2 plugin supports.
const MIN_DOCKER: (u32, u32) = (20, 10);

/// Compose v2.
const MIN_COMPOSE_MAJOR: u32 = 2;

/// How far a clock may be from this machine's before it is worth saying.
const CLOCK_SKEW_SECS: u64 = 60;

/// Why a probe's output can't be read. What a target printed is hostile, so it is shown
/// quoted and truncated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FactsError {
    /// More than a probe could honestly print.
    #[error("the probe printed more than {0} bytes")]
    TooLarge(usize),
    /// The sentinels aren't there exactly once each, in order.
    #[error(
        "the probe's output has no single block between its markers: the login shell may not be one that can run it"
    )]
    NoBlock,
    /// A line between the sentinels that isn't `key=value`.
    #[error("the probe printed a line that isn't key=value: {}", shown(.0))]
    BadLine(String),
    /// A key given twice.
    #[error("the probe printed {} twice", shown(.0))]
    Repeated(String),
    /// A value over the limit.
    #[error("the probe's value for {} is over {limit} bytes", shown(.0), limit = .1)]
    ValueTooLong(String, usize),
    /// A value with a control character in it.
    #[error("the probe's value for {} holds a control character", shown(.0))]
    ControlCharacter(String),
}

/// What a probe printed, by key. A key that didn't come reads as no, so that a probe cut short
/// is refused for what it left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    values: BTreeMap<String, String>,
}

impl HostFacts {
    /// Reads the output of [`probe`], only between its sentinels, so that a banner from a
    /// `.bashrc` can't trip it. Keys it doesn't know are ignored.
    ///
    /// # Errors
    ///
    /// [`FactsError`] if it isn't what a probe prints.
    pub fn parse(output: &str) -> Result<Self, FactsError> {
        if output.len() > MAX_OUTPUT {
            return Err(FactsError::TooLarge(MAX_OUTPUT));
        }
        let lines: Vec<&str> = output.split('\n').collect();
        let (Some(begin), Some(end)) = (only_line(&lines, BEGIN), only_line(&lines, END)) else {
            return Err(FactsError::NoBlock);
        };
        let block = lines.get(begin + 1..end).ok_or(FactsError::NoBlock)?;

        let mut values = BTreeMap::new();
        for line in block {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| FactsError::BadLine((*line).to_owned()))?;
            if value.len() > MAX_VALUE {
                return Err(FactsError::ValueTooLong(key.to_owned(), MAX_VALUE));
            }
            if value.contains(char::is_control) {
                return Err(FactsError::ControlCharacter(key.to_owned()));
            }
            if is_known(key) && values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(FactsError::Repeated(key.to_owned()));
            }
        }
        Ok(Self { values })
    }

    fn value(&self, key: &str) -> &str {
        self.values.get(key).map_or("", String::as_str)
    }

    fn yes(&self, key: &str) -> bool {
        self.value(key) == "1"
    }

    fn present(&self, key: &str) -> Option<&str> {
        Some(self.value(key)).filter(|value| !value.is_empty())
    }

    /// The target's architecture, among those a release has.
    #[must_use]
    pub fn arch(&self) -> Option<Arch> {
        Arch::from_uname(self.value("machine"))
    }

    /// Whether the login is root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.value("uid") == "0"
    }

    /// Whether the agent's unit is there.
    #[must_use]
    pub fn unit_present(&self) -> bool {
        self.yes("unit_present")
    }

    /// What the installed agent's `--version` said, if there is one.
    #[must_use]
    pub fn agent_version(&self) -> Option<&str> {
        self.present("agent_version")
    }

    /// The installed agent's SHA-256, if there is one.
    #[must_use]
    pub fn agent_sha256(&self) -> Option<&str> {
        self.present("agent_sha256")
    }

    /// Whether the compose directory at position `index` exists.
    #[must_use]
    pub fn dir_exists(&self, index: usize) -> bool {
        self.yes(&format!("{DIR_KEY}{index}"))
    }
}

/// Where `wanted` is among `lines`, if it is there exactly once.
fn only_line(lines: &[&str], wanted: &str) -> Option<usize> {
    let mut found = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == wanted)
        .map(|(index, _)| index);
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn is_known(key: &str) -> bool {
    KEYS.contains(&key)
        || key
            .strip_prefix(DIR_KEY)
            .is_some_and(|index| index.parse::<usize>().is_ok())
}

/// Why an agent can't go on a host. What the target said is shown quoted and truncated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// Not Linux.
    #[error("the target's system is {}, and the agent runs on Linux", shown(.0))]
    NotLinux(String),
    /// An architecture no release has.
    #[error("the target's architecture is {}, and a release has arm64 and amd64", shown(.0))]
    UnknownArch(String),
    /// Below Linux 5.8.
    #[error("the target's kernel is {}, and the agent needs Linux 5.8 or later", shown(.0))]
    OldKernel(String),
    /// Below systemd 235.
    #[error("the target's systemd is {}, and this needs 235 or later", shown(.0))]
    OldSystemd(String),
    /// A command the script needs.
    #[error("the target has no `{0}`, which the install needs")]
    MissingTool(&'static str),
    /// The login shell doesn't quote as a POSIX one does.
    #[error(
        "a quoting check didn't come back intact, so what ran could differ from what was shown: the likely reason is the login shell, such as fish or csh. Use a login whose shell is POSIX"
    )]
    QuoteCheck,
    /// No Docker client.
    #[error("the target has no `docker` client: install Docker Engine from Docker's packages")]
    NoDocker,
    /// Below Docker 20.10.
    #[error("the target's Docker client is {}, and this needs 20.10 or later: upgrade Docker", shown(.0))]
    OldDocker(String),
    /// No compose v2.
    #[error(
        "the target has no `docker compose` v2 (it said {}): install the docker-compose-plugin package",
        shown(.0)
    )]
    NoCompose(String),
    /// No `docker` group for the agent's user to join.
    #[error("the target has no `docker` group: the agent's user reaches Docker through it")]
    NoDockerGroup,
    /// No `docker.service` for the unit to require.
    #[error(
        "the target has no docker.service, which the agent's unit requires: the likely reason is Docker from snap, whose service has another name. Use Docker's packages"
    )]
    NoDockerService,
    /// No CA certificates, with an `https://` controller.
    #[error(
        "the target has no CA certificates, and the agent can't reach an https:// controller without them: install the ca-certificates package"
    )]
    NoCaBundle,
    /// A compose directory that isn't there.
    #[error("compose directory {} doesn't exist on the target, and is never created", shown(.0))]
    MissingComposeDir(String),
    /// Neither root nor `sudo`.
    #[error("the login is neither root nor has `sudo`")]
    NoPrivilege,
}

/// What an operator should know, and which doesn't stop an install.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Warning {
    /// More than a minute from this machine's clock.
    #[error(
        "the target's clock is {0} s from this machine's: a clock behind a fresh release puts it off. Check its NTP"
    )]
    ClockOff(u64),
    /// A clock that couldn't be read.
    #[error("the target's clock couldn't be read: {}", shown(.0))]
    ClockUnreadable(String),
}

/// The read-only script that prints what [`HostFacts::parse`] reads, with one `dir_exists:<n>`
/// for each of `dirs` by position. Needs no root, and sets its own `PATH`, as a login's may
/// leave out the `sbin` directories.
#[must_use]
pub fn probe(dirs: &[&str]) -> String {
    let check = quote(QUOTE_CHECK);
    let ca_test = CA_BUNDLES
        .iter()
        .map(|path| format!("[ -e {path} ]"))
        .collect::<Vec<_>>()
        .join(" || ");
    let mut script = format!(
        r#"PATH={SYSTEM_PATH}
export PATH
fact() {{ printf '%s=%s\n' "$1" "$2"; }}
has() {{ if command -v "$1" >/dev/null 2>&1; then echo 1; else echo 0; fi; }}
yes_if() {{ if "$@" >/dev/null 2>&1; then echo 1; else echo 0; fi; }}
echo {BEGIN}
fact os "$(uname -s 2>/dev/null)"
fact machine "$(uname -m 2>/dev/null)"
fact kernel "$(uname -r 2>/dev/null)"
fact uid "$(id -u 2>/dev/null)"
fact has_sudo "$(has sudo)"
fact has_systemctl "$(has systemctl)"
fact systemd_version "$(systemctl --version 2>/dev/null | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')"
fact has_sha256sum "$(has sha256sum)"
fact has_runuser "$(has runuser)"
fact has_diff "$(has diff)"
fact has_timeout "$(has timeout)"
fact docker_client "$({BOUNDED} docker --version 2>/dev/null | sed -n '1s/^Docker version \([0-9][^, ]*\).*/\1/p')"
fact compose "$({BOUNDED} docker compose version --short 2>/dev/null | sed -n '1p')"
fact docker_group "$(yes_if getent group docker)"
fact docker_service "$(yes_if systemctl cat docker.service)"
if {ca_test}; then fact ca_bundle 1; else fact ca_bundle 0; fi
fact clock "$(date +%s 2>/dev/null)"
if [ -x {AGENT_PATH} ]; then
  fact agent_version "$({BOUNDED} {AGENT_PATH} --version 2>/dev/null | sed -n '1p')"
  fact agent_sha256 "$(sha256sum < {AGENT_PATH} 2>/dev/null | sed 's/ .*//')"
else
  fact agent_version ''
  fact agent_sha256 ''
fi
if [ -e {UNIT_PATH} ]; then fact unit_present 1; else fact unit_present 0; fi
fact quote_check "$(printf %s {check} | od -An -tx1 | tr -d ' \n')"
"#
    );
    for (index, dir) in dirs.iter().enumerate() {
        let dir = quote(dir);
        // Writing to a `String` can't fail.
        let _ = writeln!(
            script,
            "if [ -d {dir} ]; then fact {DIR_KEY}{index} 1; else fact {DIR_KEY}{index} 0; fi"
        );
    }
    let _ = writeln!(script, "echo {END}");
    script
}

/// Whether an agent can go on this host: what it would warn about if so.
///
/// # Errors
///
/// Every [`Refusal`] that holds, so that one run says all of it.
pub fn check(
    facts: &HostFacts,
    now: i64,
    dirs: &[&str],
    controller: &ControllerUrl,
) -> Result<Vec<Warning>, Vec<Refusal>> {
    let mut refusals = Vec::new();
    let value = |key| facts.value(key).to_owned();

    if facts.value("os") != "Linux" {
        refusals.push(Refusal::NotLinux(value("os")));
    }
    if facts.arch().is_none() {
        refusals.push(Refusal::UnknownArch(value("machine")));
    }
    if !pair_at_least(facts.value("kernel"), MIN_KERNEL) {
        refusals.push(Refusal::OldKernel(value("kernel")));
    }
    if leading_number(facts.value("systemd_version")).is_none_or(|got| got < MIN_SYSTEMD) {
        refusals.push(Refusal::OldSystemd(value("systemd_version")));
    }
    for (key, tool) in [
        ("has_systemctl", "systemctl"),
        ("has_sha256sum", "sha256sum"),
        ("has_runuser", "runuser"),
        ("has_diff", "diff"),
        ("has_timeout", "timeout"),
    ] {
        if !facts.yes(key) {
            refusals.push(Refusal::MissingTool(tool));
        }
    }
    if facts.value("quote_check") != quote_check_hex() {
        refusals.push(Refusal::QuoteCheck);
    }
    // With no `timeout` these were never asked, and it is refused for that.
    if facts.yes("has_timeout") {
        match facts.value("docker_client") {
            "" => refusals.push(Refusal::NoDocker),
            client if !pair_at_least(client, MIN_DOCKER) => {
                refusals.push(Refusal::OldDocker(client.to_owned()));
            }
            _ => {}
        }
        let compose = facts.value("compose");
        let compose_major = leading_number(compose.strip_prefix('v').unwrap_or(compose));
        if compose_major.is_none_or(|major| major < MIN_COMPOSE_MAJOR) {
            refusals.push(Refusal::NoCompose(compose.to_owned()));
        }
    }
    if !facts.yes("docker_group") {
        refusals.push(Refusal::NoDockerGroup);
    }
    if !facts.yes("docker_service") {
        refusals.push(Refusal::NoDockerService);
    }
    if controller.is_https() && !facts.yes("ca_bundle") {
        refusals.push(Refusal::NoCaBundle);
    }
    for (index, dir) in dirs.iter().enumerate() {
        if !facts.dir_exists(index) {
            refusals.push(Refusal::MissingComposeDir((*dir).to_owned()));
        }
    }
    if !facts.is_root() && !facts.yes("has_sudo") {
        refusals.push(Refusal::NoPrivilege);
    }

    if refusals.is_empty() {
        Ok(clock_warning(facts.value("clock"), now)
            .into_iter()
            .collect())
    } else {
        Err(refusals)
    }
}

fn clock_warning(clock: &str, now: i64) -> Option<Warning> {
    let Ok(clock_secs) = clock.parse::<i64>() else {
        return Some(Warning::ClockUnreadable(clock.to_owned()));
    };
    let skew = clock_secs.abs_diff(now);
    (skew > CLOCK_SKEW_SECS).then_some(Warning::ClockOff(skew))
}

/// [`QUOTE_CHECK`] as the probe prints it, when it comes back intact.
fn quote_check_hex() -> String {
    QUOTE_CHECK.bytes().fold(String::new(), |mut text, byte| {
        // Writing to a `String` can't fail.
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The number `text` starts with, as with `252.22` or `8.0-generic`.
fn leading_number(text: &str) -> Option<u32> {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    text.get(..end)?.parse().ok()
}

/// Whether a `major.minor...` version is at least `floor`, as numbers. One that can't be read
/// isn't.
fn pair_at_least(version: &str, floor: (u32, u32)) -> bool {
    let Some((major, rest)) = version.split_once('.') else {
        return false;
    };
    match (leading_number(major), leading_number(rest)) {
        (Some(major), Some(minor)) => (major, minor) >= floor,
        _ => false,
    }
}
