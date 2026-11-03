//! The one script that installs an agent, which is printed and then run as root.
//!
//! It holds no secret, and every step looks before it changes anything, so that running it
//! again after any interruption converges. Each file arrives by rename. `agent.key` is only
//! ever written by `landfall-agent enrol`, which never overwrites it. The paths here are
//! constants: nothing in the environment changes them.

use std::fmt::Write as _;

use landfall_core::controller_url::ControllerUrl;
use landfall_core::ids::HostId;

use super::shell::{SYSTEM_PATH, quote};

/// The agent's file in the upload directory.
pub const UPLOAD_AGENT: &str = "landfall-agent";

/// The configuration's file in the upload directory.
pub const UPLOAD_CONFIG: &str = "fleet.toml";

/// The enrolment code's file in the upload directory.
pub const UPLOAD_CODE: &str = "enrol-code";

/// Where the agent is installed.
pub(super) const AGENT_PATH: &str = "/usr/local/bin/landfall-agent";

/// Where the agent's unit is installed.
pub(super) const UNIT_PATH: &str = "/etc/systemd/system/landfall-agent.service";

const AGENT_DIR: &str = "/usr/local/bin";
const AGENT_NEW: &str = "/usr/local/bin/.landfall-agent.new";
const CONFIG_DIR: &str = "/etc/landfall";
const CONFIG_PATH: &str = "/etc/landfall/fleet.toml";
const CONFIG_NEW: &str = "/etc/landfall/.fleet.toml.new";
const UNIT_NEW: &str = "/etc/systemd/system/.landfall-agent.service.new";
const RECOVER_PATH: &str = "/etc/systemd/system/landfall-agent-recover@.service";
const RECOVER_NEW: &str = "/etc/systemd/system/.landfall-agent-recover@.service.new";

/// Says a change of configuration, unit or group has yet to take effect. It is written before
/// the change and removed after the restart, so an interrupted run still restarts on the next.
const MARKER: &str = "/etc/landfall/.restart-pending";

const STATE_DIR: &str = "/var/lib/landfall-agent";
const CODE_PATH: &str = "/var/lib/landfall-agent/.enrol-code";
const KEY_PATH: &str = "/var/lib/landfall-agent/agent.key";

/// What an installed agent's mode is, as `stat` says it.
const AGENT_MODE: &str = "755";

/// What an installed configuration's or unit's mode is, as `stat` says it.
const FILE_MODE: &str = "644";

const TAMPERED_AGENT: &str = "the uploaded agent doesn't have the verified SHA-256";
const TAMPERED_CONFIG: &str = "the uploaded configuration doesn't have the SHA-256 this was given";

/// How long a started agent is watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How long it must hold still to count as healthy.
    pub stable_secs: u32,
    /// How long to wait for that before giving up.
    pub give_up_secs: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            stable_secs: 10,
            give_up_secs: 120,
        }
    }
}

/// The enrolment to make. A code is in the upload directory, and is never in the script.
#[derive(Debug, Clone, Copy)]
pub struct EnrolTarget<'a> {
    /// The controller to enrol with.
    pub controller: &'a ControllerUrl,
    /// The host to enrol as.
    pub host: &'a HostId,
    /// Whether the controller is `http://`, which `enrol` needs told.
    pub allow_insecure: bool,
}

/// What one install is to do.
#[derive(Debug, Clone, Copy)]
pub struct InstallRequest<'a> {
    /// The verified agent's SHA-256, in hex.
    pub sha256: &'a str,
    /// The verified agent's version.
    pub version: &'a str,
    /// The configuration's SHA-256, in hex.
    pub config_sha256: &'a str,
    /// Whether a differing configuration may be replaced.
    pub replace_config: bool,
    /// Whether differing units may be replaced.
    pub replace_unit: bool,
    /// `Some` when a code is uploaded.
    pub enrol: Option<EnrolTarget<'a>>,
    /// `landfall-agent.service`.
    pub unit: &'a str,
    /// `landfall-agent-recover@.service`.
    pub recover_unit: &'a str,
    /// The upload directory.
    pub upload: &'a str,
    /// How long a started agent is watched.
    pub timing: Timing,
}

/// One titled part of a script. The script's first step sets what the rest go by, so a script
/// of the first few steps is a script that stops there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// What it does, printed before it runs.
    pub title: String,
    /// Its shell.
    pub shell: String,
}

fn step(title: &str, shell: String) -> Step {
    Step {
        title: title.to_owned(),
        shell,
    }
}

/// An install's steps, in order. There is an `enrol` step only when a code is uploaded.
#[must_use]
pub fn install_steps(request: &InstallRequest<'_>) -> Vec<Step> {
    let mut steps = vec![
        step("preflight", preflight(request)),
        step("user", user()),
        step("state", state()),
        step("config", config(request)),
        step("binary", binary(request)),
        step("docker", docker()),
        step("units", units()),
    ];
    if let Some(target) = &request.enrol {
        steps.push(step("enrol", enrol(target)));
    }
    steps.push(step("start", start()));
    steps
}

/// All of it before any change, but for removing an enrolment code left by a killed run, and
/// that only once the directory it is in is known to be the one it should be.
fn preflight(request: &InstallRequest<'_>) -> String {
    let upload = quote(request.upload);
    let Timing {
        stable_secs,
        give_up_secs,
    } = request.timing;
    let agent_unit = quote(request.unit);
    let recover_unit = quote(request.recover_unit);
    let state_refusal = quote(&format!(
        "{STATE_DIR} is a link, or isn't a directory: the agent's state belongs in a directory of its own there"
    ));
    let mut shell = format!(
        "upload={upload}
stable_secs={stable_secs}
give_up_secs={give_up_secs}
agent_unit={agent_unit}
recover_unit={recover_unit}
if [ -L {STATE_DIR} ] || {{ [ -e {STATE_DIR} ] && [ ! -d {STATE_DIR} ]; }}; then
  refuse {state_refusal}
fi
rm -f {CODE_PATH}
"
    );
    if request.enrol.is_some() {
        shell.push_str(
            r#"state=$(unit_show ActiveState)
case "$state" in
  inactive|failed) ;;
  *) refuse "an enrolment code was given and landfall-agent is $state: stop it first (systemctl stop landfall-agent), as enrol needs the lock it holds" ;;
esac
"#,
        );
    } else {
        let refusal = quote(
            "this host has no agent key and no enrolment code was given: give one with --code-file",
        );
        // Writing to a `String` can't fail.
        let _ = writeln!(shell, "test -e {KEY_PATH} || refuse {refusal}");
    }

    let sha256 = quote(request.sha256);
    let config_sha256 = quote(request.config_sha256);
    let tampered_agent = quote(TAMPERED_AGENT);
    let tampered_config = quote(TAMPERED_CONFIG);
    let _ = writeln!(
        shell,
        "upload_is {UPLOAD_AGENT} {sha256} || refuse {tampered_agent}\n\
         upload_is {UPLOAD_CONFIG} {config_sha256} || refuse {tampered_config}"
    );

    let refusal = quote(&format!(
        "another landfall-agent is installed, and this would install {}: use landfall host upgrade",
        request.version
    ));
    let _ = writeln!(
        shell,
        "check_installed {AGENT_PATH} {AGENT_MODE}\n\
         if [ -e {AGENT_PATH} ] && ! file_is {AGENT_PATH} {sha256}; then\n  refuse {refusal}\nfi"
    );

    let _ = writeln!(
        shell,
        "check_installed {CONFIG_PATH} {FILE_MODE}\n\
         if [ -e {CONFIG_PATH} ] && ! file_is {CONFIG_PATH} {config_sha256}; then\n  read_upload {UPLOAD_CONFIG} | diff -u {CONFIG_PATH} - || true"
    );
    if !request.replace_config {
        let refusal = quote(&format!(
            "{CONFIG_PATH} differs from the one given, as above: --replace-config replaces it, keeping the old file as {CONFIG_PATH}.previous"
        ));
        let _ = writeln!(shell, "  refuse {refusal}");
    }
    shell.push_str("fi\n");

    for (path, text) in [(UNIT_PATH, "$agent_unit"), (RECOVER_PATH, "$recover_unit")] {
        let _ = writeln!(
            shell,
            "check_installed {path} {FILE_MODE}\n\
             if [ -e {path} ] && ! text_is {path} \"{text}\"; then\n  printf '%s' \"{text}\" | diff -u {path} - || true"
        );
        if !request.replace_unit {
            let refusal = quote(&format!(
                "{path} differs from the one this would write, as above: --replace-unit replaces it, keeping the old file as {path}.previous"
            ));
            let _ = writeln!(shell, "  refuse {refusal}");
        }
        shell.push_str("fi\n");
    }
    shell
}

/// A user that exists already must be one an install could have made: the guide's, with a uid
/// of its own, as anything sharing it could read or signal the agent.
fn user() -> String {
    let root_refusal = quote(
        "the landfall-agent user has uid 0, and the agent's uid must be its own: see the guide's Running it under systemd",
    );
    let home_refusal = quote(&format!(
        "the landfall-agent user's home isn't {STATE_DIR}, where the unit's sandbox expects it: see the guide's Running it under systemd"
    ));
    let shell_refusal = quote(
        "the landfall-agent user has a login shell, and it should have none: see the guide's Running it under systemd",
    );
    let shared_refusal = quote(
        "the landfall-agent user's uid is shared with another user, and the agent's uid must be its own: see the guide's Running it under systemd",
    );
    format!(
        r#"if agent_entry=$(getent passwd landfall-agent); then
  agent_uid=$(printf '%s\n' "$agent_entry" | cut -d: -f3)
  agent_home=$(printf '%s\n' "$agent_entry" | cut -d: -f6)
  agent_shell=$(printf '%s\n' "$agent_entry" | cut -d: -f7)
  if [ "$agent_uid" = 0 ]; then
    refuse {root_refusal}
  fi
  if [ "$agent_home" != {STATE_DIR} ]; then
    refuse {home_refusal}
  fi
  case "$agent_shell" in
    /usr/sbin/nologin|/sbin/nologin|/usr/bin/nologin|/bin/false|/usr/bin/false) ;;
    *) refuse {shell_refusal} ;;
  esac
  if [ "$(getent passwd | cut -d: -f3 | grep -cx "$agent_uid")" -gt 1 ]; then
    refuse {shared_refusal}
  fi
  case " $(id -nG landfall-agent) " in
    *" docker "*) ;;
    *)
      mark_restart
      usermod -aG docker landfall-agent
      ;;
  esac
else
  useradd --system --home-dir {STATE_DIR} --no-create-home --shell /usr/sbin/nologin --groups docker landfall-agent
fi
"#
    )
}

fn state() -> String {
    format!("install -d -o landfall-agent -g landfall-agent -m 0700 {STATE_DIR}\n")
}

fn config(request: &InstallRequest<'_>) -> String {
    let sha256 = quote(request.config_sha256);
    let refusal = quote(TAMPERED_CONFIG);
    format!(
        "if ! file_is {CONFIG_PATH} {sha256}; then
  [ -d {CONFIG_DIR} ] || install -d -o root -g root -m 0755 {CONFIG_DIR}
  rm -f {CONFIG_NEW}
  read_upload {UPLOAD_CONFIG} > {CONFIG_NEW}
  file_is {CONFIG_NEW} {sha256} || refuse {refusal}
  chown root:root {CONFIG_NEW}
  chmod 0644 {CONFIG_NEW}
  mark_restart
  keep_previous {CONFIG_PATH}
  mv -f {CONFIG_NEW} {CONFIG_PATH}
fi
"
    )
}

/// It stays private to root until root has compared its hash with the verified one.
fn binary(request: &InstallRequest<'_>) -> String {
    let sha256 = quote(request.sha256);
    let refusal = quote(TAMPERED_AGENT);
    format!(
        "if ! file_is {AGENT_PATH} {sha256}; then
  [ -d {AGENT_DIR} ] || install -d -o root -g root -m 0755 {AGENT_DIR}
  rm -f {AGENT_NEW}
  : > {AGENT_NEW}
  chown root:root {AGENT_NEW}
  chmod 0700 {AGENT_NEW}
  read_upload {UPLOAD_AGENT} > {AGENT_NEW}
  file_is {AGENT_NEW} {sha256} || refuse {refusal}
  chmod 0755 {AGENT_NEW}
  mv -f {AGENT_NEW} {AGENT_PATH}
fi
"
    )
}

/// As the agent's user, which proves more than the login's client version did.
fn docker() -> String {
    let refusal = quote(
        "the landfall-agent user can't reach Docker: check that the daemon runs, and the docker group",
    );
    format!(
        "if ! runuser -u landfall-agent -- docker version > /dev/null; then\n  refuse {refusal}\nfi\n"
    )
}

/// The reload goes by the marker, which every change here sets. That also holds a rerun to the
/// reload: with the files in place and the reload not done, nothing else would say one is due.
fn units() -> String {
    format!(
        r#"if ! text_is {UNIT_PATH} "$agent_unit"; then
  mark_restart
  put_text {UNIT_PATH} {UNIT_NEW} "$agent_unit"
fi
if ! text_is {RECOVER_PATH} "$recover_unit"; then
  mark_restart
  put_text {RECOVER_PATH} {RECOVER_NEW} "$recover_unit"
fi
if [ -e {MARKER} ]; then
  systemctl daemon-reload
fi
"#
    )
}

/// The agent's user writes the code, so a link planted in its directory gets it nothing it
/// doesn't have already.
fn enrol(target: &EnrolTarget<'_>) -> String {
    let controller = quote(target.controller.as_str());
    let host = quote(target.host.as_ref());
    let insecure = if target.allow_insecure {
        " --allow-insecure-controller"
    } else {
        ""
    };
    let refusal = quote("the uploaded enrolment code couldn't be read, or is empty");
    format!(
        "rm -f {CODE_PATH}
read_upload {UPLOAD_CODE} | runuser -u landfall-agent -- sh -c 'umask 077 && cat > \"$1\"' sh {CODE_PATH}
[ -s {CODE_PATH} ] || refuse {refusal}
runuser -u landfall-agent -- {AGENT_PATH} enrol --controller {controller} --host {host} --code-file {CODE_PATH}{insecure}
rm -f {CODE_PATH}
"
    )
}

/// `--no-block` throughout, as a stop waits for a deploy in flight, for up to three hours, and
/// [`WAIT_HEALTHY`] says what became of it. The marker goes once the unit has been seen healthy,
/// so an agent still stopping keeps it, and the next run looks at what replaced it.
fn start() -> String {
    format!(
        r#"previous_id=$(unit_show InvocationID)
if systemctl is-active --quiet landfall-agent; then
  if [ -e {MARKER} ]; then
    systemctl restart --no-block landfall-agent
    wait_healthy "$previous_id"
    [ -n "$health_unseen" ] || rm -f {MARKER}
  fi
else
  systemctl enable --now --no-block landfall-agent
  wait_healthy "$previous_id"
  [ -n "$health_unseen" ] || rm -f {MARKER}
fi
"#
    )
}

/// `wait_healthy <the invocation id before the start>`. The unit has `Restart=always`, so a
/// broken agent never reads `failed`: it cycles. So healthy is a new id, active, with the same
/// id and restart count `stable_secs` later. Reads `stable_secs` and `give_up_secs`, and sets
/// `health_unseen` when it passes only because a deploy is finishing.
const WAIT_HEALTHY: &str = r#"unit_show() {
  systemctl show -p "$1" --value landfall-agent 2>/dev/null || echo unknown
}
health_failed() {
  printf "landfall: landfall-agent isn't healthy: %s\n" "$1" >&2
  journalctl -u landfall-agent -n 20 --no-pager >&2 || true
}
wait_healthy() {
  health_unseen=
  waited=0
  first_restarts=
  while :; do
    now_id=$(unit_show InvocationID)
    now_state=$(unit_show ActiveState)
    now_restarts=$(unit_show NRestarts)
    if [ -n "$first_restarts" ] && [ "$now_restarts" -gt "$first_restarts" ] 2>/dev/null; then
      health_failed "it restarted by itself after starting"
      return 1
    fi
    if [ "$now_state" = active ] && [ -n "$now_id" ] && [ "$now_id" != "$1" ]; then
      first_restarts=${first_restarts:-$now_restarts}
      sleep "$stable_secs"
      waited=$((waited + stable_secs))
      if [ "$(unit_show InvocationID)" = "$now_id" ] &&
        [ "$(unit_show ActiveState)" = active ] &&
        [ "$(unit_show NRestarts)" = "$now_restarts" ]; then
        return 0
      fi
    fi
    if [ "$waited" -ge "$give_up_secs" ]; then
      if [ "$now_state" = deactivating ]; then
        echo "landfall: landfall-agent is still stopping after $waited s: a deploy is finishing. What it ran with stays in force until that deploy ends, and then the unit starts by itself. Run this again after that, to see it healthy"
        health_unseen=1
        return 0
      fi
      health_failed "it is $now_state after $waited s"
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
}
"#;

/// The script that runs `steps`, each announced as it starts.
///
/// `cleanup` runs on every way out it can catch, and a signal stops the script rather than
/// letting it go on to the next step with its files gone. A signal is taken once the command
/// in hand ends, as a shell does.
#[must_use]
pub fn render(steps: &[Step]) -> String {
    let leftovers = [AGENT_NEW, CONFIG_NEW, UNIT_NEW, RECOVER_NEW].join(" ");
    let previous_news = [CONFIG_PATH, UNIT_PATH, RECOVER_PATH]
        .map(|path| format!("{path}.previous.new"))
        .join(" ");
    let mut script = format!(
        r#"set -eu
umask 077
PATH={SYSTEM_PATH}
export PATH
cd /
refuse() {{
  printf 'landfall: refused: %s\n' "$1" >&2
  exit 1
}}
read_upload() {{
  if [ -n "${{SUDO_USER:-}}" ]; then
    runuser -u "$SUDO_USER" -- cat "$upload/$1"
  else
    cat "$upload/$1"
  fi
}}
file_is() {{
  [ -e "$1" ] || return 1
  file_sum=$(sha256sum < "$1") || return 1
  [ "${{file_sum%% *}}" = "$2" ]
}}
upload_is() {{
  upload_sum=$(read_upload "$1" | sha256sum) || return 1
  [ "${{upload_sum%% *}}" = "$2" ]
}}
check_installed() {{
  [ -e "$1" ] || [ -L "$1" ] || return 0
  if [ -L "$1" ] || [ ! -f "$1" ]; then
    refuse "$1 isn't a regular file, and this writes it as one: look at what it is, and remove it to have it written again"
  fi
  installed_as=$(stat -c %u:%g:%a -- "$1") || refuse "$1 couldn't be looked at"
  if [ "$installed_as" != "0:0:$2" ]; then
    refuse "$1 has owner, group and mode $installed_as, and root trusts what it says: make it 0:0:$2, or remove it to have it written again"
  fi
}}
text_is() {{
  printf '%s' "$2" | diff -q "$1" - > /dev/null 2>&1
}}
mark_restart() {{
  [ -d {CONFIG_DIR} ] || install -d -o root -g root -m 0755 {CONFIG_DIR}
  : > {MARKER}
}}
keep_previous() {{
  [ -e "$1" ] || return 0
  cp -p -- "$1" "$1.previous.new"
  mv -f -- "$1.previous.new" "$1.previous"
}}
put_text() {{
  rm -f -- "$2"
  printf '%s' "$3" > "$2"
  chown root:root "$2"
  chmod 0644 "$2"
  keep_previous "$1"
  mv -f -- "$2" "$1"
}}
{WAIT_HEALTHY}cleanup() {{
  cleanup_status=$?
  trap '' HUP INT TERM PIPE
  set +e
  rm -f -- {leftovers} {previous_news}
  [ -L {STATE_DIR} ] || rm -f -- {CODE_PATH}
  if [ -n "${{upload:-}}" ]; then
    rm -rf -- "$upload"
  fi
  find /tmp -maxdepth 1 -name 'landfall-install.*' -mmin +60 -exec rm -rf -- {{}} + 2> /dev/null
  exit "$cleanup_status"
}}
trap cleanup EXIT
trap 'exit 129' HUP INT TERM PIPE
"#
    );
    for (index, step) in steps.iter().enumerate() {
        let number = index + 1;
        let announcement = quote(&format!("landfall: step {number}: {}", step.title));
        // Writing to a `String` can't fail.
        let _ = writeln!(script, "echo {announcement}\n{}", step.shell);
    }
    script
}
