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

/// All of it before any change, but for removing an enrolment code left by a killed run.
fn preflight(request: &InstallRequest<'_>) -> String {
    let upload = quote(request.upload);
    let Timing {
        stable_secs,
        give_up_secs,
    } = request.timing;
    let agent_unit = quote(request.unit);
    let recover_unit = quote(request.recover_unit);
    let mut shell = format!(
        "upload={upload}
stable_secs={stable_secs}
give_up_secs={give_up_secs}
agent_unit={agent_unit}
recover_unit={recover_unit}
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
    let refusal = quote(&format!(
        "another landfall-agent is installed, and this would install {}: use landfall host upgrade",
        request.version
    ));
    let _ = writeln!(
        shell,
        "if [ -e {AGENT_PATH} ] && ! file_is {AGENT_PATH} {sha256}; then\n  refuse {refusal}\nfi"
    );

    let config_sha256 = quote(request.config_sha256);
    let _ = writeln!(
        shell,
        "if [ -e {CONFIG_PATH} ] && ! file_is {CONFIG_PATH} {config_sha256}; then\n  read_upload {UPLOAD_CONFIG} | diff -u {CONFIG_PATH} - || true"
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
            "if [ -e {path} ] && ! text_is {path} \"{text}\"; then\n  printf '%s' \"{text}\" | diff -u {path} - || true"
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

fn user() -> String {
    let root_refusal = quote(
        "the landfall-agent user has uid 0, and the agent's uid must be its own: see the guide's Running it under systemd",
    );
    format!(
        r#"if agent_uid=$(id -u landfall-agent 2>/dev/null); then
  if [ "$agent_uid" = 0 ]; then
    refuse {root_refusal}
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
    let refusal = quote("the uploaded configuration doesn't have the SHA-256 this was given");
    format!(
        "if ! file_is {CONFIG_PATH} {sha256}; then
  install -d -o root -g root -m 0755 {CONFIG_DIR}
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
    let refusal = quote("the uploaded agent doesn't have the verified SHA-256");
    format!(
        "if ! file_is {AGENT_PATH} {sha256}; then
  install -d -o root -g root -m 0755 /usr/local/bin
  rm -f {AGENT_NEW}
  : > {AGENT_NEW}
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

/// The marker holds a rerun to the reload as well: with the files in place and the reload not
/// done, nothing else would say one is due.
fn units() -> String {
    format!(
        r#"units_changed=
if ! text_is {UNIT_PATH} "$agent_unit"; then
  mark_restart
  put_text {UNIT_PATH} {UNIT_NEW} "$agent_unit"
  units_changed=1
fi
if ! text_is {RECOVER_PATH} "$recover_unit"; then
  mark_restart
  put_text {RECOVER_PATH} {RECOVER_NEW} "$recover_unit"
  units_changed=1
fi
if [ -n "$units_changed" ] || [ -e {MARKER} ]; then
  systemctl daemon-reload
fi
"#
    )
}

fn enrol(target: &EnrolTarget<'_>) -> String {
    let controller = quote(target.controller.as_str());
    let host = quote(target.host.as_ref());
    let insecure = if target.allow_insecure {
        " --allow-insecure-controller"
    } else {
        ""
    };
    format!(
        "rm -f {CODE_PATH}
install -o landfall-agent -g landfall-agent -m 0600 /dev/null {CODE_PATH}
read_upload {UPLOAD_CODE} > {CODE_PATH}
runuser -u landfall-agent -- {AGENT_PATH} enrol --controller {controller} --host {host} --code-file {CODE_PATH}{insecure}
rm -f {CODE_PATH}
"
    )
}

/// `--no-block` throughout, as a stop waits for a deploy in flight, for up to three hours, and
/// [`WAIT_HEALTHY`] says what became of it.
fn start() -> String {
    format!(
        r#"previous_id=$(unit_show InvocationID)
if systemctl is-active --quiet landfall-agent; then
  if [ -e {MARKER} ]; then
    systemctl restart --no-block landfall-agent
    wait_healthy "$previous_id"
    rm -f {MARKER}
  fi
else
  systemctl enable --now --no-block landfall-agent
  wait_healthy "$previous_id"
  rm -f {MARKER}
fi
"#
    )
}

/// `wait_healthy <the invocation id before the start>`. The unit has `Restart=always`, so a
/// broken agent never reads `failed`: it cycles. So healthy is a new id, active, with the same
/// id and restart count `stable_secs` later. Reads `stable_secs` and `give_up_secs`.
const WAIT_HEALTHY: &str = r#"unit_show() {
  systemctl show -p "$1" --value landfall-agent 2>/dev/null || echo unknown
}
health_failed() {
  echo "landfall: landfall-agent isn't healthy: $1" >&2
  journalctl -u landfall-agent -n 20 --no-pager >&2 || true
}
wait_healthy() {
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
        echo "landfall: landfall-agent is still stopping after $waited s: a deploy is finishing. What it ran with stays in force until that deploy ends, and then the unit starts by itself"
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
    let leftovers = [AGENT_NEW, CONFIG_NEW, UNIT_NEW, RECOVER_NEW, CODE_PATH].join(" ");
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
  echo "landfall: refused: $1" >&2
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
text_is() {{
  printf '%s' "$2" | diff -q "$1" - > /dev/null 2>&1
}}
mark_restart() {{
  install -d -o root -g root -m 0755 {CONFIG_DIR}
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
