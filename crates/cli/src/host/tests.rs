//! A place to run a rendered script: every system path it names mapped into a temp directory,
//! and every command that would change the system a stub on `PATH`. Nothing here needs root
//! or touches a real path.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use tempfile::TempDir;

use super::shell::SYSTEM_PATH;

mod facts;
mod plan;
mod script;
mod shell;
mod unit;

/// What's mapped into the sandbox, wherever a script says it.
const MAPPED: [&str; 4] = ["/usr/local/bin/", "/etc/", "/var/lib/", "/tmp"];

/// Stands for no value in the rows of `states`, which `set --` would otherwise lose.
const NOTHING: &str = "-";

pub(super) struct Sandbox {
    _dir: TempDir,
    root: PathBuf,
    stubs: PathBuf,
    env: Vec<(String, String)>,
}

impl Sandbox {
    /// A sandbox whose unit is inactive and which has no agent's user yet.
    pub(super) fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("root");
        let stubs = dir.path().join("stubs");
        for path in [
            "usr/local/bin",
            "etc/landfall",
            "etc/systemd/system",
            "var/lib/landfall-agent",
            "tmp",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::create_dir_all(&stubs).unwrap();
        let sandbox = Self {
            root,
            stubs,
            env: Vec::new(),
            _dir: dir,
        };
        sandbox.install_stubs();
        sandbox.set_states(&[("inactive", "", 0)]);
        sandbox
    }

    fn install_stubs(&self) {
        let log = self.path("/log");
        let log = log.display();
        let ctl = self.stubs.display();
        // Delegates, as a Mac on CI may have only `shasum`.
        self.stub(
            "sha256sum",
            r#"for tool in /usr/bin/sha256sum /sbin/sha256sum /bin/sha256sum; do
  if [ -x "$tool" ]; then exec "$tool" "$@"; fi
done
exec shasum -a 256 "$@""#,
        );
        self.stub(
            "runuser",
            &format!("echo \"runuser $*\" >> {log}\nshift 3\nexec \"$@\""),
        );
        self.stub(
            "systemctl",
            &format!(
                r#"echo "systemctl $*" >> {log}
tick=$(cat {ctl}/tick 2>/dev/null || echo 0)
rows=$(wc -l < {ctl}/states)
row=$((tick + 1))
if [ "$row" -gt "$rows" ]; then row=$rows; fi
action=$1
property=${{3:-}}
set -- $(sed -n "${{row}}p" {ctl}/states)
case "$action" in
  show)
    case "$property" in
      ActiveState) echo "$1" ;;
      InvocationID) if [ "$2" != {NOTHING} ]; then echo "$2"; fi ;;
      NRestarts) echo "$3" ;;
    esac
    ;;
  is-active) [ "$1" = active ] ;;
esac"#
            ),
        );
        self.stub(
            "sleep",
            &format!(
                "tick=$(cat {ctl}/tick 2>/dev/null || echo 0)\necho $((tick + 1)) > {ctl}/tick"
            ),
        );
        self.stub(
            "journalctl",
            &format!("echo \"journalctl $*\" >> {log}\necho 'a journal line'"),
        );
        self.stub("docker", &format!("echo \"docker $*\" >> {log}"));
        self.stub("chown", &format!("echo \"chown $*\" >> {log}"));
        // The real one can't name an owner without root.
        self.stub(
            "install",
            &format!(
                r#"echo "install $*" >> {log}
directory=
for arg in "$@"; do
  if [ "$arg" = -d ]; then directory=1; fi
  target=$arg
done
if [ -n "$directory" ]; then mkdir -p "$target"; else : > "$target"; fi"#
            ),
        );
        self.stub(
            "useradd",
            &format!(
                "echo \"useradd $*\" >> {log}\necho 999 > {ctl}/agent_uid\necho 'landfall-agent docker' > {ctl}/agent_groups"
            ),
        );
        self.stub(
            "usermod",
            &format!(
                "echo \"usermod $*\" >> {log}\necho 'landfall-agent docker' > {ctl}/agent_groups"
            ),
        );
        self.stub(
            "id",
            &format!(
                r#"case "$1" in
  -u) exec cat {ctl}/agent_uid 2>/dev/null ;;
  -nG) exec cat {ctl}/agent_groups ;;
esac"#
            ),
        );
    }

    /// Where the sandbox holds what a script calls `absolute`.
    pub(super) fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// A command on the script's `PATH`.
    pub(super) fn stub(&self, name: &str, body: &str) {
        write_executable(&self.stubs.join(name), body);
    }

    /// The rows `systemctl` answers from: state, invocation id and restarts. A `sleep` moves
    /// to the next, and the last holds.
    pub(super) fn set_states(&self, rows: &[(&str, &str, u32)]) {
        let text = rows
            .iter()
            .map(|(state, id, restarts)| {
                let id = if id.is_empty() { NOTHING } else { id };
                format!("{state} {id} {restarts}\n")
            })
            .collect::<Vec<_>>()
            .concat();
        fs::write(self.stubs.join("states"), text).unwrap();
    }

    /// An agent's user that already exists.
    pub(super) fn set_agent_user(&self, uid: u32, groups: &str) {
        fs::write(self.stubs.join("agent_uid"), format!("{uid}\n")).unwrap();
        fs::write(self.stubs.join("agent_groups"), format!("{groups}\n")).unwrap();
    }

    /// An environment variable for what runs.
    pub(super) fn set_env(&mut self, name: &str, value: &str) {
        self.env.push((name.to_owned(), value.to_owned()));
    }

    /// `script` with every path it names in the sandbox, and its `PATH` the stubs'. One pass,
    /// so that the sandbox's own path isn't mapped again wherever the temp directory is.
    pub(super) fn text(&self, script: &str) -> String {
        let root = self.root.display().to_string();
        let mut mapped = String::with_capacity(script.len());
        let mut rest = script;
        while let Some(next) = rest.chars().next() {
            if let Some(prefix) = MAPPED.iter().find(|prefix| rest.starts_with(**prefix)) {
                mapped.push_str(&root);
                mapped.push_str(prefix);
                rest = &rest[prefix.len()..];
            } else {
                mapped.push(next);
                rest = &rest[next.len_utf8()..];
            }
        }
        mapped.replace(
            &format!("PATH={SYSTEM_PATH}"),
            &format!("PATH={}", self.path_var()),
        )
    }

    fn path_var(&self) -> String {
        format!("{}:/usr/bin:/bin", self.stubs.display())
    }

    fn command(&self, script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(self.text(script))
            .env_clear()
            .env("PATH", self.path_var())
            .envs(self.env.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Runs `script` in the sandbox.
    pub(super) fn run(&self, script: &str) -> Output {
        self.command(script).output().unwrap()
    }

    /// Starts `script` in the sandbox.
    pub(super) fn spawn(&self, script: &str) -> Child {
        self.command(script).spawn().unwrap()
    }

    /// What the stubs were asked to do.
    pub(super) fn log(&self) -> String {
        fs::read_to_string(self.path("/log")).unwrap_or_default()
    }
}

pub(super) fn write_executable(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

pub(super) fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub(super) fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
