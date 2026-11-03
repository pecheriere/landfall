//! A place to run a rendered script: every system path it names mapped into a temp directory,
//! and every command that would change the system a stub on `PATH`. Nothing here needs root
//! or touches a real path.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use tempfile::TempDir;

use super::shell::{SYSTEM_PATH, quote};

mod facts;
mod guards;
mod install;
mod plan;
mod script;
mod shell;
mod ssh;
mod unit;

/// What's mapped into the sandbox, wherever a script says it. With no trailing slash, as a
/// script names a directory by itself too.
const MAPPED: [&str; 4] = ["/usr/local/bin", "/etc", "/var/lib", "/tmp"];

const STATE_DIR: &str = "/var/lib/landfall-agent";

/// Stands for no value in the rows of `states`, which `set --` would otherwise lose.
const NOTHING: &str = "-";

pub(super) struct Sandbox {
    dir: TempDir,
    root: PathBuf,
    stubs: PathBuf,
    env: Vec<(String, String)>,
}

impl Sandbox {
    /// A sandbox whose unit is inactive and which has no agent's user yet.
    pub(super) fn new() -> Self {
        let dir = temp_dir();
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
        for path in ["usr/local/bin", "etc/landfall", "etc/systemd/system"] {
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(&stubs).unwrap();
        let sandbox = Self {
            root,
            stubs,
            env: Vec::new(),
            dir,
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
            // With the umask a PAM session may well set, whatever the script's was.
            &format!("echo \"runuser $*\" >> {log}\nshift 3\numask 022\nexec \"$@\""),
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
        let home = self.path(STATE_DIR);
        let home = home.display();
        self.stub(
            "useradd",
            &format!(
                "echo \"useradd $*\" >> {log}\necho 'landfall-agent:x:999:999::{home}:/usr/sbin/nologin' > {ctl}/passwd\necho 'landfall-agent docker' > {ctl}/agent_groups"
            ),
        );
        self.stub(
            "usermod",
            &format!(
                "echo \"usermod $*\" >> {log}\necho 'landfall-agent docker' > {ctl}/agent_groups"
            ),
        );
        self.install_lookup_stubs();
    }

    /// The commands that only say what's there, answering for a host the tests make up.
    fn install_lookup_stubs(&self) {
        let log = self.path("/log");
        let log = log.display();
        let ctl = self.stubs.display();
        self.stub(
            "id",
            &format!(
                r#"case "$1" in
  -nG) exec cat {ctl}/agent_groups ;;
  *) echo 1000 ;;
esac"#
            ),
        );
        self.stub(
            "getent",
            &format!(
                r#"case "$1 ${{2:-}}" in
  "passwd landfall-agent") grep '^landfall-agent:' {ctl}/passwd 2>/dev/null || exit 2 ;;
  "passwd ") cat {ctl}/passwd 2>/dev/null ;;
  *) exit 2 ;;
esac"#
            ),
        );
        // Files here can't belong to root, so all do but the one `set_owner` names. The mode is
        // the file's own, and the answer goes by the format, as the real one's does.
        self.stub(
            "stat",
            &format!(
                r#"format=
while [ "$#" -gt 1 ]; do
  if [ "$1" = -c ]; then format=$2; fi
  shift
done
path=$1
owner=0:0
if [ "$path" = "$(cat {ctl}/owned_path 2>/dev/null)" ]; then owner=$(cat {ctl}/owner); fi
mode=$(/usr/bin/stat -L -c %a "$path" 2>/dev/null || /usr/bin/stat -L -f %Mp%Lp "$path") || exit
printf '%s\n' "$format" | sed "s/%u/${{owner%:*}}/;s/%g/${{owner#*:}}/;s/%a/${{mode#0}}/""#
            ),
        );
        self.stub(
            "timeout",
            &format!("echo \"timeout $*\" >> {log}\nshift 3\nexec \"$@\""),
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

    /// `shell` runs first whenever the stub `name` is called.
    pub(super) fn before(&self, name: &str, shell: &str) {
        let real = self.stubs.join(format!("{name}.real"));
        fs::rename(self.stubs.join(name), &real).unwrap();
        self.stub(name, &format!("{shell}\nexec {} \"$@\"", real.display()));
    }

    /// The rows `systemctl` answers from: state, invocation id and restarts. A `sleep` moves
    /// to the next, and the last holds. This starts them again from the first.
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
        fs::write(self.stubs.join("tick"), "0\n").unwrap();
    }

    /// An agent's user that already exists, and is as an install would have made it.
    pub(super) fn set_agent_user(&self, uid: u32, groups: &str) {
        let home = self.path(STATE_DIR);
        self.set_passwd(&format!(
            "landfall-agent:x:{uid}:{uid}::{}:/usr/sbin/nologin\n",
            home.display()
        ));
        fs::write(self.stubs.join("agent_groups"), format!("{groups}\n")).unwrap();
    }

    /// What `getent passwd` says.
    pub(super) fn set_passwd(&self, text: &str) {
        fs::write(self.stubs.join("passwd"), text).unwrap();
    }

    /// `owner` is what `stat` says of the file a script calls `absolute`, as `uid:gid`.
    pub(super) fn set_owner(&self, absolute: &str, owner: &str) {
        let path = self.path(absolute);
        fs::write(self.stubs.join("owned_path"), path.display().to_string()).unwrap();
        fs::write(self.stubs.join("owner"), owner).unwrap();
    }

    /// An environment variable for what runs.
    pub(super) fn set_env(&mut self, name: &str, value: &str) {
        self.env.push((name.to_owned(), value.to_owned()));
    }

    /// `script` with every path it names in the sandbox, and its `PATH` the stubs'. It must say
    /// that `PATH`, or it would find the real commands, and what this returns names none of
    /// [`MAPPED`] but in the sandbox.
    pub(super) fn text(&self, script: &str) -> String {
        let system_path = format!("PATH={SYSTEM_PATH}");
        let (before, after) = script
            .split_once(&system_path)
            .unwrap_or_else(|| panic!("a script that doesn't set {system_path}:\n{script}"));
        let text = format!(
            "{}PATH={}{}",
            self.mapped(before),
            quote(&self.path_var()),
            self.mapped(after)
        );

        let root = self.root.display();
        let outside = MAPPED
            .iter()
            .fold(text.clone(), |rest, dir| {
                rest.replace(&format!("{root}{dir}"), "")
            })
            .replace(&self.dir.path().display().to_string(), "");
        for dir in MAPPED {
            let dir = dir.trim_end_matches('/');
            assert!(!outside.contains(dir), "{dir} isn't mapped in:\n{text}");
        }
        text
    }

    /// One pass, so that the sandbox's own path isn't mapped again wherever the temp directory
    /// is.
    fn mapped(&self, script: &str) -> String {
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
        mapped
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

/// A temp directory whose path a script can say bare, as the mapped paths are. So not under a
/// `TMPDIR` that needs quoting.
fn temp_dir() -> TempDir {
    let base = std::env::temp_dir();
    let plain = base.to_str().is_some_and(|path| {
        path.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    });
    if plain {
        TempDir::new().unwrap()
    } else {
        TempDir::new_in("/tmp").unwrap()
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
