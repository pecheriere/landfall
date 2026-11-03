//! `landfall host install`: everything local first, then what the target says, then the agent
//! verified, and only then, once what will run has been shown, anything sent.

use std::fs::{self, File};
use std::io::{self, Read as _, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use landfall_core::controller_url::ControllerUrl;
use landfall_core::ids::{HostId, ReleaseTag};
use landfall_core::protocol::EnrolCode;
use tokio::runtime::Runtime;

use super::facts::{HostFacts, Refusal, check, probe};
use super::plan::{
    EnrolTarget, InstallRequest, Step, Timing, UPLOAD_AGENT, UPLOAD_CODE, UPLOAD_CONFIG,
    install_steps, render,
};
use super::shell::{quote, remote_command};
use super::ssh::{Destination, Output, Remote};
use super::unit::{UnitInput, agent_unit, check_path, recover_unit};
use super::{HostError, upload_dir};
use crate::agent_release::{AgentSource, VerifiedAgent, default_tag, sha256_hex};

/// The most an enrolment code's file is read of: a code is 64 digits.
const CODE_FILE_CAP: u64 = 4096;

/// Arguments of `landfall host install`.
#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is its own flag on the command line, which is how clap derives them"
)]
pub struct InstallArgs {
    /// The target: `[user@]host` or `ssh://[user@]host[:port]`.
    #[arg(value_name = "DEST")]
    pub dest: String,
    /// The host's id in the configuration.
    #[arg(long, value_name = "ID")]
    pub host: HostId,
    /// The fleet configuration file, which goes to the target as it is.
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// The controller the agent polls.
    #[arg(long, value_name = "URL")]
    pub controller: String,
    /// Let the controller be `http://`.
    #[arg(long)]
    pub allow_insecure_controller: bool,
    /// A file holding the enrolment code from `landfall-server enrol-code`. It reaches the target
    /// over SSH's input, and never a command line.
    #[arg(long, value_name = "FILE")]
    pub code_file: Option<PathBuf>,
    /// The release to install. Defaults to this `landfall`'s own version.
    #[arg(long, value_name = "TAG")]
    pub tag: Option<ReleaseTag>,
    /// Show what would run, and change nothing on the target.
    #[arg(long)]
    pub dry_run: bool,
    /// Don't ask before running it. Needed without a terminal.
    #[arg(long)]
    pub yes: bool,
    /// Replace a configuration on the target that differs, keeping the old file as
    /// `fleet.toml.previous`.
    #[arg(long)]
    pub replace_config: bool,
    /// Replace units on the target that differ, each keeping the old file as `.previous`.
    #[arg(long)]
    pub replace_unit: bool,
    /// The `ssh_config` to use, instead of the usual ones.
    #[arg(long, value_name = "FILE")]
    pub ssh_config: Option<PathBuf>,
    /// The Sigstore TUF cache directory; it must exist. Defaults to
    /// `$XDG_CACHE_HOME/landfall/tuf` (or `~/.cache/landfall/tuf`), created when missing.
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,
    /// How long a started agent is watched. The Docker tests shorten it; no flag sets it.
    #[arg(skip)]
    pub timing: Timing,
}

/// What came of an install that didn't fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The script ran to its end.
    Installed,
    /// `--dry-run`: it was shown, and nothing was sent.
    DryRun,
    /// The operator said no: nothing was sent.
    Declined,
}

/// Asks the operator.
pub trait Confirm {
    /// Whether there is someone to ask.
    fn is_terminal(&self) -> bool;

    /// Whether to run the script with this hash, which they have just been shown.
    ///
    /// # Errors
    ///
    /// If they couldn't be asked.
    fn ask(&mut self, script_sha256: &str) -> io::Result<bool>;
}

/// What was found fit before connecting.
struct Local {
    config: Vec<u8>,
    dirs: Vec<String>,
    controller: ControllerUrl,
    tag: ReleaseTag,
    dest: Destination,
    code: Option<EnrolCode>,
}

/// Everything that needs no target, so that a mistake here costs no connection. That this build
/// can verify anything at all comes first.
fn local_checks<S: AgentSource>(args: &InstallArgs, source: &S) -> Result<Local, HostError> {
    source.ready().map_err(HostError::Release)?;
    let tag =
        default_tag(env!("CARGO_PKG_VERSION"), args.tag.clone()).map_err(HostError::Release)?;
    let config = fs::read(&args.config).map_err(|source| HostError::ReadConfig {
        path: args.config.clone(),
        source,
    })?;
    let parsed = landfall_approval::parse_config(&config).map_err(|source| HostError::Config {
        path: args.config.clone(),
        source: Box::new(source),
    })?;
    let mut dirs: Vec<String> = parsed
        .deployments_for_host(&args.host)
        .map(|deployment| deployment.compose().dir().to_owned())
        .collect();
    dirs.sort_unstable();
    dirs.dedup();
    if dirs.is_empty() {
        return Err(HostError::NoDeployment {
            host: args.host.clone(),
            path: args.config.clone(),
        });
    }
    for dir in &dirs {
        check_path(dir)?;
    }
    let controller = ControllerUrl::parse(&args.controller, args.allow_insecure_controller)?;
    let dest = Destination::parse(&args.dest)?;
    let code = args.code_file.as_deref().map(read_code).transpose()?;
    Ok(Local {
        config,
        dirs,
        controller,
        tag,
        dest,
        code,
    })
}

/// The code in a regular file that isn't a link, without any of its content reaching an error.
fn read_code(path: &Path) -> Result<EnrolCode, HostError> {
    let code_file = |source| HostError::CodeFile {
        path: path.to_owned(),
        source,
    };
    let not_regular = || HostError::CodeNotRegular(path.to_owned());
    let found = fs::symlink_metadata(path).map_err(code_file)?;
    if !found.is_file() {
        return Err(not_regular());
    }
    let file = File::open(path).map_err(code_file)?;
    let opened = file.metadata().map_err(code_file)?;
    if (opened.dev(), opened.ino()) != (found.dev(), found.ino()) {
        return Err(not_regular());
    }
    let mut text = String::new();
    file.take(CODE_FILE_CAP)
        .read_to_string(&mut text)
        .map_err(code_file)?;
    text.trim()
        .parse()
        .map_err(|_| HostError::CodeInvalid(path.to_owned()))
}

fn read_facts<R: Remote>(remote: &R, dirs: &[&str]) -> Result<HostFacts, HostError> {
    let output = remote.run(&remote_command(&probe(dirs)), b"")?;
    Ok(HostFacts::parse(&String::from_utf8_lossy(&output.stdout))?)
}

/// What the target is to run. The upload's name is in it, so what is shown is what runs.
fn script(args: &InstallArgs, local: &Local, agent: &VerifiedAgent, upload: &str) -> Vec<Step> {
    let dirs: Vec<&str> = local.dirs.iter().map(String::as_str).collect();
    let unit = agent_unit(&UnitInput {
        controller: &local.controller,
        host: &args.host,
        allow_insecure: args.allow_insecure_controller,
        compose_dirs: &dirs,
    });
    let recover = recover_unit(&dirs);
    let version = agent.version().to_string();
    let config_sha256 = sha256_hex(&local.config);
    install_steps(&InstallRequest {
        sha256: agent.sha256(),
        version: &version,
        config_sha256: &config_sha256,
        replace_config: args.replace_config,
        replace_unit: args.replace_unit,
        enrol: local.code.as_ref().map(|_| EnrolTarget {
            controller: &local.controller,
            host: &args.host,
            allow_insecure: args.allow_insecure_controller,
        }),
        unit: &unit,
        recover_unit: &recover,
        upload,
        timing: args.timing,
    })
}

fn print_plan(
    out: &mut dyn Write,
    dest: &Destination,
    agent: &VerifiedAgent,
    steps: &[Step],
    script: &str,
    script_sha256: &str,
) -> io::Result<()> {
    writeln!(
        out,
        "landfall: the agent is {}, SHA-256 {}",
        agent.summary(),
        agent.sha256()
    )?;
    let titles: Vec<&str> = steps.iter().map(|step| step.title.as_str()).collect();
    writeln!(out, "landfall: the steps are {}", titles.join(", "))?;
    writeln!(out, "landfall: this is what runs as root on {dest}:")?;
    writeln!(out, "{script}")?;
    writeln!(out, "landfall: the script's SHA-256 is {script_sha256}")
}

/// The login's own leftovers, which are all that it can remove anyway: the root script takes
/// another user's, once they are old.
fn remove_stale() -> String {
    remote_command(
        r#"find /tmp -maxdepth 1 -name 'landfall-install.*' -user "$(id -u)" -exec rm -rf -- {} + 2> /dev/null"#,
    )
}

/// Fails if anything is there, so that nothing can be planted.
fn make_upload(upload: &str) -> String {
    remote_command(&format!("umask 077 && mkdir -m 700 -- {}", quote(upload)))
}

fn write_upload(upload: &str, name: &str) -> String {
    remote_command(&format!(
        "umask 077 && cat > {}",
        quote(&format!("{upload}/{name}"))
    ))
}

fn remove_upload(upload: &str) -> String {
    remote_command(&format!("rm -rf -- {}", quote(upload)))
}

fn succeeded(output: &Output, what: &'static str) -> Result<(), HostError> {
    if output.status == 0 {
        Ok(())
    } else {
        Err(HostError::Upload {
            what,
            status: output.status,
            said: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// Sends what the script reads, with the code last, as close to the script as it can be, by
/// input and never in a command.
fn send<R: Remote>(
    remote: &R,
    upload: &str,
    agent: &VerifiedAgent,
    config: &[u8],
    code: Option<&EnrolCode>,
) -> Result<(), HostError> {
    let file = |name| write_upload(upload, name);
    succeeded(
        &remote.run(&file(UPLOAD_AGENT), agent.bytes())?,
        "the agent",
    )?;
    succeeded(
        &remote.run(&file(UPLOAD_CONFIG), config)?,
        "the configuration",
    )?;
    if let Some(code) = code {
        let hex = code.to_hex();
        succeeded(
            &remote.run(&file(UPLOAD_CODE), hex.as_bytes())?,
            "the enrolment code",
        )?;
    }
    Ok(())
}

/// The upload, then the script. Whatever comes of either, nothing of the upload is left that
/// this can remove: the script removes it itself on its way out, or this does when it didn't run.
fn deliver_and_run<R: Remote>(
    remote: &R,
    upload: &str,
    script: &str,
    interactive: bool,
    agent: &VerifiedAgent,
    local: &Local,
    out: &mut dyn Write,
) -> Result<(), HostError> {
    // Whether anything was there to remove doesn't matter, and a lost connection will show next.
    let _ = remote.run(&remove_stale(), b"")?;
    succeeded(&remote.run(&make_upload(upload), b"")?, "a directory")?;
    let ran = send(remote, upload, agent, &local.config, local.code.as_ref()).and_then(|()| {
        out.flush().map_err(HostError::Output)?;
        match remote.run_privileged(script, interactive)? {
            0 => Ok(()),
            status => Err(HostError::ScriptFailed(status)),
        }
    });
    if ran.is_err() {
        // It's being reported already, and the root script removes what stays here once it's old.
        let _ = remote.run(&remove_upload(upload), b"");
    }
    ran
}

/// Runs `landfall host install` with what reaches the outside world passed in, so that a test can
/// give its own. Nothing on a command line leads to a fake.
///
/// # Errors
///
/// A [`HostError`], whose [`HostError::exit_code`] is the process's status.
pub fn run_with<S: AgentSource, R: Remote>(
    args: &InstallArgs,
    source: &S,
    remote: &R,
    runtime: &Runtime,
    out: &mut dyn Write,
    confirm: &mut dyn Confirm,
) -> Result<Outcome, HostError> {
    let local = local_checks(args, source)?;
    let output = |result: io::Result<()>| result.map_err(HostError::Output);
    output(writeln!(out, "landfall: connecting to {}", local.dest))?;

    let dirs: Vec<&str> = local.dirs.iter().map(String::as_str).collect();
    let facts = read_facts(remote, &dirs)?;
    let warnings =
        check(&facts, unix_now(), &dirs, &local.controller).map_err(HostError::Refused)?;
    for warning in warnings {
        output(writeln!(out, "landfall: warning: {warning}"))?;
    }
    let arch = facts
        .arch()
        .ok_or_else(|| HostError::Refused(vec![Refusal::UnknownArch(String::new())]))?;

    let agent = runtime
        .block_on(source.agent(&local.tag, arch))
        .map_err(HostError::Release)?;

    let upload = upload_dir()?;
    let steps = script(args, &local, &agent, &upload);
    let script = render(&steps);
    let script_sha256 = sha256_hex(script.as_bytes());
    output(print_plan(
        out,
        &local.dest,
        &agent,
        &steps,
        &script,
        &script_sha256,
    ))?;
    if args.dry_run {
        return Ok(Outcome::DryRun);
    }

    let interactive = confirm.is_terminal();
    if !args.yes {
        if !interactive {
            return Err(HostError::NoTerminal);
        }
        output(out.flush())?;
        if !confirm.ask(&script_sha256).map_err(HostError::Output)? {
            return Ok(Outcome::Declined);
        }
    }
    // With nobody to answer it, a prompt would only be found out after the upload.
    if !interactive && !facts.is_root() {
        let sudo = remote.run(&remote_command("sudo -n true"), b"")?;
        if sudo.status != 0 {
            return Err(HostError::NoSudo);
        }
    }
    deliver_and_run(remote, &upload, &script, interactive, &agent, &local, out)?;
    Ok(Outcome::Installed)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}
