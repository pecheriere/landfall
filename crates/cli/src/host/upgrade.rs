//! `landfall host upgrade`: the same verification and the same way of running a script as an
//! install, touching only the binary and a restart. The controller isn't asked, and neither the
//! configuration, the units nor the key are looked at.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;
use landfall_core::ids::ReleaseTag;
use semver::Version;
use tokio::runtime::Runtime;

use super::HostError;
use super::facts::{Refusal, check_for_upgrade, shown_version};
use super::install::{
    Confirm, Outcome, Upload, deliver_and_run, permission, print_plan, read_facts, unix_now,
};
use super::plan::{Timing, UPLOAD_AGENT, UpgradeRequest, render, upgrade_steps};
use super::ssh::{Destination, Remote};
use super::upload_dir;
use crate::agent_release::{AgentSource, VerifiedAgent, default_tag, sha256_hex};

/// Arguments of `landfall host upgrade`.
#[derive(Debug, Args)]
pub struct UpgradeArgs {
    /// The target: `[user@]host` or `ssh://[user@]host[:port]`.
    #[arg(value_name = "DEST")]
    pub dest: String,
    /// The release to upgrade to. Defaults to this `landfall`'s own version.
    #[arg(long, value_name = "TAG")]
    pub tag: Option<ReleaseTag>,
    /// Allow going back to an older version, replacing the same version with other bytes, or
    /// replacing what doesn't say what version it is.
    #[arg(long)]
    pub allow_downgrade: bool,
    /// Show what would run, and change nothing on the target.
    #[arg(long)]
    pub dry_run: bool,
    /// Don't ask before running it. Needed without a terminal.
    #[arg(long)]
    pub yes: bool,
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

/// What an upgrade is to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// It's there already.
    Nothing,
    /// A newer version, or nothing there to compare with.
    Upgrade,
    /// An older version, with `--allow-downgrade`.
    Downgrade,
    /// The same version with other bytes, or one that doesn't say, with `--allow-downgrade`.
    Replace,
}

/// What to do about what's on the target. `running` is what its `--version` said, and
/// `running_sha256` its hash, both hostile, and both empty if there's no agent there, as
/// [`host install`](super::install) sends a host that's lost its binary here. There's nothing then
/// to go back from.
///
/// # Errors
///
/// [`HostError::OlderVersion`], [`HostError::OtherBytes`] or [`HostError::UnknownVersion`] for
/// what needs `allow_downgrade`, and hasn't got it.
pub fn decide(
    running: &str,
    running_sha256: &str,
    wanted: &VerifiedAgent,
    allow_downgrade: bool,
) -> Result<Decision, HostError> {
    if running.is_empty() && running_sha256.is_empty() {
        return Ok(Decision::Upgrade);
    }
    if running_sha256 == wanted.sha256() {
        return Ok(Decision::Nothing);
    }
    let needing_the_flag = |decision, error: HostError| {
        if allow_downgrade {
            Ok(decision)
        } else {
            Err(error)
        }
    };
    let Some(version) = running_version(running) else {
        return needing_the_flag(
            Decision::Replace,
            HostError::UnknownVersion {
                running: running.to_owned(),
                wanted: wanted.version().clone(),
            },
        );
    };
    match version.cmp(wanted.version()) {
        std::cmp::Ordering::Less => Ok(Decision::Upgrade),
        std::cmp::Ordering::Greater => needing_the_flag(
            Decision::Downgrade,
            HostError::OlderVersion {
                running: version,
                wanted: wanted.version().clone(),
            },
        ),
        std::cmp::Ordering::Equal => needing_the_flag(
            Decision::Replace,
            HostError::OtherBytes {
                version,
                running_sha256: running_sha256.to_owned(),
                wanted_sha256: wanted.sha256().to_owned(),
            },
        ),
    }
}

/// The version in what `landfall-agent --version` prints: `landfall-agent 1.2.3`.
fn running_version(said: &str) -> Option<Version> {
    let last = said.rsplit(' ').next()?;
    last.strip_prefix('v').unwrap_or(last).parse().ok()
}

/// Runs `landfall host upgrade` with what reaches the outside world passed in, so that a test can
/// give its own. Nothing on a command line leads to a fake.
///
/// # Errors
///
/// A [`HostError`], whose [`HostError::exit_code`] is the process's status.
pub fn run_with<S: AgentSource, R: Remote>(
    args: &UpgradeArgs,
    source: &S,
    remote: &R,
    runtime: &Runtime,
    out: &mut dyn Write,
    confirm: &mut dyn Confirm,
) -> Result<Outcome, HostError> {
    source.ready().map_err(HostError::Release)?;
    let tag =
        default_tag(env!("CARGO_PKG_VERSION"), args.tag.clone()).map_err(HostError::Release)?;
    let dest = Destination::parse(&args.dest)?;
    let output = |result: io::Result<()>| result.map_err(HostError::Output);
    output(writeln!(out, "landfall: connecting to {dest}"))?;

    let facts = read_facts(remote, &[])?;
    let warnings = check_for_upgrade(&facts, unix_now()).map_err(HostError::Refused)?;
    for warning in warnings {
        output(writeln!(out, "landfall: warning: {warning}"))?;
    }
    if !facts.unit_present() {
        return Err(HostError::NoUnit);
    }
    let arch = facts
        .arch()
        .ok_or_else(|| HostError::Refused(vec![Refusal::UnknownArch(String::new())]))?;

    let agent = runtime
        .block_on(source.agent(&tag, arch))
        .map_err(HostError::Release)?;
    let running = facts.agent_version().unwrap_or_default();
    let running_sha256 = facts.agent_sha256().unwrap_or_default();
    let decision = decide(running, running_sha256, &agent, args.allow_downgrade)?;
    output(writeln!(
        out,
        "landfall: the target has {}, SHA-256 {}, and this is {}: {decision:?}",
        shown_version(running),
        shown_version(running_sha256),
        agent.version(),
    ))?;
    // A run that failed, or was stopped, with the file in place and no restart since looks the
    // same but for this. Where the login can't look, root's script does.
    if decision == Decision::Nothing && facts.restart_pending() == Some(false) {
        output(writeln!(out, "landfall: it's on that version already"))?;
        return Ok(Outcome::Nothing);
    }

    let upload = upload_dir()?;
    let steps = upgrade_steps(&UpgradeRequest {
        sha256: agent.sha256(),
        upload: &upload,
        timing: args.timing,
        only_if_none_there: running_sha256.is_empty() && !args.allow_downgrade,
    });
    let script = render(&steps);
    let script_sha256 = sha256_hex(script.as_bytes());
    output(print_plan(
        out,
        &dest,
        &agent,
        &steps,
        &script,
        &script_sha256,
    ))?;
    if args.dry_run {
        return Ok(Outcome::DryRun);
    }

    let Some(interactive) = permission(args.yes, &facts, &script_sha256, remote, confirm, out)?
    else {
        return Ok(Outcome::Declined);
    };
    let uploads = [Upload {
        name: UPLOAD_AGENT,
        what: "the agent",
        bytes: agent.bytes(),
    }];
    deliver_and_run(remote, &upload, &script, interactive, &uploads, out)?;
    Ok(Outcome::Installed)
}
