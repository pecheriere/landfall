//! Each read command's view for a person. Every string the controller sent goes through
//! [`safe`] before it is printed, and every enum through [`wire_name`], so a value from a newer
//! controller reads `unknown`.

use std::fmt::Write as _;
use std::io::{self, Write};

use landfall_api::{
    ApprovalsView, AuditEntry, CommitsState, CommitsView, DeployView, DeploymentSummary,
    DeploymentView, HostView, HostsView, NextAction, Page, PromotionView, ReleaseStory,
    ReleaseView, RequestState, RequestView, RunningView, Why,
};
use landfall_core::ids::PrincipalId;
use serde_json::Value;

use super::Stopped;
use crate::display::{safe, wire_name};

/// The heading of a story's commits: an approver reads them to decide, so it says whose word
/// they are.
const COMMITS_HEADING: &str =
    "commits, as GitHub lists them (not verified; authors are GitHub's attribution)";

/// `secs` since the Unix epoch, in UTC, as RFC 3339; the number itself if out of range.
fn when(secs: i64) -> String {
    jiff::Timestamp::from_second(secs).map_or_else(|_| secs.to_string(), |at| at.to_string())
}

/// What a deployment's host last said of what runs.
fn running_text(running: Option<&RunningView>) -> String {
    let Some(running) = running else {
        return "nothing reported".to_owned();
    };
    let tag = running
        .tag
        .as_ref()
        .map_or_else(|| "nothing".to_owned(), ToString::to_string);
    let mut text = format!("runs {} ({})", safe(&tag), safe(&running.phase));
    for (flag, name) in [
        (running.busy, "busy"),
        (running.drift, "drifted"),
        (running.config_drift, "config drift"),
    ] {
        if flag {
            text.push_str(", ");
            text.push_str(name);
        }
    }
    text
}

/// One line for a deployment in a list.
fn summary_line(summary: &DeploymentSummary) -> String {
    let latest = summary.latest.as_ref().map_or_else(
        || "no release known".to_owned(),
        |latest| {
            format!(
                "latest {} {}",
                safe(latest.tag.as_ref()),
                safe(&wire_name(&latest.status))
            )
        },
    );
    let mut line = format!(
        "{} on {}: {}, {latest}",
        safe(summary.id.as_ref()),
        safe(summary.host.as_ref()),
        running_text(summary.running.as_ref()),
    );
    if let Some(request) = summary.open_request {
        // Writing to a String cannot fail.
        let _ = write!(line, ", request {request}");
    }
    if summary.needs_you {
        line.push_str(", needs you");
    }
    line
}

/// `next: <kind>: <detail>`, when there is something to do.
fn next_line(next: Option<&NextAction>, out: &mut dyn Write) -> io::Result<()> {
    match next {
        Some(next) => writeln!(
            out,
            "next: {}: {}",
            safe(&wire_name(&next.kind)),
            safe(&next.detail)
        ),
        None => Ok(()),
    }
}

/// What `status` says when it stopped paging before the last page.
pub(crate) fn stopped_text(stopped: Stopped) -> &'static str {
    match stopped {
        Stopped::Items => {
            "stopped at 1000 deployments: narrow it with --host, --repo or --needs-you"
        }
        Stopped::Bytes => {
            "stopped at 8 MiB of answers: narrow it with --host, --repo or --needs-you"
        }
        Stopped::Pages => "stopped after 20 pages: narrow it with --host, --repo or --needs-you",
        Stopped::RepeatedCursor => "stopped: the controller sent a cursor it had already sent",
    }
}

/// The deployments, a line each.
pub(crate) fn deployments(summaries: &[DeploymentSummary], out: &mut dyn Write) -> io::Result<()> {
    if summaries.is_empty() {
        return writeln!(out, "no deployments");
    }
    for summary in summaries {
        writeln!(out, "{}", summary_line(summary))?;
    }
    Ok(())
}

fn promotion_text(promotion: &PromotionView) -> String {
    format!(
        "{} after {} s healthy",
        safe(&promotion.deployment.to_string()),
        promotion.healthy_for_secs
    )
}

/// One deployment in full.
pub(crate) fn deployment(view: &DeploymentView, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{}", summary_line(&view.summary))?;
    writeln!(out, "repository {}", safe(view.summary.repo.as_ref()))?;
    let rule = &view.rule;
    let bump =
        |bump: Option<&String>| bump.map_or_else(|| "never".to_owned(), |b| safe(b).into_owned());
    let approvers: Vec<String> = rule
        .approvers
        .iter()
        .map(|approver| safe(approver.as_ref()).into_owned())
        .collect();
    writeln!(
        out,
        "rule: auto {}, approve {}, approvers {}, prereleases {}",
        bump(rule.auto.as_ref()),
        bump(rule.approve.as_ref()),
        if approvers.is_empty() {
            "none".to_owned()
        } else {
            approvers.join(", ")
        },
        if rule.prereleases { "yes" } else { "no" },
    )?;
    if let Some(promotion) = &view.promote_to {
        writeln!(out, "promotes to {}", promotion_text(promotion))?;
    }
    for promotion in &view.promoted_from {
        writeln!(out, "promoted from {}", promotion_text(promotion))?;
    }
    if !view.holds.is_empty() {
        writeln!(out, "holds:")?;
    }
    for hold in &view.holds {
        let tag = hold
            .tag
            .as_ref()
            .map_or_else(|| "the whole deployment".to_owned(), ToString::to_string);
        writeln!(
            out,
            "  {}: {}, since {}",
            safe(&tag),
            safe(&hold.reason),
            when(hold.since)
        )?;
    }
    let more = usize::try_from(view.holds_total)
        .unwrap_or(usize::MAX)
        .saturating_sub(view.holds.len());
    if more > 0 {
        writeln!(out, "  and {more} more")?;
    }
    Ok(())
}

/// A deploy's state and outcome: `finished, rolled_back`.
fn deploy_state(state: &impl serde::Serialize, outcome: Option<&impl serde::Serialize>) -> String {
    let state = wire_name(state);
    match outcome {
        Some(outcome) => format!("{}, {}", safe(&state), safe(&wire_name(outcome))),
        None => safe(&state).into_owned(),
    }
}

/// `, approved by <principal>`, or nothing when nobody approved.
fn approved_by(principal: Option<&PrincipalId>) -> String {
    principal
        .map(|by| format!(", approved by {}", safe(by.as_ref())))
        .unwrap_or_default()
}

/// A deployment's deploys, newest first.
pub(crate) fn deploys(page: &Page<DeployView>, out: &mut dyn Write) -> io::Result<()> {
    if page.items.is_empty() {
        return writeln!(out, "no deploys");
    }
    for deploy in &page.items {
        let host = deploy
            .host
            .as_ref()
            .map_or_else(|| "a host you can't see".to_owned(), ToString::to_string);
        writeln!(
            out,
            "deploy {}: {} on {}, {}, queued {}",
            deploy.id,
            safe(deploy.tag.as_ref()),
            safe(&host),
            deploy_state(&deploy.state, deploy.outcome.as_ref()),
            when(deploy.created_at)
        )?;
        if let Some(request) = deploy.request {
            let by = approved_by(deploy.approved_by.as_ref());
            writeln!(out, "  from request {request}{by}")?;
        }
        if let Some(reason) = &deploy.reason {
            writeln!(out, "  reason: {}", safe(reason))?;
        }
        if let Some(reason) = &deploy.rollback_reason {
            writeln!(out, "  going back failed: {}", safe(reason))?;
        }
        for step in &deploy.steps {
            if let Some(failure) = &step.failure {
                writeln!(out, "  step {} failed: {}", safe(&step.name), safe(failure))?;
            }
        }
    }
    more_line(page.next_cursor.is_some(), out)
}

/// Says that a list has more than this page, when it does.
fn more_line(more: bool, out: &mut dyn Write) -> io::Result<()> {
    if more {
        writeln!(out, "(more: raise --limit, up to 100, or use --json)")?;
    }
    Ok(())
}

/// A deployment's releases, newest first.
pub(crate) fn releases(page: &Page<ReleaseView>, out: &mut dyn Write) -> io::Result<()> {
    if page.items.is_empty() {
        return writeln!(out, "no releases");
    }
    for release in &page.items {
        writeln!(
            out,
            "{}: {} (decision {}), first seen {}",
            safe(release.tag.as_ref()),
            safe(&wire_name(&release.status)),
            safe(&wire_name(&release.decision)),
            when(release.first_seen_at)
        )?;
    }
    more_line(page.next_cursor.is_some(), out)
}

/// `<compare_url>`, or what stands for it when there is none.
fn link(commits: &CommitsView) -> String {
    commits
        .compare_url
        .as_deref()
        .map_or_else(|| "no link".to_owned(), |url| safe(url).into_owned())
}

/// The commits a release brings, or why they're unknown: never "no commits" unless GitHub
/// listed none.
fn commits(commits: &CommitsView, out: &mut dyn Write) -> io::Result<()> {
    let base = commits.base.as_ref().map_or_else(
        || "the release below".to_owned(),
        |b| safe(b.as_ref()).into_owned(),
    );
    let unknown = match commits.state {
        CommitsState::Listed => None,
        CommitsState::TooLarge => {
            return writeln!(out, "commits: too large to list here: {}", link(commits));
        }
        CommitsState::First => {
            return writeln!(
                out,
                "commits: the first verified release, with none below to compare with"
            );
        }
        CommitsState::BaseNotFound => Some(format!(
            "{base} isn't an ancestor of this release: the history was rewritten between them; \
             compare at {}",
            link(commits)
        )),
        CommitsState::NotYet => Some("not fetched from GitHub yet".to_owned()),
        CommitsState::Unavailable => {
            Some("GitHub couldn't be asked; it is tried again later".to_owned())
        }
        CommitsState::NotRecorded => Some(
            "never fetched: the release isn't verified under this configuration, or was \
             recorded before the controller compared commits"
                .to_owned(),
        ),
        CommitsState::Unknown => Some("a state this CLI doesn't know".to_owned()),
    };
    if let Some(why) = unknown {
        return writeln!(out, "commits: unknown: {why}");
    }
    if commits.commits.is_empty() {
        return writeln!(
            out,
            "commits since {base}: no commits, as GitHub lists them"
        );
    }
    writeln!(out, "{COMMITS_HEADING}, since {base}:")?;
    for commit in &commits.commits {
        let sha = commit.sha.as_ref();
        let author = commit
            .author
            .as_deref()
            .map_or_else(|| "no author".to_owned(), |a| safe(a).into_owned());
        writeln!(
            out,
            "  {} {} ({author})",
            safe(sha.get(..12).unwrap_or(sha)),
            safe(&commit.summary)
        )?;
    }
    let shown = u64::try_from(commits.commits.len()).unwrap_or(u64::MAX);
    if let Some(total) = commits.total.filter(|total| *total > shown) {
        writeln!(
            out,
            "the newest {shown} of {total}; all of them at {}",
            link(commits)
        )?;
    }
    Ok(())
}

/// One release's story.
pub(crate) fn story(story: &ReleaseStory, out: &mut dyn Write) -> io::Result<()> {
    let release = &story.release;
    writeln!(
        out,
        "{}: {} (decision {})",
        safe(release.tag.as_ref()),
        safe(&wire_name(&release.status)),
        safe(&wire_name(&release.decision))
    )?;
    for reason in &story.reasons {
        writeln!(out, "  {}", safe(reason))?;
    }
    next_line(story.next.as_ref(), out)?;
    match &story.origin {
        Some(origin) => {
            let signer = origin.signer.as_ref().map_or_else(
                || "tag signature not required".to_owned(),
                |signer| format!("tag signed by {}", safe(signer.as_ref())),
            );
            writeln!(
                out,
                "origin: commit {}, digest {}, {signer}",
                safe(origin.commit.as_ref()),
                safe(origin.digest.as_ref())
            )?;
            writeln!(out, "  built by {}", safe(&origin.san))?;
            writeln!(out, "  run {}", safe(&origin.run_url))?;
            if let Some(index) = origin.rekor_log_index {
                writeln!(out, "  transparency log index {index}")?;
            }
        }
        None => writeln!(out, "origin: not verified")?,
    }
    commits(&story.commits, out)?;
    if !story.requests.is_empty() {
        writeln!(out, "requests:")?;
    }
    for request in &story.requests {
        let approved = approved_by(request.approved_by.as_ref());
        let closed = request
            .closed_reason
            .as_deref()
            .map(|reason| format!(": {}", safe(reason)))
            .unwrap_or_default();
        writeln!(
            out,
            "  request {}: {}, asked by {} at {}{approved}{closed}",
            request.id,
            safe(&wire_name(&request.state)),
            safe(request.requested_by.as_ref()),
            when(request.created_at)
        )?;
    }
    if !story.deploys.is_empty() {
        writeln!(out, "deploys:")?;
    }
    for deploy in &story.deploys {
        writeln!(
            out,
            "  deploy {}: {}, queued {}",
            deploy.id,
            deploy_state(&deploy.state, deploy.outcome.as_ref()),
            when(deploy.created_at)
        )?;
    }
    Ok(())
}

/// Why a deploy ended as it did.
pub(crate) fn why(why: &Why, out: &mut dyn Write) -> io::Result<()> {
    let outcome = why
        .outcome
        .as_ref()
        .map_or_else(|| "not finished".to_owned(), wire_name);
    writeln!(out, "deploy {}: {}", why.deploy, safe(&outcome))?;
    writeln!(out, "{}", safe(&why.summary))?;
    for event in &why.events {
        let at = event
            .at
            .map(|at| format!("{} ", when(at)))
            .unwrap_or_default();
        writeln!(
            out,
            "  {at}{}: {}",
            safe(&wire_name(&event.what)),
            safe(&event.text)
        )?;
    }
    next_line(why.next.as_ref(), out)
}

/// One host, and the deployments on it that this principal may view.
pub(crate) fn host(host: &HostView, out: &mut dyn Write) -> io::Result<()> {
    let enrolled = host.enrolled_at.map_or_else(
        || "never enrolled".to_owned(),
        |at| format!("enrolled {}", when(at)),
    );
    let report = host.last_report.map_or_else(
        || "no report yet".to_owned(),
        |at| format!("last report {}", when(at)),
    );
    let drift = if host.config_drift {
        ", config drift"
    } else {
        ""
    };
    writeln!(
        out,
        "{}: {enrolled}, {report}{drift}",
        safe(host.id.as_ref())
    )?;
    for summary in &host.deployments {
        writeln!(out, "  {}", summary_line(summary))?;
    }
    Ok(())
}

/// The hosts this principal may see.
pub(crate) fn hosts(hosts: &HostsView, out: &mut dyn Write) -> io::Result<()> {
    if hosts.hosts.is_empty() {
        return writeln!(out, "no hosts");
    }
    for view in &hosts.hosts {
        host(view, out)?;
    }
    Ok(())
}

/// A value of an audit row's detail: a string as itself, anything else as JSON, escaped.
fn detail_value(value: &Value) -> String {
    match value {
        Value::String(text) => safe(text).into_owned(),
        other => safe(&other.to_string()).into_owned(),
    }
}

/// A page of the audit log.
pub(crate) fn audit(page: &Page<AuditEntry>, out: &mut dyn Write) -> io::Result<()> {
    if page.items.is_empty() {
        return writeln!(out, "no audit rows");
    }
    for entry in &page.items {
        let mut line = format!("{} {} {}", entry.seq, when(entry.ts), safe(&entry.kind));
        if let Some(deployment) = &entry.deployment {
            let _ = write!(line, " {}", safe(deployment.as_ref()));
        }
        if let Some(host) = &entry.host {
            let _ = write!(line, " on {}", safe(host.as_ref()));
        }
        match &entry.detail {
            Value::Object(fields) => {
                for (name, value) in fields {
                    let _ = write!(line, " {}={}", safe(name), detail_value(value));
                }
            }
            other => {
                let _ = write!(line, " {}", detail_value(other));
            }
        }
        writeln!(out, "{line}")?;
    }
    more_line(page.next_cursor.is_some(), out)
}

/// Where an approver signs an open request, and that agents can't: `landfall request`
/// prints it too.
pub(crate) fn approval_line(approve_url: Option<&str>, out: &mut dyn Write) -> io::Result<()> {
    match approve_url {
        Some(url) => writeln!(
            out,
            "An approver signs this at {} with their passkey. Agents can't approve.",
            safe(url)
        ),
        None => writeln!(
            out,
            "This controller has no [approval] settings, so nobody can approve yet."
        ),
    }
}

/// One request waiting for an approver: what it would deploy, and what an approver signs.
fn request(
    request: &RequestView,
    approve_url: Option<&str>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let intent = &request.intent;
    writeln!(
        out,
        "request {} for {} on {}: {}, {}, asked by {} at {}, until {}",
        request.id,
        safe(intent.deployment.as_ref()),
        safe(request.host.as_ref()),
        safe(intent.tag.as_ref()),
        safe(&wire_name(&request.state)),
        safe(request.requested_by.as_ref()),
        when(request.created_at),
        when(request.expires_at)
    )?;
    writeln!(out, "  commit {}", safe(intent.commit.as_ref()))?;
    writeln!(out, "  digest {}", safe(intent.digest.as_ref()))?;
    let expected = intent.expected_running.as_ref().map_or_else(
        || "nothing (a first deploy)".to_owned(),
        |digest| safe(digest.as_ref()).into_owned(),
    );
    writeln!(out, "  expects running {expected}")?;
    writeln!(out, "  nonce {}", safe(&intent.nonce))?;
    // Only an open request can be signed: the controller lists only those, and anything else
    // a newer one sends is shown for what it is.
    if request.state == RequestState::AwaitingApproval {
        approval_line(approve_url, out)?;
    }
    Ok(())
}

/// The requests waiting for an approver.
pub(crate) fn approvals(
    approvals: &ApprovalsView,
    approve_url: Option<&str>,
    out: &mut dyn Write,
) -> io::Result<()> {
    if approvals.approvals.is_empty() {
        return writeln!(out, "nothing waits for an approver");
    }
    for view in &approvals.approvals {
        request(view, approve_url, out)?;
    }
    Ok(())
}
