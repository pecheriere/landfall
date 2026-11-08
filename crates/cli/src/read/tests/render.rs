//! What each view prints for a person: hostile text escaped, unknown values said as such,
//! and a list of commits never passed off as more than GitHub's word.

use landfall_api::{DeploymentSummary, ReleaseStory, Why};
use serde_json::{Value, json};

use super::{deploy, deployment, host, listed, request, story, summary, typed, why};
use crate::read::render;

fn printed(write: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
    let mut out = Vec::new();
    write(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn story_text(value: &Value) -> String {
    let story: ReleaseStory = typed(value);
    printed(|out| render::story(&story, out))
}

/// Hostile text as a field can hold it: an OSC title escape ended by BEL, a C1 CSI, a
/// carriage return, a bidi override, and a line feed to forge a line of output.
const HOSTILE: &str = "h\x1b]0;owned\x07\u{9b}2J\r\u{202e}\nFORGED";

/// [`HOSTILE`], as `safe` prints it.
const ESCAPED: &str = "h\\u{1b}]0;owned\\u{7}\\u{9b}2J\\u{d}\\u{202e}\\u{a}FORGED";

/// `text` holds [`HOSTILE`] escaped exactly `fields` times, and nothing of it raw: no
/// control, no override, and no line it forged.
fn assert_escaped(view: &str, text: &str, fields: usize) {
    for raw in ['\x1b', '\x07', '\r', '\u{9b}', '\u{202e}'] {
        assert!(!text.contains(raw), "{view}: {raw:?} in {text:?}");
    }
    assert!(
        !text
            .lines()
            .any(|line| line.trim_start().starts_with("FORGED")),
        "{view}: a forged line in:\n{text}"
    );
    assert_eq!(
        text.matches(ESCAPED).count(),
        fields,
        "{view}: hostile fields escaped, in:\n{text}"
    );
}

/// Every server string each command prints for a person, seeded with [`HOSTILE`].
#[test]
fn hostile_text_is_escaped_in_human_output() {
    let hostile = json!(HOSTILE);

    // release: a commit's summary and author, the compare link, reasons naming a check and a
    // host's words, the origin's identity and run, the next step, and why a request closed.
    // The list is cut, so GitHub's compare link prints too.
    let mut commits = listed(1, 2);
    commits["commits"][0]["summary"] = hostile.clone();
    commits["commits"][0]["author"] = hostile.clone();
    commits["compare_url"] = hostile.clone();
    let mut value = story(commits);
    value["reasons"] = json!([HOSTILE, HOSTILE]);
    value["origin"]["san"] = hostile.clone();
    value["origin"]["run_url"] = hostile.clone();
    value["next"]["detail"] = hostile.clone();
    value["requests"][0]["closed_reason"] = hostile.clone();
    assert_escaped("release", &story_text(&value), 9);

    // history: the host's reason, why going back failed, and a failed step's name and words.
    let mut value = deploy();
    value["reason"] = hostile.clone();
    value["rollback_reason"] = hostile.clone();
    value["steps"][1]["name"] = hostile.clone();
    value["steps"][1]["failure"] = hostile.clone();
    let page = typed(&json!({"items": [value], "next_cursor": null}));
    assert_escaped("history", &printed(|out| render::deploys(&page, out)), 4);

    // why: the summary, an event's text, and the next step.
    let mut value = why();
    value["summary"] = hostile.clone();
    value["events"][1]["text"] = hostile.clone();
    value["next"]["detail"] = hostile.clone();
    let why: Why = typed(&value);
    assert_escaped("why", &printed(|out| render::why(&why, out)), 3);

    // status: a hold's reason, the phase a host reported, and the rule's bumps.
    let mut value = deployment();
    value["holds"][0]["reason"] = hostile.clone();
    value["summary"]["running"]["phase"] = hostile.clone();
    value["rule"]["auto"] = hostile.clone();
    value["rule"]["approve"] = hostile.clone();
    let view = typed(&value);
    assert_escaped("status", &printed(|out| render::deployment(&view, out)), 4);

    // hosts: the phase of each deployment on it.
    let mut value = host();
    value["deployments"][0]["running"]["phase"] = hostile.clone();
    let view = typed(&value);
    assert_escaped("hosts", &printed(|out| render::host(&view, out)), 1);

    // audit: the kind, and a detail's key, its value, and a value that isn't a string.
    let mut detail = serde_json::Map::new();
    detail.insert(HOSTILE.to_owned(), hostile.clone());
    detail.insert("nested".to_owned(), json!([HOSTILE]));
    let page = typed(&json!({"items": [{
        "seq": 1, "ts": 1, "kind": HOSTILE, "deployment": null, "host": null, "detail": detail,
    }], "next_cursor": null}));
    let text = printed(|out| render::audit(&page, out));
    // The nested value is JSON first, so its controls are JSON escapes, escaped again.
    assert_escaped("audit", &text, 3);
    assert!(text.contains("nested=[\"h\\\\u001b]0;owned"), "{text}");

    // approvals: the nonce, and where /me says an approver signs.
    let mut value = request();
    value["intent"]["nonce"] = hostile.clone();
    let view = typed(&json!({"approvals": [value]}));
    let text = printed(|out| render::approvals(&view, Some(HOSTILE), out));
    assert_escaped("approvals", &text, 2);
}

#[test]
fn status_line_shows_needs_you() {
    let mut value = summary();
    value["needs_you"] = json!(true);
    let line: DeploymentSummary = typed(&value);
    let text = printed(|out| render::deployments(std::slice::from_ref(&line), out));
    assert_eq!(
        text,
        "app/prod on home-1: runs v1.2.0 (idle), latest v1.3.0 awaiting_approval, request 7, needs you\n"
    );

    let mut value = summary();
    value["running"] = Value::Null;
    value["latest"] = Value::Null;
    value["open_request"] = Value::Null;
    let line: DeploymentSummary = typed(&value);
    let text = printed(|out| render::deployments(std::slice::from_ref(&line), out));
    assert_eq!(
        text,
        "app/prod on home-1: nothing reported, no release known\n"
    );
    assert!(!text.contains("needs you"));
}

#[test]
fn story_heads_commits_as_unverified_and_says_how_many() {
    let text = story_text(&story(listed(2, 2)));
    assert!(
        text.contains(
            "commits, as GitHub lists them (not verified; authors are GitHub's attribution), since v1.2.0:"
        ),
        "{text}"
    );
    assert!(text.contains("\"change 0\" (dev)"), "{text}");
    assert!(!text.contains("the newest"), "{text}");

    let text = story_text(&story(listed(100, 250)));
    assert!(
        text.contains(
            "the newest 100 of 250; all of them at https://github.com/example/app/compare/a...b"
        ),
        "{text}"
    );
}

#[test]
fn unknown_commit_state_is_not_printed_as_none() {
    for (state, says) in [
        ("not_yet", "unknown: not fetched from GitHub yet"),
        ("unavailable", "unknown: GitHub couldn't be asked"),
        ("not_recorded", "unknown: never fetched"),
        (
            "base_not_found",
            "unknown: v1.2.0 isn't an ancestor of this release",
        ),
        ("teleporting", "unknown: a state this CLI doesn't know"),
    ] {
        let mut commits = listed(0, 0);
        commits["state"] = json!(state);
        commits["total"] = Value::Null;
        let text = story_text(&story(commits));
        assert!(text.contains(says), "{state}: {text}");
        assert!(!text.contains("no commits"), "{state}: {text}");
        assert!(!text.contains("as GitHub lists them"), "{state}: {text}");
    }

    // Listed and empty is the one case of none.
    let text = story_text(&story(listed(0, 0)));
    assert!(text.contains("no commits"), "{text}");
}

#[test]
fn too_large_prints_the_link_and_no_list() {
    let mut commits = listed(3, 3);
    commits["state"] = json!("too_large");
    commits["total"] = Value::Null;
    let text = story_text(&story(commits));
    assert!(
        text.contains(
            "commits: too large to list here: https://github.com/example/app/compare/a...b"
        ),
        "{text}"
    );
    assert!(!text.contains("change 0"), "{text}");
    assert!(!text.contains("as GitHub lists them"), "{text}");
}

#[test]
fn why_prints_summary_events_and_next() {
    let why: Why = typed(&why());
    let text = printed(|out| render::why(&why, out));
    assert_eq!(
        text,
        "deploy 12: rolled_back\n\
         v1.3.0 failed on home-1 at step \"checks\" and rolled back to the previous version\n\
         \x20 2023-11-14T22:13:20Z queued: queued for home-1\n\
         \x20 step_failed: step \"checks\" failed: \"web never healthy\"\n\
         next: request: landfall request app/prod v1.3.0\n"
    );
}

#[test]
fn unknown_status_prints_unknown() {
    let mut value = story(listed(0, 0));
    value["release"]["status"] = json!("teleporting");
    value["release"]["decision"] = json!("dithering");
    value["next"]["kind"] = json!("dance");
    let text = story_text(&value);
    assert!(
        text.starts_with("v1.3.0: unknown (decision unknown)\n"),
        "{text}"
    );
    assert!(text.contains("next: unknown: "), "{text}");

    let mut value = summary();
    value["latest"]["status"] = json!("teleporting");
    let line: DeploymentSummary = typed(&value);
    let text = printed(|out| render::deployments(std::slice::from_ref(&line), out));
    assert!(text.contains("latest v1.3.0 unknown"), "{text}");
}

/// A newer controller's fields change nothing a person reads, and its values read `unknown`.
#[test]
fn human_output_ignores_unknown_fields() {
    let mut value = story(listed(1, 1));
    value["from_the_future"] = json!({"x": "\u{9b}"});
    value["release"]["new_field"] = json!(1);
    value["commits"]["commits"][0]["signed"] = json!(true);
    value["requests"][0]["state"] = json!("escalated");
    let text = story_text(&value);
    let plain = story_text(&story(listed(1, 1)));
    assert_eq!(
        text,
        plain.replace("request 7: awaiting_approval", "request 7: unknown")
    );

    let mut value = summary();
    value["new"] = json!(1);
    value["running"]["uptime_secs"] = json!(5);
    let with_extra: DeploymentSummary = typed(&value);
    let line: DeploymentSummary = typed(&summary());
    assert_eq!(
        printed(|out| render::deployments(std::slice::from_ref(&with_extra), out)),
        printed(|out| render::deployments(std::slice::from_ref(&line), out))
    );
}
