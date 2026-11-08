//! What each view prints for a person: hostile text escaped, unknown values said as such,
//! and a list of commits never passed off as more than GitHub's word.

use landfall_api::{DeploymentSummary, ReleaseStory, Why};
use serde_json::{Value, json};

use super::{deploy, deployment, host, listed, story, summary, typed, why};
use crate::read::render;

fn printed(write: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
    let mut out = Vec::new();
    write(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn story_text(value: Value) -> String {
    let story: ReleaseStory = typed(value);
    printed(|out| render::story(&story, out))
}

fn assert_escaped(text: &str) {
    for raw in ['\x1b', '\x07', '\r', '\u{9b}', '\u{202e}'] {
        assert!(!text.contains(raw), "{raw:?} in {text:?}");
    }
}

#[test]
fn hostile_text_is_escaped_in_human_output() {
    // A release story: a commit summary, its author, a check name and a host's reason.
    let mut commits = listed(1, 1);
    commits["commits"][0]["summary"] = json!("fix\x1b]0;owned\x07");
    commits["commits"][0]["author"] = json!("dev\rroot");
    let mut value = story(commits);
    value["reasons"] = json!([
        "check \"web\u{9b}2J\" failed",
        "home-1 said \"\u{202e}gpj.exe\"",
    ]);
    let text = story_text(value);
    assert_escaped(&text);
    for escaped in [
        "fix\\u{1b}]0;owned\\u{7}",
        "dev\\u{d}root",
        "web\\u{9b}2J",
        "\\u{202e}gpj.exe",
    ] {
        assert!(text.contains(escaped), "{escaped} missing from:\n{text}");
    }

    // A deploy's host reason and failed step, in history.
    let mut value = deploy();
    value["reason"] = json!("\u{202e}bad");
    value["steps"][1]["name"] = json!("checks\u{9b}2J");
    value["steps"][1]["failure"] = json!("web\x1b[2K");
    let page = typed(json!({"items": [value], "next_cursor": null}));
    let text = printed(|out| render::deploys(&page, out));
    assert_escaped(&text);
    for escaped in ["\\u{202e}bad", "checks\\u{9b}2J", "web\\u{1b}[2K"] {
        assert!(text.contains(escaped), "{escaped} missing from:\n{text}");
    }

    // Why: the summary and each event's text, a check name among them.
    let mut value = why();
    value["summary"] = json!("failed at \"checks\x1b]0;x\x07\"");
    value["events"][1]["text"] = json!("check \"web\u{9b}2J\" failed\r");
    let why: Why = typed(value);
    let text = printed(|out| render::why(&why, out));
    assert_escaped(&text);
    assert!(text.contains("checks\\u{1b}]0;x\\u{7}"), "{text}");
    assert!(
        text.contains("check \"web\\u{9b}2J\" failed\\u{d}"),
        "{text}"
    );

    // A hold's reason, in a deployment's status.
    let mut value = deployment();
    value["holds"][0]["reason"] = json!("host said \u{202e}no\r");
    let view = typed(value);
    let text = printed(|out| render::deployment(&view, out));
    assert_escaped(&text);
    assert!(text.contains("host said \\u{202e}no\\u{d}"), "{text}");

    // A host's phase, in the hosts list.
    let mut value = host();
    value["deployments"][0]["running"]["phase"] = json!("idle\x1b[31m");
    let view = typed(value);
    let text = printed(|out| render::host(&view, out));
    assert_escaped(&text);
    assert!(text.contains("idle\\u{1b}[31m"), "{text}");

    // An audit row's detail.
    let page = typed(json!({"items": [{
        "seq": 1, "ts": 1, "kind": "deploy_refused\u{9b}", "deployment": null, "host": null,
        "detail": {"reason": "\"\u{202e}x\r\""},
    }], "next_cursor": null}));
    let text = printed(|out| render::audit(&page, out));
    assert_escaped(&text);
    assert!(text.contains("deploy_refused\\u{9b}"), "{text}");
    assert!(text.contains("\\u{202e}x\\u{d}"), "{text}");
}

#[test]
fn status_line_shows_needs_you() {
    let mut value = summary();
    value["needs_you"] = json!(true);
    let line: DeploymentSummary = typed(value);
    let text = printed(|out| render::deployments(std::slice::from_ref(&line), out));
    assert_eq!(
        text,
        "app/prod on home-1: runs v1.2.0 (idle), latest v1.3.0 awaiting_approval, request 7, needs you\n"
    );

    let mut value = summary();
    value["running"] = Value::Null;
    value["latest"] = Value::Null;
    value["open_request"] = Value::Null;
    let line: DeploymentSummary = typed(value);
    let text = printed(|out| render::deployments(std::slice::from_ref(&line), out));
    assert_eq!(
        text,
        "app/prod on home-1: nothing reported, no release known\n"
    );
    assert!(!text.contains("needs you"));
}

#[test]
fn story_heads_commits_as_unverified_and_says_how_many() {
    let text = story_text(story(listed(2, 2)));
    assert!(
        text.contains(
            "commits, as GitHub lists them (not verified; authors are GitHub's attribution), since v1.2.0:"
        ),
        "{text}"
    );
    assert!(text.contains("\"change 0\" (dev)"), "{text}");
    assert!(!text.contains("the newest"), "{text}");

    let text = story_text(story(listed(100, 250)));
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
        let text = story_text(story(commits));
        assert!(text.contains(says), "{state}: {text}");
        assert!(!text.contains("no commits"), "{state}: {text}");
        assert!(!text.contains("as GitHub lists them"), "{state}: {text}");
    }

    // Listed and empty is the one case of none.
    let text = story_text(story(listed(0, 0)));
    assert!(text.contains("no commits"), "{text}");
}

#[test]
fn too_large_prints_the_link_and_no_list() {
    let mut commits = listed(3, 3);
    commits["state"] = json!("too_large");
    commits["total"] = Value::Null;
    let text = story_text(story(commits));
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
    let why: Why = typed(why());
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
    let text = story_text(value);
    assert!(
        text.starts_with("v1.3.0: unknown (decision unknown)\n"),
        "{text}"
    );
    assert!(text.contains("next: unknown: "), "{text}");

    let mut value = summary();
    value["latest"]["status"] = json!("teleporting");
    let line: DeploymentSummary = typed(value);
    let text = printed(|out| render::deployments(std::slice::from_ref(&line), out));
    assert!(text.contains("latest v1.3.0 unknown"), "{text}");
}
