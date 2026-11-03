//! The units, against the guide they come from.

use landfall_core::controller_url::ControllerUrl;
use landfall_core::ids::HostId;

use crate::host::unit::{UnitError, UnitInput, agent_unit, check_path, recover_unit};

const GUIDE: &str = include_str!("../../../../../docs/operations.md");

const ENVIRONMENT_FILE: &str = "EnvironmentFile=-/etc/landfall/agent.env";

/// The lines of the `ini` block after `marker` in the guide, but its comments.
fn guide_lines(marker: &str) -> Vec<&'static str> {
    let (_, after) = GUIDE.split_once(marker).unwrap();
    let (_, block) = after.split_once("```ini\n").unwrap();
    let (block, _) = block.split_once("```").unwrap();
    without_comments(block)
}

fn without_comments(text: &str) -> Vec<&str> {
    text.lines().filter(|line| !line.starts_with('#')).collect()
}

fn controller() -> ControllerUrl {
    ControllerUrl::parse("https://controller.example", false).unwrap()
}

fn host() -> HostId {
    "home-1".parse().unwrap()
}

fn rendered(allow_insecure: bool, compose_dirs: &[&str]) -> String {
    agent_unit(&UnitInput {
        controller: &controller(),
        host: &host(),
        allow_insecure,
        compose_dirs,
    })
}

/// One `key=value` line of a unit, as a whole line.
fn has_line(unit: &str, line: &str) -> bool {
    unit.lines().any(|candidate| candidate == line)
}

/// Line for line, so that nothing can be added to undo the guide's hardening, or moved to where
/// systemd ignores it. The one line the guide doesn't have is the agent's environment file.
#[test]
fn unit_matches_the_operations_guide() {
    let unit = rendered(false, &["/srv/compose/app"]);
    let mut lines = without_comments(&unit);
    let extra = lines
        .iter()
        .position(|line| *line == ENVIRONMENT_FILE)
        .unwrap();
    assert_eq!(lines[extra - 1], "SupplementaryGroups=docker", "{unit}");
    lines.remove(extra);
    assert_eq!(
        lines,
        guide_lines("`/etc/systemd/system/landfall-agent.service`")
    );
}

#[test]
fn recover_unit_matches_the_operations_guide() {
    let unit = recover_unit(&["/srv/compose/app"]);
    assert_eq!(
        without_comments(&unit),
        guide_lines("`/etc/systemd/system/landfall-agent-recover@.service`")
    );
}

#[test]
fn the_agent_reads_its_optional_environment_file() {
    assert!(has_line(
        &rendered(false, &["/srv/compose/app"]),
        ENVIRONMENT_FILE
    ));
}

#[test]
fn unsafe_path_is_refused() {
    for path in [
        "",
        "relative/path",
        "./app",
        "/srv/with space",
        "/srv/with\ttab",
        "/srv/with\nnewline",
        "/srv/nbsp\u{a0}here",
        "/srv/it's",
        "/srv/\"quoted\"",
        "/srv/100%",
        "/srv/$HOME",
        "/srv/back\\slash",
        "/srv/bell\u{7}",
        "/srv/del\u{7f}",
    ] {
        assert_eq!(
            check_path(path),
            Err(UnitError::UnsafePath(path.to_owned())),
            "{path:?}"
        );
    }
    for path in ["/srv/compose/app", "/srv/compose/app-1_b.c", "/srv/héllo"] {
        assert_eq!(check_path(path), Ok(()), "{path:?}");
    }
}

#[test]
fn paths_with_several_deployments_are_all_read_write() {
    let dirs = ["/srv/compose/b", "/srv/compose/a", "/srv/compose/b"];
    let want = "ReadWritePaths=/srv/compose/a /srv/compose/b";
    assert!(has_line(&rendered(false, &dirs), want));
    assert!(has_line(&recover_unit(&dirs), want));
}

#[test]
fn insecure_flag_reaches_exec_start() {
    let exec_start = |unit: &str| {
        unit.lines()
            .find(|line| line.starts_with("ExecStart="))
            .unwrap()
            .to_owned()
    };
    let unit = rendered(true, &["/srv/compose/app"]);
    assert!(
        exec_start(&unit).ends_with(" --allow-insecure-controller"),
        "{unit}"
    );
    let unit = rendered(false, &["/srv/compose/app"]);
    assert!(!unit.contains("--allow-insecure-controller"), "{unit}");
}

/// The URL parser takes `$` and quotes in a host name, and a unit would read them.
#[test]
fn a_controller_name_cannot_say_anything_to_systemd() {
    for (text, want) in [
        (
            "https://a$b.example",
            r#"--controller "https://a$$b.example" --host"#,
        ),
        (
            "https://a'b.example",
            r#"--controller "https://a'b.example" --host"#,
        ),
        (
            "https://a\"b.example",
            r#"--controller "https://a\"b.example" --host"#,
        ),
        (
            "https://controller.example:8443",
            "--controller https://controller.example:8443 --host",
        ),
    ] {
        let controller = ControllerUrl::parse(text, false).unwrap();
        let unit = agent_unit(&UnitInput {
            controller: &controller,
            host: &host(),
            allow_insecure: false,
            compose_dirs: &["/srv/compose/app"],
        });
        assert!(unit.contains(want), "{text}: {unit}");
    }
}
