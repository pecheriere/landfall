//! Rule decisions: what to do with a candidate version (spec 6.2).

use std::cmp::Ordering;

use semver::Version;

use crate::config::{Level, Rule};

/// What a rule says about a candidate version. Callers match on it
/// exhaustively: there is deliberately no boolean shortcut, so a refused
/// candidate can never fall through to a deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Deploy without a human.
    Auto,
    /// Deploy once an approver agrees.
    NeedsApproval,
    /// Deploy only on an explicit, host-verified operator request.
    Manual,
    /// Never deploy this candidate.
    Refused(Refusal),
}

/// Why a candidate is refused outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A pre-release, and the rule does not opt in to pre-releases.
    Prerelease,
    /// The candidate is the version already running.
    AlreadyRunning,
}

/// Decide what to do with `candidate` given the `running` version, if any.
#[must_use]
pub fn decide(rule: &Rule, running: Option<&Version>, candidate: &Version) -> Decision {
    if !candidate.pre.is_empty() && !rule.prereleases() {
        return Decision::Refused(Refusal::Prerelease);
    }
    let Some(running) = running else {
        return Decision::Manual;
    };
    match candidate.cmp_precedence(running) {
        Ordering::Equal => Decision::Refused(Refusal::AlreadyRunning),
        Ordering::Less => Decision::Manual,
        Ordering::Greater => {
            let part = jump(running, candidate);
            if rule.auto().is_some_and(|level| level >= part) {
                Decision::Auto
            } else if rule.approve().is_some_and(|level| level >= part) {
                Decision::NeedsApproval
            } else {
                Decision::Manual
            }
        }
    }
}

/// Why [`decide`] said `decision` of `candidate` over `running`, in the words the controller
/// records and shows: the one place they are written.
#[must_use]
pub fn reason(decision: Decision, running: Option<&Version>, candidate: &Version) -> &'static str {
    match decision {
        Decision::Auto => "a higher version within the rule's automatic level",
        Decision::NeedsApproval => "a higher version that needs an approver",
        Decision::Manual => match running {
            None => "nothing has been deployed yet: a first deploy needs an operator",
            Some(running) if candidate < running => {
                "lower than the running version: a downgrade needs an operator"
            }
            Some(_) => "beyond the rule's levels: it needs an operator",
        },
        Decision::Refused(refusal) => refusal_reason(refusal),
    }
}

/// Why a candidate is refused outright, in the words the controller records and shows.
#[must_use]
pub fn refusal_reason(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Prerelease => "a pre-release, and the rule does not opt in",
        Refusal::AlreadyRunning => "already running",
    }
}

/// The smallest level that permits moving from `running` up to `candidate`.
/// Pre-release and build fields are ignored: only major, minor and patch count.
fn jump(running: &Version, candidate: &Version) -> Level {
    if candidate.major != running.major {
        Level::Any
    } else if candidate.minor != running.minor {
        Level::Minor
    } else {
        Level::Patch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    /// The rule of the only deployment in a minimal valid configuration.
    fn rule(auto: Option<&str>, approve: Option<&str>, prereleases: bool) -> Rule {
        let level = |key: &str, value: Option<&str>| {
            value.map_or_else(String::new, |level| format!("{key} = \"{level}\", "))
        };
        let text = format!(
            r#"
[signers]
maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn"

[approval]
rp_id = "landfall.example"
origin = "https://landfall.example"

[approvers]
operator = {{ credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }}

[[deployment]]
id = "app/prod"
repo = {{ name = "example/app", id = 1234, owner_id = 5678 }}
host = "home-1"
compose = {{ dir = "/srv/compose/app", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }}
rule = {{ {}{}prereleases = {prereleases}, approvers = ["operator"] }}
checks = ["container-healthy"]
"#,
            level("auto", auto),
            level("approve", approve),
        );
        let config = config::parse_for_tests(text.as_bytes(), |_| Ok(())).unwrap();
        config.deployments()[0].rule().clone()
    }

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    fn decide_str(rule: &Rule, running: Option<&str>, candidate: &str) -> Decision {
        decide(rule, running.map(v).as_ref(), &v(candidate))
    }

    #[test]
    fn higher_versions_follow_the_levels() {
        let layered = rule(Some("patch"), Some("minor"), false);
        assert_eq!(decide_str(&layered, Some("1.2.3"), "1.2.4"), Decision::Auto);
        assert_eq!(
            decide_str(&layered, Some("1.2.3"), "1.3.0"),
            Decision::NeedsApproval
        );
        assert_eq!(
            decide_str(&layered, Some("1.2.3"), "2.0.0"),
            Decision::Manual
        );

        let any = rule(Some("any"), None, false);
        assert_eq!(decide_str(&any, Some("1.2.3"), "2.0.0"), Decision::Auto);

        let neither = rule(None, None, false);
        assert_eq!(
            decide_str(&neither, Some("1.2.3"), "1.2.4"),
            Decision::Manual
        );
    }

    #[test]
    fn equal_is_refused_and_lower_is_manual() {
        let any = rule(Some("any"), None, false);
        assert_eq!(
            decide_str(&any, Some("1.2.3"), "1.2.3"),
            Decision::Refused(Refusal::AlreadyRunning)
        );
        assert_eq!(decide_str(&any, Some("1.2.3"), "1.2.2"), Decision::Manual);
    }

    #[test]
    fn first_deploy_is_manual() {
        let any = rule(Some("any"), None, false);
        assert_eq!(decide_str(&any, None, "1.0.0"), Decision::Manual);
    }

    #[test]
    fn prerelease_is_refused_unless_opted_in() {
        let closed = rule(Some("any"), None, false);
        assert_eq!(
            decide_str(&closed, Some("1.2.3"), "1.3.0-rc.1"),
            Decision::Refused(Refusal::Prerelease)
        );
        let open = rule(Some("any"), None, true);
        assert_eq!(
            decide_str(&open, Some("1.2.3"), "1.3.0-rc.1"),
            Decision::Auto
        );

        let patch = rule(Some("patch"), None, true);
        assert_eq!(
            decide_str(&patch, Some("1.3.0-rc.1"), "1.3.0"),
            Decision::Auto
        );
    }

    #[test]
    fn build_metadata_does_not_make_versions_differ() {
        let any = rule(Some("any"), None, false);
        assert_eq!(
            decide_str(&any, Some("1.2.3+a"), "1.2.3+b"),
            Decision::Refused(Refusal::AlreadyRunning)
        );
        assert_eq!(
            decide_str(&any, Some("1.2.3+b"), "1.2.3+a"),
            Decision::Refused(Refusal::AlreadyRunning)
        );
    }

    #[test]
    fn level_boundaries_are_inclusive() {
        let minor = rule(Some("minor"), None, false);
        assert_eq!(decide_str(&minor, Some("1.2.3"), "1.3.0"), Decision::Auto);
        let approve_only = rule(None, Some("patch"), false);
        assert_eq!(
            decide_str(&approve_only, Some("1.2.3"), "1.2.4"),
            Decision::NeedsApproval
        );
    }

    #[test]
    fn first_deploy_of_a_prerelease_is_refused_unless_opted_in() {
        let closed = rule(Some("any"), None, false);
        assert_eq!(
            decide_str(&closed, None, "1.0.0-rc.1"),
            Decision::Refused(Refusal::Prerelease)
        );
    }

    #[test]
    fn a_prerelease_of_the_running_version_is_a_downgrade() {
        // 1.3.0-rc.1 precedes 1.3.0, so it is manual, never automatic.
        let open = rule(Some("any"), None, true);
        assert_eq!(
            decide_str(&open, Some("1.3.0"), "1.3.0-rc.1"),
            Decision::Manual
        );
    }

    #[test]
    fn each_decision_has_the_words_the_controller_records() {
        let v = |text: &str| Version::parse(text).unwrap();
        let (low, mid, high) = (v("1.2.0"), v("1.3.0"), v("1.4.0"));
        let rows = [
            (
                Decision::Auto,
                Some(&low),
                "a higher version within the rule's automatic level",
            ),
            (
                Decision::NeedsApproval,
                Some(&low),
                "a higher version that needs an approver",
            ),
            (
                Decision::Manual,
                None,
                "nothing has been deployed yet: a first deploy needs an operator",
            ),
            (
                Decision::Manual,
                Some(&high),
                "lower than the running version: a downgrade needs an operator",
            ),
            (
                Decision::Manual,
                Some(&low),
                "beyond the rule's levels: it needs an operator",
            ),
            (
                Decision::Refused(Refusal::Prerelease),
                None,
                "a pre-release, and the rule does not opt in",
            ),
            (
                Decision::Refused(Refusal::AlreadyRunning),
                Some(&mid),
                "already running",
            ),
        ];
        for (decision, running, want) in rows {
            assert_eq!(reason(decision, running, &mid), want, "{decision:?}");
        }
    }
}
