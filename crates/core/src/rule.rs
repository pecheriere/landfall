//! Rule decisions: what to do with a candidate version (spec 6.2).

use std::cmp::Ordering;

use semver::Version;

use crate::config::{Level, Rule};

/// What a rule says about a candidate version.
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

impl Decision {
    /// Whether a human approval is required before deploying.
    #[must_use]
    pub fn needs_approval(&self) -> bool {
        matches!(self, Self::NeedsApproval | Self::Manual)
    }
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
    match candidate.cmp(running) {
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

/// The smallest level that permits moving from `running` up to `candidate`.
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

    fn rule(auto: Option<&str>, approve: Option<&str>, prereleases: bool) -> Rule {
        let level = |key: &str, value: Option<&str>| {
            value.map_or_else(String::new, |level| format!("{key} = \"{level}\"\n"))
        };
        let toml = format!(
            "approvers = [\"operator\"]\nprereleases = {prereleases}\n{}{}",
            level("auto", auto),
            level("approve", approve),
        );
        toml::from_str(&toml).unwrap()
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
        let any = rule(Some("any"), Some("any"), false);
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
    fn only_approval_and_manual_need_approval() {
        assert!(!Decision::Auto.needs_approval());
        assert!(Decision::NeedsApproval.needs_approval());
        assert!(Decision::Manual.needs_approval());
        assert!(!Decision::Refused(Refusal::Prerelease).needs_approval());
    }
}
