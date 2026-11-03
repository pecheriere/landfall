"""Fail unless the `release` environment really holds a release back for a person.

GitHub silently creates an environment a job names and doesn't find, with no protection at all, so
the workflow reads this one first and the job that publishes needs this to pass. It takes GitHub's
two answers, for the environment and for its `deployment-branch-policies`, and wants:

- a `required_reviewers` rule, with someone in it, and `prevent_self_review` off, which on would
  stop a project's only maintainer from approving;
- `can_admins_bypass` off, as an admin could otherwise publish with no reviewer;
- `custom_branch_policies` on and `protected_branches` off, with one policy, a tag policy for
  `v[0-9]*`, so that a tag can use the environment and nothing else can. A manual run shows it here
  if the setting would refuse the tag at `publish`, which would otherwise cost a version number.

A setting it can't read counts as a fault. This reads the settings and can't show GitHub enforcing
them, which only a real tag does. `CONTRIBUTING.md` tells the owner to make exactly these settings,
so a change here changes it there.

This runs under `python3 -I`, which keeps a script's directory off the import path, so it stands
alone. `test_check_environment.py` keeps what it shares with `assemble_release.py` equal.

Usage: check_environment.py ENVIRONMENT_JSON POLICIES_JSON
"""

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ENVIRONMENT = "release"
TAG_POLICY = "v[0-9]*"
MAX_ANSWER_BYTES = 1024 * 1024
MAX_SHOWN = 200


def shown(value: object) -> str:
    """Return a value safe to print on one line of a GitHub annotation, and not too long."""
    text = ascii(str(value))[1:-1]
    return text if len(text) <= MAX_SHOWN else f"{text[:MAX_SHOWN]}..."


def refuse_repeats(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object, refusing a repeated key: two readers can take different ones."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            msg = f"repeated key {shown(key)}"
            raise ValueError(msg)
        result[key] = value
    return result


def refuse_constant(name: str) -> None:
    """Refuse NaN and Infinity, which aren't JSON."""
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def names_someone(reviewer: object) -> bool:
    """Say if an entry of a reviewers list holds a person or a team."""
    return isinstance(reviewer, dict) and isinstance(reviewer.get("reviewer"), dict)


def reviewer_faults(rules: list[object]) -> list[str]:
    """Say what's wrong with the environment's required reviewers."""
    reviewers = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if not reviewers:
        return ["it has no required_reviewers rule, so nobody is asked before publishing"]
    found = []
    for rule in reviewers:
        people = rule.get("reviewers")
        if not isinstance(people, list) or not people or not all(map(names_someone, people)):
            found.append("its required_reviewers rule has no reviewers, or one with nobody in it")
        if rule.get("prevent_self_review") is not False:
            found.append("prevent_self_review is not off, so a sole maintainer could never approve")
    return found


def branch_policy_fault(policy: object) -> str | None:
    """Say what's wrong with the environment's summary of its deployment policy, if anything."""
    if not isinstance(policy, dict):
        return "deployment_branch_policy is not set, so any ref could use the environment"
    if policy.get("custom_branch_policies") is True and policy.get("protected_branches") is False:
        return None
    return (
        "deployment_branch_policy needs custom_branch_policies on and protected_branches off, for "
        f"a tag to be able to use the environment, and has {shown(policy)}"
    )


def environment_faults(answer: object) -> list[str]:
    """Return everything wrong with GitHub's answer for the environment."""
    if not isinstance(answer, dict):
        return ["GitHub's answer for the environment is not an object"]
    found = []
    if answer.get("name") != ENVIRONMENT:
        found.append(f"GitHub's answer is for {shown(answer.get('name'))}, not {ENVIRONMENT}")
    rules = answer.get("protection_rules")
    if isinstance(rules, list):
        found.extend(reviewer_faults(rules))
    else:
        found.append("it has no list of protection_rules, so no required_reviewers rule to read")
    if answer.get("can_admins_bypass") is not False:
        found.append("can_admins_bypass is not off, so an admin could publish with no reviewer")
    fault = branch_policy_fault(answer.get("deployment_branch_policy"))
    if fault is not None:
        found.append(fault)
    return found


def policy_faults(answer: object) -> list[str]:
    """Want the policy list to be one tag policy for release tags, and nothing else."""
    wanted = {"name": TAG_POLICY, "type": "tag"}
    if isinstance(answer, dict) and answer.get("total_count") == 1:
        policies = answer.get("branch_policies")
        if (
            isinstance(policies, list)
            and len(policies) == 1
            and isinstance(policies[0], dict)
            and {key: policies[0].get(key) for key in wanted} == wanted
        ):
            return []
    fault = f"must be one tag policy for {TAG_POLICY}, and is {shown(answer)}"
    return [f"deployment-branch-policies {fault}"]


def faults(environment: object, policies: object) -> list[str]:
    """Return everything wrong with GitHub's two answers."""
    return environment_faults(environment) + policy_faults(policies)


def read_answer(path: Path) -> object:
    """Parse one of GitHub's answers, refusing what a stricter reader wouldn't take."""
    with path.open("rb") as file:
        raw = file.read(MAX_ANSWER_BYTES + 1)
    if len(raw) > MAX_ANSWER_BYTES:
        msg = f"it is more than {MAX_ANSWER_BYTES} bytes"
        raise ValueError(msg)
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=refuse_repeats,
        parse_constant=refuse_constant,
    )


def checked(path: Path, what: str, check: Callable[[object], list[str]]) -> list[str]:
    """Return what's wrong with one answer, of which being unreadable is one thing."""
    try:
        answer = read_answer(path)
    except (OSError, ValueError, RecursionError) as error:
        return [f"GitHub's answer for {what} could not be read: {shown(error)}"]
    return check(answer)


def main(argv: list[str] | None = None) -> int:
    """Read the two answers. Print each fault as a GitHub annotation, and return 1 for any."""
    parser = argparse.ArgumentParser(description="Check the release environment's settings.")
    parser.add_argument("environment", type=Path, help="GitHub's answer for the environment")
    parser.add_argument("policies", type=Path, help="its answer for deployment-branch-policies")
    args = parser.parse_args(argv)
    found = [
        *checked(args.environment, "the environment", environment_faults),
        *checked(args.policies, "deployment-branch-policies", policy_faults),
    ]
    for fault in found:
        print(f"::error title=Release environment::{fault}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
