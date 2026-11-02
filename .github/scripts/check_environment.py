"""Fail unless the `release` environment really holds a release back for a person.

GitHub silently creates an environment a job names and doesn't find, with no protection at all, so
the workflow reads this one first and the job that publishes needs this to pass. It wants one
`required_reviewers` rule, with someone in it, who is able to approve (`prevent_self_review` on
stops a project's only maintainer from doing so), and a deployment branch policy, so that only a
tag can use the environment. A setting it can't read counts as a fault. It can't see which refs
that policy allows, which a different endpoint holds: a fork's owner sets those by hand.

This runs under `python3 -I`, which keeps a script's directory off the import path, so it stands
alone. `test_check_environment.py` keeps what it shares with `assemble_release.py` equal.

Usage: gh api repos/OWNER/NAME/environments/release | check_environment.py
"""

import json
import sys
from typing import Any

ENVIRONMENT = "release"
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
        if not isinstance(people, list) or not people:
            found.append("its required_reviewers rule has no reviewers")
        if rule.get("prevent_self_review") is not False:
            found.append("prevent_self_review is not off, so a sole maintainer could never approve")
    return found


def faults(answer: object) -> list[str]:
    """Return everything wrong with GitHub's answer for the environment."""
    if not isinstance(answer, dict):
        return ["GitHub's answer is not an object"]
    found = []
    if answer.get("name") != ENVIRONMENT:
        found.append(f"GitHub's answer is for {shown(answer.get('name'))}, not {ENVIRONMENT}")
    rules = answer.get("protection_rules")
    if isinstance(rules, list):
        found.extend(reviewer_faults(rules))
    else:
        found.append("it has no list of protection_rules, so no required_reviewers rule to read")
    if not isinstance(answer.get("deployment_branch_policy"), dict):
        found.append("deployment_branch_policy is not set, so any ref could use the environment")
    return found


def read_answer(raw: bytes) -> object:
    """Parse GitHub's answer, refusing what a stricter reader wouldn't take."""
    if len(raw) > MAX_ANSWER_BYTES:
        msg = f"it is more than {MAX_ANSWER_BYTES} bytes"
        raise ValueError(msg)
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=refuse_repeats,
        parse_constant=refuse_constant,
    )


def main() -> int:
    """Read the answer on stdin. Print each fault as a GitHub annotation, and return 1 for any."""
    raw = sys.stdin.buffer.read(MAX_ANSWER_BYTES + 1)
    try:
        found = faults(read_answer(raw))
    except (ValueError, RecursionError) as error:
        found = [f"GitHub's answer could not be read: {shown(error)}"]
    for fault in found:
        print(f"::error title=Release environment::{fault}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
