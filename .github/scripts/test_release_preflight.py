"""Unit tests for release_preflight.py, with real `ssh-keygen` signatures and a fake GitHub."""

import contextlib
import io
import os
import subprocess
import unittest
from unittest import mock

import release_preflight
from release_preflight import RefusedError
from release_preflight_support import (
    LINE_SEPARATOR,
    OTHER_SHA,
    REPO,
    REPOSITORY_ROOT,
    SHA,
    TAG,
    TAG_OBJECT_SHA,
    FakeGitHub,
    Keys,
    RepositoryLayout,
    annotated_ref,
    fake_command,
    payload_for,
    tag_answer,
)

COMMAND_TIMEOUT_SECONDS = 60


class VersionTests(RepositoryLayout):
    """The tag is the workspace's version."""

    def test_tag_must_match_workspace_version(self) -> None:
        """A tag that isn't `v` plus the version stops before GitHub is asked anything."""
        for tag in ("v1.2.4", "1.2.3", "v1.2.3-rc.1", "V1.2.3", "v1.2.3\n", "vv1.2.3"):
            with self.subTest(tag=tag):
                github = self.signed(self.keys.first)
                with self.assertRaisesRegex(RefusedError, "version"):
                    self.preflight(github, tag=tag)
                self.assertEqual(github.calls, [])

    def test_a_prerelease_tag_matches_a_prerelease_version(self) -> None:
        """The first tag is meant to be a release candidate."""
        self.write_version("1.2.3-rc.1")
        tag = "v1.2.3-rc.1"
        payload = payload_for(tag=tag)
        answer = tag_answer(payload, self.keys.sign(self.keys.first, payload), tag=tag)
        github = FakeGitHub(annotated_ref(), answer)
        ref = {"ref": f"refs/tags/{tag}", "object": {"sha": TAG_OBJECT_SHA, "type": "tag"}}
        github.answers[f"repos/{REPO}/git/ref/tags/{tag}"] = ref
        self.preflight(github, tag=tag)

    def test_an_unusable_cargo_toml_is_refused(self) -> None:
        """No version, or one that couldn't be a release, or no file, is a refusal."""
        for text in (
            "not toml = = =",
            "[workspace]\n",
            "[workspace.package]\nversion = 1\n",
            '[workspace.package]\nversion = "../1.2.3"\n',
        ):
            with self.subTest(text=text):
                (self.root / "Cargo.toml").write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(RefusedError, "Cargo.toml"):
                    self.preflight(self.signed(self.keys.first))
        (self.root / "Cargo.toml").unlink()
        with self.assertRaisesRegex(RefusedError, "Cargo.toml"):
            self.preflight(self.signed(self.keys.first))

    def test_a_bad_commit_or_repository_stops_before_github(self) -> None:
        """Each would become part of a path or a comparison, so each is checked first."""
        github = self.signed(self.keys.first)
        for sha in ("", "A" * 40, "a" * 39, "a" * 64, f"{'a' * 40}\n", "HEAD"):
            with self.subTest(sha=sha), self.assertRaisesRegex(RefusedError, "commit"):
                release_preflight.preflight(TAG, sha, REPO, self.root, github)
        for repo in ("", "owner", "owner/../x", "a/b/c", "--repo/x", "owner/x y"):
            with self.subTest(repo=repo), self.assertRaisesRegex(RefusedError, "repository"):
                release_preflight.preflight(TAG, SHA, repo, self.root, github)
        self.assertEqual(github.calls, [])


class TagSignatureTests(RepositoryLayout):
    """The tag object as GitHub answers it, proved with `ssh-keygen`."""

    def trust_both(self) -> None:
        """Trust the first and second keys, as during a rotation."""
        self.write_signers(
            "# the old key",
            Keys.public(self.keys.first),
            Keys.public(self.keys.second),
        )

    def test_tag_signature_table(self) -> None:
        """Signed by a listed key passes, and nothing else does."""
        keys = self.keys
        payload = payload_for()
        unsigned = FakeGitHub(annotated_ref(), tag_answer(payload, None))
        lightweight = FakeGitHub(
            {"ref": f"refs/tags/{TAG}", "object": {"sha": SHA, "type": "commit"}},
            tag_answer(payload, keys.sign(keys.first, payload)),
        )
        cases: dict[str, tuple[FakeGitHub, str | None]] = {
            "signed by a listed key": (self.signed(keys.first), None),
            "signed by the second of two listed keys": (self.signed(keys.second), None),
            "signed by an unlisted key": (self.signed(keys.stranger), "signature"),
            "unsigned": (unsigned, "not signed"),
            "lightweight": (lightweight, "lightweight"),
            "naming another tag": (
                self.signed(keys.first, payload_for(tag="v1.2.2")),
                "v1.2.2",
            ),
            "naming another commit": (
                self.signed(keys.first, payload_for(sha=OTHER_SHA)),
                OTHER_SHA,
            ),
        }
        self.trust_both()
        for name, (github, expected) in cases.items():
            with self.subTest(name=name):
                if expected is None:
                    self.preflight(github)
                else:
                    with self.assertRaisesRegex(RefusedError, expected):
                        self.preflight(github)

    def test_a_tag_made_by_git_passes(self) -> None:
        """The fixture `git tag -s` wrote for `landfall-core`, cut where GitHub cuts it."""
        fixtures = REPOSITORY_ROOT / "crates" / "core" / "tests" / "fixtures" / "tag"
        raw = (fixtures / "valid.tag").read_text(encoding="utf-8")
        payload, armor, rest = raw.partition("-----BEGIN SSH SIGNATURE-----")
        commit = payload.split("\n")[0].removeprefix("object ")
        self.write_signers(" ".join((fixtures / "signer.pub").read_text("utf-8").split()[:2]))
        answer = tag_answer(payload.encode(), armor + rest, sha=commit)
        self.preflight(FakeGitHub(annotated_ref(), answer), sha=commit)

    def test_github_saying_verified_is_not_believed(self) -> None:
        """An unlisted key that GitHub knows and shows as verified is still unlisted."""
        github = self.signed(self.keys.stranger)
        tag_object = github.answers[f"repos/{REPO}/git/tags/{TAG_OBJECT_SHA}"]
        tag_object["verification"]["verified"] = True
        tag_object["verification"]["reason"] = "valid"
        with self.assertRaisesRegex(RefusedError, "signature"):
            self.preflight(github)

    def test_a_signature_for_other_bytes_is_refused(self) -> None:
        """A listed key's real signature, moved onto a changed message."""
        payload = payload_for()
        signature = self.keys.sign(self.keys.first, payload)
        changed = payload + b"and more\n"
        github = FakeGitHub(annotated_ref(), tag_answer(changed, signature))
        with self.assertRaisesRegex(RefusedError, "signature"):
            self.preflight(github)

    def test_a_signature_in_another_namespace_is_refused(self) -> None:
        """A key's signature on a file isn't its signature on a tag."""
        payload = payload_for()
        signature = self.keys.sign(self.keys.first, payload, namespace="file")
        github = FakeGitHub(annotated_ref(), tag_answer(payload, signature))
        with self.assertRaisesRegex(RefusedError, "signature"):
            self.preflight(github)

    def test_a_signed_tag_of_something_other_than_a_commit_is_refused(self) -> None:
        """A tag of a tag or of a tree isn't a release of this commit."""
        for kind in ("tag", "tree"):
            with self.subTest(kind=kind):
                github = self.signed(self.keys.first, payload_for(kind=kind))
                with self.assertRaisesRegex(RefusedError, kind):
                    self.preflight(github)

    def test_the_payload_is_what_counts_and_not_the_message(self) -> None:
        """The right headers in the message, under wrong real ones, don't help."""
        fake = (
            f"object {OTHER_SHA}\ntype commit\ntag v1.2.2\n"
            "tagger Example <example@example.invalid> 1767225600 +0000\n\n"
            f"object {SHA}\ntype commit\ntag {TAG}\n"
        ).encode()
        with self.assertRaisesRegex(RefusedError, "v1.2.2"):
            self.preflight(self.signed(self.keys.first, fake))

    def test_repeated_or_missing_headers_are_refused(self) -> None:
        """A signed object two readers could read two ways isn't a proof of either."""
        for name, payload in {
            "a second object": (f"object {OTHER_SHA}\n{payload_for().decode()}").encode(),
            "a second tag": (f"tag v9.9.9\n{payload_for().decode()}").encode(),
            "no object": b"type commit\ntag v1.2.3\n\nrelease\n",
            "no type": f"object {SHA}\ntag v1.2.3\n\nrelease\n".encode(),
            "no tag": f"object {SHA}\ntype commit\n\nrelease\n".encode(),
            "a header with no value": f"object {SHA}\ntype commit\ntag v1.2.3\nx\n\n".encode(),
            "nothing": b"",
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                self.preflight(self.signed(self.keys.first, payload))

    def test_a_tag_object_answer_disagreeing_with_its_payload_is_refused(self) -> None:
        """The signed bytes decide, but an answer at odds with them is not a GitHub to trust."""
        for name, fields in {
            "another tag": {"tag": "v9.9.9"},
            "another object": {"sha": OTHER_SHA},
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                self.preflight(self.signed(self.keys.first, **fields))

    def test_a_tag_object_answer_for_another_object_is_refused(self) -> None:
        """Asked for one object, an answer about another."""
        github = self.signed(self.keys.first)
        github.answers[f"repos/{REPO}/git/tags/{TAG_OBJECT_SHA}"]["sha"] = OTHER_SHA
        with self.assertRaises(RefusedError):
            self.preflight(github)

    def test_openpgp_signature_is_refused_by_name(self) -> None:
        """A tag signed the other way is a mistake worth a sentence, not a verify failure."""
        armor = "-----BEGIN PGP SIGNATURE-----\n\nAA==\n-----END PGP SIGNATURE-----\n"
        github = FakeGitHub(annotated_ref(), tag_answer(payload_for(), armor))
        with self.assertRaisesRegex(RefusedError, "SSH"):
            self.preflight(github)

    def test_strange_answers_are_refused(self) -> None:
        """Anything that isn't what GitHub answers, in any position, is a refusal."""
        good_tag = tag_answer(payload_for(), self.keys.sign(self.keys.first, payload_for()))
        for name, github in {
            "a list for the ref": FakeGitHub([annotated_ref()], good_tag),
            "another ref": FakeGitHub(
                {"ref": "refs/tags/other", "object": {"sha": TAG_OBJECT_SHA, "type": "tag"}},
                good_tag,
            ),
            "a ref with no object": FakeGitHub({"ref": f"refs/tags/{TAG}"}, good_tag),
            "a tag object that is a list": FakeGitHub(annotated_ref(), []),
            "no verification": FakeGitHub(
                annotated_ref(),
                {key: value for key, value in good_tag.items() if key != "verification"},
            ),
            "a numeric payload": FakeGitHub(
                annotated_ref(),
                {**good_tag, "verification": {"payload": 1, "signature": "x"}},
            ),
            "a numeric signature": FakeGitHub(
                annotated_ref(),
                {**good_tag, "verification": {"payload": "x", "signature": 1}},
            ),
            "a lone surrogate in the message": FakeGitHub(
                annotated_ref(),
                {
                    **good_tag,
                    "verification": {
                        "payload": payload_for().decode() + chr(0xD800) + "\n",
                        "signature": good_tag["verification"]["signature"],
                    },
                },
            ),
            "a lone surrogate in the signature": FakeGitHub(
                annotated_ref(),
                {
                    **good_tag,
                    "verification": {
                        "payload": payload_for().decode(),
                        "signature": good_tag["verification"]["signature"] + chr(0xD800),
                    },
                },
            ),
            "a tag object answer saying it points at a tree": FakeGitHub(
                annotated_ref(),
                {**good_tag, "object": {"sha": SHA, "type": "tree"}},
            ),
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                self.preflight(github)

    def test_only_a_newline_ends_a_header(self) -> None:
        """Signed by a listed key, and read as `verify_tag` reads it: not the tag's name."""
        for name, ending in {
            "a carriage return": "\r",
            "a form feed": "\f",
            "a line separator": LINE_SEPARATOR,
            "a next line": chr(0x85),
        }.items():
            with self.subTest(name=name):
                payload = payload_for(tag=f"{TAG}{ending}x y")
                with self.assertRaisesRegex(RefusedError, "is named"):
                    self.preflight(self.signed(self.keys.first, payload))

    def test_only_an_empty_line_ends_the_headers(self) -> None:
        """So a second tag after a line that merely looks empty still counts."""
        for name, looks_empty in {"a space": " ", "a carriage return and a space": "\r "}.items():
            with self.subTest(name=name):
                head = f"object {SHA}\ntype commit\ntag {TAG}\n{looks_empty}\n"
                payload = f"{head}tag v9.9.9\n\nrelease\n".encode()
                with self.assertRaisesRegex(RefusedError, "second tag"):
                    self.preflight(self.signed(self.keys.first, payload))

    def test_signed_bytes_with_no_final_newline_are_refused(self) -> None:
        """The CLI joins them to the signature and wants its armor at a line's start."""
        payload = payload_for().rstrip(b"\n")
        with self.assertRaisesRegex(RefusedError, "newline"):
            self.preflight(self.signed(self.keys.first, payload))

    def test_a_signature_field_must_be_one_block_and_nothing_else(self) -> None:
        """`ssh-keygen` reads the first block and `verify_tag` the last, so two can't be allowed."""
        payload = payload_for()
        good = self.keys.sign(self.keys.first, payload)
        stranger = self.keys.sign(self.keys.stranger, payload)
        for name, signature in {
            "a second block after": good + stranger,
            "text after": f"{good}and more\n",
            "text before": f"text\n{good}",
            "CRLF line ends": good.replace("\n", "\r\n"),
            "no end armor": good.split("-----END")[0],
        }.items():
            with self.subTest(name=name):
                github = FakeGitHub(annotated_ref(), tag_answer(payload, signature))
                with self.assertRaisesRegex(RefusedError, "SSH signature"):
                    self.preflight(github)
        self.preflight(FakeGitHub(annotated_ref(), tag_answer(payload, good.rstrip("\n"))))

    def with_ssh_keygen(self, script: str | None) -> None:
        """Make PATH hold only this `ssh-keygen`, or none, from here to the end of the test."""
        directory = self.root / "fake-bin"
        directory.mkdir()
        if script is not None:
            fake_command(directory, "ssh-keygen", script)
        patch = mock.patch.dict(os.environ, {"PATH": str(directory)})
        patch.start()
        self.addCleanup(patch.stop)

    def test_an_ssh_keygen_killed_by_a_signal_is_a_refusal(self) -> None:
        """Its exit status is then negative, which must not read as a good signature."""
        github = self.signed(self.keys.first)
        self.with_ssh_keygen("kill -9 $$")
        with self.assertRaisesRegex(RefusedError, "signature"):
            self.preflight(github)

    def test_a_missing_ssh_keygen_is_a_refusal(self) -> None:
        """A sentence, not a traceback."""
        github = self.signed(self.keys.first)
        self.with_ssh_keygen(None)
        with self.assertRaisesRegex(RefusedError, "ssh-keygen could not run"):
            self.preflight(github)

    def test_a_hung_ssh_keygen_is_a_refusal(self) -> None:
        """Only the timeout stops it, short of the job's own limit."""
        github = self.signed(self.keys.first)
        self.with_ssh_keygen("exec /bin/sleep 30")
        with (
            mock.patch.object(release_preflight, "COMMAND_TIMEOUT_SECONDS", 0.2),
            self.assertRaisesRegex(RefusedError, "ssh-keygen could not run"),
        ):
            self.preflight(github)

    def test_a_ref_that_points_at_no_tag_object_stops_there(self) -> None:
        """Its sha would become part of a path, so nothing else is asked with one that's strange."""
        for name, target in {
            "a path for a sha": {"sha": "../../x", "type": "tag"},
            "an uppercase sha": {"sha": TAG_OBJECT_SHA.upper(), "type": "tag"},
            "a numeric sha": {"sha": 1, "type": "tag"},
            "a tree": {"sha": TAG_OBJECT_SHA, "type": "tree"},
            "no type": {"sha": TAG_OBJECT_SHA},
        }.items():
            with self.subTest(name=name):
                github = FakeGitHub({"ref": f"refs/tags/{TAG}", "object": target}, {})
                with self.assertRaisesRegex(RefusedError, "tag object"):
                    self.preflight(github)
                self.assertEqual(len(github.calls), 1)

    def test_a_404_is_a_refusal(self) -> None:
        """A tag GitHub doesn't know is not one to publish."""
        github = FakeGitHub(annotated_ref(), {})
        github.answers = {}
        with self.assertRaisesRegex(RefusedError, "gh api"):
            self.preflight(github)

    def test_no_signers_stops_before_github(self) -> None:
        """A build that trusts no key has nothing to prove the tag with."""
        self.write_signers("# nothing yet")
        github = self.signed(self.keys.first)
        with self.assertRaisesRegex(RefusedError, "key"):
            self.preflight(github)
        self.assertEqual(github.calls, [])

    def test_a_missing_signers_file_is_refused(self) -> None:
        """The same, with no file."""
        (self.root / "crates" / "cli" / "assets" / "release-signers").unlink()
        with self.assertRaisesRegex(RefusedError, "release-signers"):
            self.preflight(self.signed(self.keys.first))

    def test_ssh_keygen_gets_no_token_and_no_shell(self) -> None:
        """It needs neither, and what it reads arrives as a file or on stdin."""
        github = self.signed(self.keys.first)
        run = subprocess.run
        seen: list[tuple[list[str], dict[str, object]]] = []

        def spy(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            seen.append((args, kwargs))
            return run(args, **kwargs)

        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "secret"}),
            mock.patch.object(release_preflight.subprocess, "run", spy),
        ):
            self.preflight(github)
        self.assertEqual(len(seen), 1)
        args, kwargs = seen[0]
        self.assertEqual(
            args[:7],
            ["ssh-keygen", "-Y", "verify", "-n", "git", "-I", "landfall-release"],
        )
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("GH_TOKEN", kwargs["env"])
        self.assertEqual(kwargs["input"], payload_for())
        self.assertEqual(kwargs["timeout"], COMMAND_TIMEOUT_SECONDS)

    def test_a_local_failure_is_an_annotation_and_exit_one(self) -> None:
        """A machine that can't make a temporary directory gets a sentence, not a traceback."""
        github = self.signed(self.keys.first)
        printed = io.StringIO()
        with (
            mock.patch.object(release_preflight, "gh_api", github),
            mock.patch.object(release_preflight, "ROOT", self.root),
            mock.patch.object(
                release_preflight.tempfile,
                "TemporaryDirectory",
                side_effect=OSError("no space"),
            ),
            contextlib.redirect_stdout(printed),
        ):
            status = release_preflight.main(["--tag", TAG, "--sha", SHA, "--repo", REPO])
        self.assertEqual(status, 1)
        self.assertTrue(printed.getvalue().startswith("::error title=Release preflight::no space"))


class GhApiTests(unittest.TestCase):
    """How GitHub's answer is read, with `subprocess.run` answering for `gh`."""

    def answer(self, stdout: bytes, returncode: int = 0) -> object:
        """Call `gh_api` with this as the command's result."""
        result = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=b"gh says no")
        with mock.patch.object(release_preflight.subprocess, "run", return_value=result) as run:
            answer = release_preflight.gh_api("repos/owner/landfall/git/ref/tags/v1.2.3")
        self.assertEqual(
            run.call_args.args[0],
            ["gh", "api", "--method", "GET", "repos/owner/landfall/git/ref/tags/v1.2.3"],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], COMMAND_TIMEOUT_SECONDS)
        return answer

    def test_an_answer_is_parsed(self) -> None:
        """The usual case."""
        self.assertEqual(self.answer(b'{"a": 1}'), {"a": 1})

    def test_failure_is_a_refusal(self) -> None:
        """Whatever `gh` said, and without repeating it unsafely."""
        with self.assertRaisesRegex(RefusedError, "gh says no"):
            self.answer(b"", returncode=1)

    def test_a_gh_killed_by_a_signal_is_a_refusal(self) -> None:
        """Its exit status is then negative, and what it printed before dying isn't an answer."""
        with self.assertRaisesRegex(RefusedError, "failed"):
            self.answer(b'{"a": 1}', returncode=-9)

    def test_an_oversized_answer_is_refused_before_parsing(self) -> None:
        """Everything fetched is hostile. 1 MiB is written out, so a new cap takes two edits."""
        with self.assertRaisesRegex(RefusedError, "bytes"):
            self.answer(b" " * (1024 * 1024 + 1))
        with self.assertRaisesRegex(RefusedError, "isn't JSON"):
            self.answer(b" " * (1024 * 1024))

    def test_long_values_are_shortened_in_a_message(self) -> None:
        """A hostile value can't fill a log line."""
        self.assertEqual(release_preflight.shown("x" * 200), "x" * 200)
        self.assertEqual(release_preflight.shown("x" * 201), "x" * 200 + "...")

    def test_answers_that_are_not_json_are_refused(self) -> None:
        """Including JSON a stricter reader wouldn't take."""
        for raw in (
            b"not json",
            b"\xff\xfe",
            b'{"a": NaN}',
            b'{"a": 1, "a": 2}',
            b"[" * 100_000,
        ):
            with self.subTest(raw=raw[:20]), self.assertRaises(RefusedError):
                self.answer(raw)

    def test_a_missing_gh_is_a_refusal(self) -> None:
        """Neither a missing command nor a hung one is a traceback."""
        for error in (FileNotFoundError("gh"), subprocess.TimeoutExpired("gh", 1)):
            with (
                self.subTest(error=error),
                mock.patch.object(release_preflight.subprocess, "run", side_effect=error),
                self.assertRaises(RefusedError),
            ):
                release_preflight.gh_api("repos/owner/landfall/git/ref/tags/v1.2.3")


if __name__ == "__main__":
    unittest.main()
