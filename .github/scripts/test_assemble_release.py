"""Unit tests for assemble_release.py, on small files and made-up bundles built here."""

import base64
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import assemble_release
from assemble_release import RefusedError, Release

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERSION = "1.2.3"
REPO = "owner/landfall"
RELEASE = Release(VERSION, REPO)
BINARY_MODE = 0o755
LICENCE_MODE = 0o644

# The assets table of the plan, for 1.2.3. Spelled out rather than built, so a change of name
# anywhere has to change this as well.
BINARIES = (
    "landfall-1.2.3-darwin-arm64",
    "landfall-1.2.3-linux-amd64",
    "landfall-1.2.3-linux-arm64",
    "landfall-agent-1.2.3-linux-amd64",
    "landfall-agent-1.2.3-linux-arm64",
)
OTHERS = ("LICENSE-APACHE", "LICENSE-MIT", "SHA256SUMS", "landfall.rb")
INPUTS = (
    "dist/linux_amd64/landfall",
    "dist/linux_amd64/landfall-agent",
    "dist/linux_arm64/landfall",
    "dist/linux_arm64/landfall-agent",
    "macos/landfall",
)
PROOF = {"logIndex": "1", "rootHash": "AA==", "hashes": ["AA=="]}
PROMISE = {"signedEntryTimestamp": "AA=="}
SHA_LENGTH = 64


def sha256(data: bytes) -> str:
    """Return the hex digest of some bytes."""
    return hashlib.sha256(data).hexdigest()


def block(formula: str, opening: str) -> str:
    """Return the block a line of a formula opens, as far as the `end` at that line's indent."""
    lines = formula.split("\n")
    start = next(i for i, line in enumerate(lines) if line.strip() == opening)
    indent = lines[start][: -len(lines[start].lstrip())]
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == f"{indent}end")
    return "\n".join(lines[start + 1 : end])


def statement(subjects: list[dict[str, object]]) -> dict[str, object]:
    """Return an in-toto statement naming these subjects."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": subjects,
        "predicate": {},
    }


def bundle(payload: dict[str, object] | bytes) -> dict[str, object]:
    """Return a bundle of the right shape around a statement. No signature in it means anything."""
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": "AA=="},
            "tlogEntries": [
                {"logIndex": "1", "inclusionProof": PROOF, "inclusionPromise": PROMISE}
            ],
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(raw).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "AA=="}],
        },
    }


class TempDirTestCase(unittest.TestCase):
    """A test with a directory of its own."""

    def setUp(self) -> None:
        """Make the directory, removed when the test ends."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)


class AssembleTests(TempDirTestCase):
    """What `assemble` writes, and what it refuses to start on."""

    def setUp(self) -> None:
        """Lay out the inputs as the build jobs leave them, each with its own bytes."""
        super().setUp()
        self.dist = self.tmp / "dist"
        self.macos = self.tmp / "macos"
        self.root = self.tmp / "root"
        self.out = self.tmp / "out"
        for name in INPUTS:
            self.input_file(name).parent.mkdir(parents=True, exist_ok=True)
            self.input_file(name).write_bytes(f"binary {name}".encode())
        # What the Dockerfile's stage also holds, and a release doesn't.
        (self.dist / "linux_amd64" / "landfall-server").write_bytes(b"server")
        self.root.mkdir()
        (self.root / "LICENSE-MIT").write_bytes(b"mit text")
        (self.root / "LICENSE-APACHE").write_bytes(b"apache text")

    def input_file(self, name: str) -> Path:
        """Return where an input lies."""
        return self.tmp / name

    def assemble(self, release: Release = RELEASE) -> None:
        """Assemble into `self.out`."""
        assemble_release.assemble(self.dist, self.macos, release, self.out, self.root)

    def sums(self) -> list[tuple[str, str]]:
        """Return SHA256SUMS as (digest, name), in its order, wanting its exact line format."""
        text = (self.out / "SHA256SUMS").read_text(encoding="utf-8")
        self.assertTrue(text.endswith("\n"))
        lines = [line.split("  ") for line in text[:-1].split("\n")]
        self.assertTrue(all(len(line) == 2 for line in lines), lines)  # noqa: PLR2004
        return [(line[0], line[1]) for line in lines]

    def test_names_match_the_table(self) -> None:
        """The out directory holds exactly the table's files, and no landfall-server."""
        self.assemble()
        self.assertEqual({path.name for path in self.out.iterdir()}, {*BINARIES, *OTHERS})

    def test_each_name_holds_the_right_input(self) -> None:
        """An arm64 name with amd64 bytes would be an attested lie."""
        self.assemble()
        expected = {
            "landfall-1.2.3-darwin-arm64": "macos/landfall",
            "landfall-1.2.3-linux-amd64": "dist/linux_amd64/landfall",
            "landfall-1.2.3-linux-arm64": "dist/linux_arm64/landfall",
            "landfall-agent-1.2.3-linux-amd64": "dist/linux_amd64/landfall-agent",
            "landfall-agent-1.2.3-linux-arm64": "dist/linux_arm64/landfall-agent",
        }
        for name, source in expected.items():
            with self.subTest(name=name):
                self.assertEqual((self.out / name).read_bytes(), f"binary {source}".encode())

    def test_binaries_are_executable_whatever_the_input_mode(self) -> None:
        """Artifacts lose the executable bit, so nothing may depend on what came in."""
        self.input_file("macos/landfall").chmod(0o600)
        self.assemble()
        for name in BINARIES:
            with self.subTest(name=name):
                mode = stat.S_IMODE((self.out / name).stat().st_mode)
                self.assertEqual(mode, BINARY_MODE)

    def test_licences_are_copied_and_not_executable(self) -> None:
        """Nothing runs them, so their mode is the same whatever the checkout or the umask."""
        (self.root / "LICENSE-MIT").chmod(0o755)
        self.addCleanup(os.umask, os.umask(0o077))
        self.assemble()
        self.assertEqual((self.out / "LICENSE-MIT").read_bytes(), b"mit text")
        self.assertEqual((self.out / "LICENSE-APACHE").read_bytes(), b"apache text")
        mode = stat.S_IMODE((self.out / "LICENSE-MIT").stat().st_mode)
        self.assertEqual(mode, LICENCE_MODE)

    def test_missing_input_binary_is_refused(self) -> None:
        """Each input is needed, and refusing writes nothing a later step could mistake."""
        for name in INPUTS:
            with self.subTest(name=name):
                path = self.input_file(name)
                held = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(RefusedError, "missing"):
                    self.assemble()
                self.assertFalse(self.out.exists())
                path.write_bytes(held)

    def test_empty_input_binary_is_refused(self) -> None:
        """A build that wrote nothing shouldn't get a hash and a name."""
        self.input_file("macos/landfall").write_bytes(b"")
        with self.assertRaisesRegex(RefusedError, "empty"):
            self.assemble()

    def test_linked_input_binary_is_refused(self) -> None:
        """A link in an artifact could copy anything readable into a public release."""
        path = self.input_file("macos/landfall")
        path.unlink()
        path.symlink_to(self.root / "LICENSE-MIT")
        with self.assertRaisesRegex(RefusedError, "not a regular file"):
            self.assemble()

    def test_a_link_on_the_way_to_an_input_is_refused(self) -> None:
        """A link further up could copy anything readable as well, and nothing is written."""
        elsewhere = self.tmp / "elsewhere"
        shutil.copytree(self.dist, elsewhere)
        for name, path, target in (
            ("a platform directory", self.dist / "linux_arm64", elsewhere / "linux_arm64"),
            ("--dist itself", self.dist, elsewhere),
            ("--macos itself", self.macos, elsewhere),
        ):
            with self.subTest(name=name):
                held = path.with_name(f"{path.name}.held")
                path.rename(held)
                path.symlink_to(target)
                with self.assertRaisesRegex(RefusedError, "is a link"):
                    self.assemble()
                self.assertFalse(self.out.exists())
                path.unlink()
                held.rename(path)

    def test_an_output_that_is_a_link_is_refused(self) -> None:
        """Files written through it would land somewhere nobody named."""
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.out.symlink_to(elsewhere)
        with self.assertRaisesRegex(RefusedError, "is a link"):
            self.assemble()
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_directory_as_an_input_is_refused(self) -> None:
        """A sentence, not a traceback from the copy."""
        path = self.input_file("macos/landfall")
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(RefusedError, "not a regular file"):
            self.assemble()

    def test_generated_files_have_their_mode_whatever_the_umask(self) -> None:
        """A release asset mustn't depend on the runner's umask."""
        self.addCleanup(os.umask, os.umask(0o077))
        self.assemble()
        for name in ("SHA256SUMS", "landfall.rb"):
            with self.subTest(name=name):
                mode = stat.S_IMODE((self.out / name).stat().st_mode)
                self.assertEqual(mode, LICENCE_MODE)

    def test_missing_licence_is_refused(self) -> None:
        """The table lists them, so a release without one isn't the release it describes."""
        (self.root / "LICENSE-APACHE").unlink()
        with self.assertRaisesRegex(RefusedError, "LICENSE-APACHE"):
            self.assemble()

    def test_output_directory_with_anything_in_it_is_refused(self) -> None:
        """Whatever is in it would be attested, as the workflow attests `out/*`."""
        self.out.mkdir()
        (self.out / "leftover").write_bytes(b"x")
        with self.assertRaisesRegex(RefusedError, "not empty"):
            self.assemble()

    def test_sums_cover_every_subject_and_are_sorted(self) -> None:
        """Every file but SHA256SUMS, with its real digest, sorted by name."""
        self.assemble()
        sums = self.sums()
        names = [name for _, name in sums]
        self.assertEqual(names, sorted(names))
        self.assertEqual(set(names), {*BINARIES, *OTHERS} - {"SHA256SUMS"})
        for digest, name in sums:
            with self.subTest(name=name):
                self.assertEqual(digest, sha256((self.out / name).read_bytes()))

    def test_sums_do_not_list_themselves(self) -> None:
        """A file can't hold its own hash."""
        self.assemble()
        self.assertNotIn("SHA256SUMS", [name for _, name in self.sums()])

    def test_formula_pins_each_platform_url_and_hash(self) -> None:
        """Each platform's block has that platform's URL and that file's hash, and no other's."""
        self.assemble()
        formula = (self.out / "landfall.rb").read_text(encoding="utf-8")
        base = "https://github.com/owner/landfall/releases/download/v1.2.3"
        macos = block(formula, "on_macos do")
        linux = block(formula, "on_linux do")
        platforms = {
            "landfall-1.2.3-darwin-arm64": macos,
            "landfall-1.2.3-linux-arm64": block(linux, "on_arm do"),
            "landfall-1.2.3-linux-amd64": block(linux, "on_intel do"),
        }
        for name, text in platforms.items():
            with self.subTest(name=name):
                digest = sha256((self.out / name).read_bytes())
                self.assertEqual(
                    [
                        line.strip()
                        for line in text.split("\n")
                        if "url" in line or "sha256" in line
                    ],
                    [f'url "{base}/{name}"', f'sha256 "{digest}"'],
                )
        self.assertIn("depends_on arch: :arm64", macos)
        self.assertIn('homepage "https://github.com/owner/landfall"', formula)
        self.assertIn('version "1.2.3"', formula)

    def test_formula_installs_the_one_binary_as_landfall(self) -> None:
        """A raw file arrives under its asset name, and the command is `landfall`."""
        self.assemble()
        formula = (self.out / "landfall.rb").read_text(encoding="utf-8")
        self.assertIn('bin.install Dir["landfall-*"].first => "landfall"', formula)
        self.assertIn('  desc "', formula)

    def test_formula_has_any_of_license_and_a_version_test(self) -> None:
        """The licence is a choice of two, and installing proves the binary's version."""
        self.assemble()
        formula = (self.out / "landfall.rb").read_text(encoding="utf-8")
        self.assertIn('license any_of: ["MIT", "Apache-2.0"]', formula)
        self.assertIn(
            'assert_match version.to_s, shell_output("#{bin}/landfall --version")',
            block(formula, "test do"),
        )

    def test_formula_parses_as_ruby(self) -> None:
        """`ruby -c` is the most a machine without Homebrew can say about it."""
        ruby = shutil.which("ruby")
        if ruby is None:
            if os.environ.get("LANDFALL_TEST_REQUIRE_RUBY"):
                self.fail("LANDFALL_TEST_REQUIRE_RUBY is set and there is no ruby")
            self.skipTest("no ruby on this machine: formula_parses_as_ruby did not run")
        self.assemble()
        result = subprocess.run(
            [ruby, "-c", str(self.out / "landfall.rb")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_prerelease_versions_name_files_the_same_way(self) -> None:
        """A release candidate differs only in the version, in each name and in the formula."""
        self.assemble(Release("1.2.3-rc.1", REPO))
        names = {path.name for path in self.out.iterdir()}
        expected = {name.replace("1.2.3", "1.2.3-rc.1") for name in BINARIES}
        self.assertEqual(names, {*expected, *OTHERS})
        formula = (self.out / "landfall.rb").read_text(encoding="utf-8")
        self.assertIn('version "1.2.3-rc.1"', formula)
        self.assertIn(
            "releases/download/v1.2.3-rc.1/landfall-1.2.3-rc.1-linux-arm64",
            formula,
        )


class ReleaseTests(unittest.TestCase):
    """What may become part of a file name, a URL and a Ruby string."""

    def test_versions_that_could_not_be_a_release_are_refused(self) -> None:
        """They'd reach file names and a formula, so nothing that isn't a version gets through."""
        for version in (
            "",
            "1.2",
            "v1.2.3",
            "1.2.3\n",
            "01.2.3",
            "1.2.3+build",
            "1.2.3-",
            "1.2.3-rc..1",
            "../1.2.3",
            '1.2.3"; system("x")#',
            "1.2.3-#{x}",
            f"{chr(0x661)}.{chr(0x662)}.{chr(0x663)}",
            "1.2.3-01",
            "1.2.3-rc.01",
        ):
            with self.subTest(version=version), self.assertRaisesRegex(RefusedError, "version"):
                Release(version, REPO)

    def test_repositories_that_could_not_exist_are_refused(self) -> None:
        """The same, for what goes in the URLs."""
        for repo in (
            "",
            "owner",
            "owner/",
            "/name",
            "a/b/c",
            "owner/..",
            "owner/.",
            "-owner/name",
            "owner/na me",
            'owner/x"',
            "owner/name\n",
            "owner/#{x}",
        ):
            with self.subTest(repo=repo), self.assertRaisesRegex(RefusedError, "repository"):
                Release(VERSION, repo)

    def test_good_names_pass(self) -> None:
        """A prerelease with hyphens and dots, and a repository name with both."""
        Release("10.20.30-rc.1-a", "some-owner/some.repo_name-1")
        for version in ("1.2.3-0", "1.2.3-0a", "1.2.3-rc.10", "1.2.3-01a", "1.2.3--"):
            with self.subTest(version=version):
                Release(version, REPO)


class CheckBundleTests(TempDirTestCase):
    """`check-bundle` reads a bundle's shape, against the files in a directory."""

    def setUp(self) -> None:
        """Make a directory of two files, and subjects that name exactly them."""
        super().setUp()
        self.out = self.tmp / "out"
        self.out.mkdir()
        (self.out / "one").write_bytes(b"first")
        (self.out / "two").write_bytes(b"second")
        self.subjects: list[dict[str, object]] = [
            {"name": "one", "digest": {"sha256": sha256(b"first")}},
            {"name": "two", "digest": {"sha256": sha256(b"second")}},
        ]
        self.bundle_path = self.tmp / "bundle.json"

    def check(self, value: dict[str, object] | None = None) -> None:
        """Write a bundle, by default the good one, as one line and check it."""
        document = value if value is not None else bundle(statement(self.subjects))
        self.bundle_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        assemble_release.check_bundle(self.bundle_path, self.out)

    def assert_refused(self, value: dict[str, object], *pieces: str) -> None:
        """Want this bundle refused, with each piece in the message."""
        with self.assertRaises(RefusedError) as caught:
            self.check(value)
        for piece in pieces:
            self.assertIn(piece, str(caught.exception))

    def test_bundle_naming_every_file_passes(self) -> None:
        """The right shape, naming each file by basename and digest."""
        self.check()

    def test_a_real_bundle_has_the_shape_wanted(self) -> None:
        """What `landfall-origin` verifies, from a real release: only its subject differs here."""
        fixture = REPOSITORY_ROOT / "crates/origin/tests/fixtures/attestation/bundle.json"
        document = json.loads(fixture.read_text(encoding="utf-8"))
        real = assemble_release.read_statement(document)
        assemble_release.check_shape(document)
        self.assertEqual(len(assemble_release.subject_digests(real)), 1)

    def test_bundle_missing_a_file_is_refused(self) -> None:
        """A file on its way to the release that the attestation doesn't cover."""
        self.assert_refused(bundle(statement(self.subjects[:1])), "two")

    def test_bundle_with_a_wrong_digest_is_refused(self) -> None:
        """The name alone doesn't make it this file."""
        self.subjects[1]["digest"] = {"sha256": sha256(b"other")}
        self.assert_refused(bundle(statement(self.subjects)), "two", "digest")

    def test_bundle_with_swapped_names_is_refused(self) -> None:
        """Each digest is attested, but under the other's name: what the name check is for."""
        one, two = self.subjects
        one["digest"], two["digest"] = two["digest"], one["digest"]
        self.assert_refused(bundle(statement(self.subjects)), "digest")

    def test_bundle_with_an_extra_subject_is_refused(self) -> None:
        """The attestation would vouch for a file nobody is publishing."""
        self.subjects.append({"name": "three", "digest": {"sha256": sha256(b"third")}})
        self.assert_refused(bundle(statement(self.subjects)), "three")

    def test_bundle_naming_a_subject_twice_is_refused(self) -> None:
        """Which of two would count isn't something to guess."""
        self.subjects.append(self.subjects[0])
        self.assert_refused(bundle(statement(self.subjects)), "one", "twice")

    def test_bundle_without_a_promise_is_refused(self) -> None:
        """The verifier wants both, so a bundle without it would ship and never verify."""
        document = bundle(statement(self.subjects))
        del document["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]
        self.assert_refused(document, "inclusionPromise")

    def test_bundle_without_a_proof_is_refused(self) -> None:
        """The same, for the proof, and an empty one is no proof."""
        document = bundle(statement(self.subjects))
        del document["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
        self.assert_refused(document, "inclusionProof")
        document = bundle(statement(self.subjects))
        document["verificationMaterial"]["tlogEntries"][0]["inclusionProof"] = {}
        self.assert_refused(document, "inclusionProof")

    def test_tlog_entries_other_than_one_are_refused(self) -> None:
        """Rule 4 of the design wants exactly one."""
        for count in (0, 2):
            with self.subTest(count=count):
                document = bundle(statement(self.subjects))
                entries = document["verificationMaterial"]["tlogEntries"]
                document["verificationMaterial"]["tlogEntries"] = entries[:1] * count
                self.assert_refused(document, "tlog", str(count))

    def test_other_bundle_versions_are_refused(self) -> None:
        """Older formats need no inclusion proof."""
        document = bundle(statement(self.subjects))
        document["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
        self.assert_refused(document, "v0.3")

    def test_other_predicate_types_are_refused(self) -> None:
        """An SBOM with the right subjects isn't provenance."""
        payload = statement(self.subjects)
        payload["predicateType"] = "https://spdx.dev/Document/v2.3"
        self.assert_refused(bundle(payload), "provenance")

    def test_other_statement_and_payload_types_are_refused(self) -> None:
        """Anything but an in-toto statement in its envelope isn't what the verifier reads."""
        payload = statement(self.subjects)
        payload["_type"] = "https://example.invalid/other"
        self.assert_refused(bundle(payload), "statement")
        document = bundle(statement(self.subjects))
        document["dsseEnvelope"]["payloadType"] = "text/plain"
        self.assert_refused(document, "payload")

    def test_subject_with_another_digest_type_is_refused(self) -> None:
        """Only sha256 is compared, so a subject with more says something unchecked."""
        self.subjects[0]["digest"] = {"sha256": sha256(b"first"), "sha1": "0" * 40}
        self.assert_refused(bundle(statement(self.subjects)), "one", "digest")

    def test_malformed_statements_are_refused(self) -> None:
        """Whatever it holds, the answer is a refusal rather than a traceback."""
        for name, payload in {
            "not base64": None,
            "not JSON": b"not json",
            "not an object": b"[]",
            "no subject": json.dumps({**statement(self.subjects), "subject": None}).encode(),
            "a subject that is not an object": json.dumps(statement(["x"])).encode(),
            "a nameless subject": json.dumps(statement([{"digest": {}}])).encode(),
        }.items():
            with self.subTest(name=name):
                document = bundle(payload if payload is not None else b"x")
                if payload is None:
                    document["dsseEnvelope"]["payload"] = "!!!"
                self.assert_refused(document)

    def test_wrong_types_are_refused(self) -> None:
        """Each position that wants an object, a list or text, given something else."""
        material = "verificationMaterial"
        for name, change in {
            "tlog entries that are text": lambda d: d[material].update(tlogEntries="x"),
            "tlog entries that are an object": lambda d: d[material].update(tlogEntries={"a": 1}),
            "a tlog entry that is text": lambda d: d[material].update(tlogEntries=["x"]),
            "a proof that is text": lambda d: d[material]["tlogEntries"][0].update(
                inclusionProof="x"
            ),
            "a numeric payload": lambda d: d["dsseEnvelope"].update(payload=1),
        }.items():
            with self.subTest(name=name):
                document = bundle(statement(self.subjects))
                change(document)
                self.assert_refused(document)

    def test_digests_of_the_wrong_type_are_refused(self) -> None:
        """A digest that isn't an object holding text can't be compared with a file's."""
        for digest in ("x", ["x"], {"sha256": 1}, None):
            with self.subTest(digest=digest):
                subject = {"name": "one", "digest": digest}
                self.assert_refused(bundle(statement([subject, self.subjects[1]])), "one", "sha256")

    def test_nan_and_deep_nesting_are_refused(self) -> None:
        """Python's `json` would take the one, and on some versions raise for the other."""
        for name, raw in {
            "NaN": '{"mediaType": NaN}\n',
            "Infinity": '{"mediaType": -Infinity}\n',
            "deep nesting": "[" * 100_000 + "\n",
        }.items():
            with self.subTest(name=name):
                self.bundle_path.write_text(raw, encoding="utf-8")
                with self.assertRaisesRegex(RefusedError, "not valid"):
                    assemble_release.check_bundle(self.bundle_path, self.out)

    def test_an_unreadable_directory_is_refused(self) -> None:
        """Missing, or a file where a directory should be."""
        (self.tmp / "afile").write_bytes(b"x")
        self.bundle_path.write_text("{}\n", encoding="utf-8")
        for path in (self.tmp / "missing", self.tmp / "afile"):
            with self.subTest(path=path), self.assertRaisesRegex(RefusedError, "could not be read"):
                assemble_release.check_bundle(self.bundle_path, path)

    def test_the_limit_is_the_verifiers(self) -> None:
        """Read from the Rust constant, as its comment says: a bundle this accepts, it must too."""
        source = (REPOSITORY_ROOT / "crates/origin/src/attestation.rs").read_text(encoding="utf-8")
        found = re.search(r"const MAX_BUNDLE_BYTES: usize = (\d+) \* (\d+) \* (\d+);", source)
        self.assertIsNotNone(found)
        rust = math.prod(int(factor) for factor in found.groups())
        self.assertEqual(assemble_release.MAX_BUNDLE_BYTES, rust)

    def test_long_values_are_shortened_in_a_message(self) -> None:
        """A hostile value can't fill a log line."""
        self.assertEqual(assemble_release.shown("x" * 200), "x" * 200)
        self.assertEqual(assemble_release.shown("x" * 201), "x" * 200 + "...")

    def test_a_payload_with_characters_outside_base64_is_refused(self) -> None:
        """A lenient decoder would skip them, and another reader might not."""
        document = bundle(statement(self.subjects))
        document["dsseEnvelope"]["payload"] = f"!{document['dsseEnvelope']['payload']}"
        self.assert_refused(document, "base64")

    def test_malformed_shapes_are_refused(self) -> None:
        """The same, for the bundle around it."""
        for document in (
            {},
            {"mediaType": assemble_release.BUNDLE_MEDIA_TYPE},
            {**bundle(statement(self.subjects)), "verificationMaterial": []},
            {**bundle(statement(self.subjects)), "dsseEnvelope": None},
        ):
            with self.subTest(document=document):
                self.assert_refused(document)

    def test_a_bundle_must_be_one_line_and_an_end_of_line(self) -> None:
        """Two lines may be two bundles, and which one a reader takes isn't something to guess."""
        good = json.dumps(bundle(statement(self.subjects)))
        for name, raw in {
            "no end of line": good,
            "two lines": f"{good}\n{good}\n",
            "a blank line after": f"{good}\n\n",
            "pretty-printed": json.dumps(bundle(statement(self.subjects)), indent=1) + "\n",
            "empty": "",
        }.items():
            with self.subTest(name=name):
                self.bundle_path.write_text(raw, encoding="utf-8")
                with self.assertRaisesRegex(RefusedError, "line"):
                    assemble_release.check_bundle(self.bundle_path, self.out)

    def test_a_repeated_key_is_refused(self) -> None:
        """Two readers can take different ones of a repeated key: this one and `gh`, say."""
        good = json.dumps(bundle(statement(self.subjects)))
        self.bundle_path.write_text('{"mediaType":"x",' + good[1:] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RefusedError, "mediaType"):
            assemble_release.check_bundle(self.bundle_path, self.out)

    def test_a_repeated_key_in_the_statement_is_refused(self) -> None:
        """The same, inside the envelope, where the subjects are."""
        good = json.dumps(statement(self.subjects))
        raw = '{"subject":[],' + good[1:]
        self.assert_refused(bundle(raw.encode()), "subject")

    def test_an_oversized_bundle_is_refused(self) -> None:
        """It's read into memory, so the verifier's limit applies here too."""
        with self.bundle_path.open("wb") as file:
            file.truncate(assemble_release.MAX_BUNDLE_BYTES + 1)
        with self.assertRaisesRegex(RefusedError, "bytes"):
            assemble_release.check_bundle(self.bundle_path, self.out)

    def test_a_missing_bundle_is_refused(self) -> None:
        """A step that wrote nothing fails here with a sentence."""
        with self.assertRaisesRegex(RefusedError, "could not be read"):
            assemble_release.check_bundle(self.bundle_path, self.out)

    def test_an_empty_directory_is_refused(self) -> None:
        """A bundle naming nothing, of nothing, would pass for lack of anything to check."""
        for path in self.out.iterdir():
            path.unlink()
        with self.assertRaisesRegex(RefusedError, "no files"):
            self.check(bundle(statement([])))

    def test_something_other_than_a_file_in_the_directory_is_refused(self) -> None:
        """`subject-path` wouldn't name what a link or a directory holds as this does."""
        (self.out / "link").symlink_to(self.out / "one")
        with self.assertRaisesRegex(RefusedError, "regular file"):
            self.check()
        (self.out / "link").unlink()
        (self.out / "directory").mkdir()
        with self.assertRaisesRegex(RefusedError, "regular file"):
            self.check()

    def test_a_refusal_prints_safely_on_one_line(self) -> None:
        """A subject's name comes from the bundle, so it can't be allowed to start a command."""
        self.subjects.append({"name": "x\n::error::forged", "digest": {"sha256": "0" * SHA_LENGTH}})
        with self.assertRaises(RefusedError) as caught:
            self.check()
        self.assertNotIn("\n", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
