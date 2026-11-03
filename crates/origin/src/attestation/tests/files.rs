//! A named release file, against a real bundle with many files as subjects.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use landfall_core::ids::ImageDigest;
use serde_json::{Value, json};
use sigstore_verify::types::Statement;

use super::super::file::find_subject;
use super::super::{
    AttestationError, CertificateIdentity, FileSubject, MAX_BUNDLE_BYTES, SLSA_PROVENANCE,
    match_identity, verify_file_bundle,
};
use super::{Config, mismatched_field};
use crate::release::ReleaseError;
use crate::test_support::sha256;
use crate::trust::TrustRoot;

const BUNDLE: &[u8] = include_bytes!("../../../tests/fixtures/attestation-files/bundle.json");

const CHECKSUMS: &[u8] = include_bytes!("../../../tests/fixtures/attestation-files/checksums.txt");

const TRUSTED_ROOT: &str =
    include_str!("../../../tests/fixtures/attestation-files/trusted_root.json");

const REPO: &str = "nektos/act";

const REPO_ID: u64 = 163_883_279;

const OWNER_ID: u64 = 3_813_618;

const WORKFLOW: &str = ".github/workflows/release.yml";

const TAG: &str = "v0.2.94";

const COMMIT: &str = "3fde8e609623104b099747ff67166561ecb7e6be";

const SAN: &str = "https://github.com/nektos/act/.github/workflows/release.yml@refs/tags/v0.2.94";

const RUN_URL: &str = "https://github.com/nektos/act/actions/runs/41234509130/attempts/1";

const REKOR_LOG_INDEX: u64 = 3_614_772_332;

const INTEGRATED_TIME: i64 = 1_793_475_369;

const ARM: &str = "act_Linux_arm64.tar.gz";

const INTEL: &str = "act_Linux_x86_64.tar.gz";

const SUMS: &str = "checksums.txt";

const SUBJECTS: usize = 12;

fn config() -> Config {
    Config {
        repo: REPO.parse().unwrap(),
        repo_id: REPO_ID,
        owner_id: OWNER_ID,
        workflow: WORKFLOW.to_owned(),
        tag: TAG.parse().unwrap(),
        commit: COMMIT.parse().unwrap(),
    }
}

fn root() -> TrustRoot {
    TrustRoot::from_json(TRUSTED_ROOT)
}

/// The fixture's signed statement, read as plain JSON, independently of the
/// types the code under test parses it with.
fn fixture_statement() -> Value {
    let bundle: Value = serde_json::from_slice(BUNDLE).unwrap();
    let payload = STANDARD
        .decode(bundle["dsseEnvelope"]["payload"].as_str().unwrap())
        .unwrap();
    serde_json::from_slice(&payload).unwrap()
}

/// What the signed statement says the file called `name` hashes to.
fn attested(name: &str) -> ImageDigest {
    let statement = fixture_statement();
    let subject = statement["subject"]
        .as_array()
        .unwrap()
        .iter()
        .find(|subject| subject["name"] == name)
        .unwrap();
    format!("sha256:{}", subject["digest"]["sha256"].as_str().unwrap())
        .parse()
        .unwrap()
}

fn verify(
    bundle: &[u8],
    subjects: &[FileSubject<'_>],
    config: &Config,
) -> Result<super::super::VerifiedAttestation, AttestationError> {
    verify_file_bundle(bundle, subjects, &root(), &config.expected())
}

/// The fixture bundle with its payload replaced by what `edit` makes of it,
/// and its signature left as it was.
fn with_edited_statement(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut statement = fixture_statement();
    edit(&mut statement);
    let mut bundle: Value = serde_json::from_slice(BUNDLE).unwrap();
    bundle["dsseEnvelope"]["payload"] =
        Value::String(STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
    serde_json::to_vec(&bundle).unwrap()
}

/// A statement that names these files, for the tests of the name logic.
fn statement_of(subjects: &[(&str, &ImageDigest)]) -> Statement {
    let subject: Vec<Value> = subjects
        .iter()
        .map(|(name, digest)| {
            let hex = digest.as_ref().strip_prefix("sha256:").unwrap();
            json!({ "name": name, "digest": { "sha256": hex } })
        })
        .collect();
    serde_json::from_value(json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subject,
        "predicateType": SLSA_PROVENANCE,
        "predicate": {},
    }))
    .unwrap()
}

fn some_digest() -> ImageDigest {
    format!("sha256:{}", "ab".repeat(32)).parse().unwrap()
}

/// With one digest throughout, so only the name can decide: the statement's own
/// name is found, and `asked` is refused.
fn assert_name_alone_refuses(in_statement: &str, asked: &str) {
    let digest = some_digest();
    let statement = statement_of(&[(in_statement, &digest)]);
    let own = FileSubject {
        name: in_statement,
        digest: &digest,
    };
    assert_eq!(find_subject(&statement, &own), Ok(()), "{in_statement:?}");
    let other = FileSubject {
        name: asked,
        digest: &digest,
    };
    assert!(
        matches!(
            find_subject(&statement, &other),
            Err(AttestationError::FileSubject { .. })
        ),
        "{asked:?} against {in_statement:?}"
    );
}

/// The fixture's identity, as its certificate has it.
fn act_identity() -> CertificateIdentity {
    CertificateIdentity {
        san: Some(SAN.to_owned()),
        issuer: Some("https://token.actions.githubusercontent.com".to_owned()),
        build_config_uri: Some(SAN.to_owned()),
        source_repository_digest: Some(COMMIT.to_owned()),
        source_repository_ref: Some(format!("refs/tags/{TAG}")),
        source_repository_identifier: Some(REPO_ID.to_string()),
        source_repository_owner_identifier: Some(OWNER_ID.to_string()),
        build_trigger: Some("push".to_owned()),
        runner_environment: Some("github-hosted".to_owned()),
        run_invocation_uri: Some(RUN_URL.to_owned()),
    }
}

#[test]
fn real_bundle_verifies_for_each_named_file() {
    let (sums, arm, intel) = (attested(SUMS), attested(ARM), attested(INTEL));
    let config = config();
    let subjects = [
        FileSubject {
            name: SUMS,
            digest: &sums,
        },
        FileSubject {
            name: ARM,
            digest: &arm,
        },
        FileSubject {
            name: INTEL,
            digest: &intel,
        },
    ];

    let verified = verify(BUNDLE, &subjects, &config).unwrap();

    assert_eq!(verified.digest, sums, "the first subject's digest");
    assert_eq!(verified.san, SAN);
    assert_eq!(verified.commit, config.commit);
    assert_eq!(verified.git_ref, "refs/tags/v0.2.94");
    assert_eq!(verified.repo_id, REPO_ID);
    assert_eq!(verified.owner_id, OWNER_ID);
    assert_eq!(verified.run_url, RUN_URL);
    assert_eq!(verified.rekor_log_index, REKOR_LOG_INDEX);
    assert_eq!(verified.integrated_time, INTEGRATED_TIME);
}

#[test]
fn every_file_of_the_statement_verifies_alone() {
    let statement = fixture_statement();
    let subjects = statement["subject"].as_array().unwrap();
    assert_eq!(subjects.len(), SUBJECTS);
    let config = config();
    for subject in subjects {
        let name = subject["name"].as_str().unwrap();
        let digest = attested(name);
        let asked = [FileSubject {
            name,
            digest: &digest,
        }];
        let verified = verify(BUNDLE, &asked, &config).unwrap();
        assert_eq!(verified.digest, digest, "{name}");
    }
}

#[test]
fn the_fixtures_checksums_file_is_the_attested_one() {
    assert_eq!(sha256(CHECKSUMS), attested(SUMS).as_ref());
}

#[test]
fn another_files_digest_is_refused_under_this_name() {
    let intel = attested(INTEL);
    let asked = [FileSubject {
        name: ARM,
        digest: &intel,
    }];
    let result = verify(BUNDLE, &asked, &config());
    match result {
        Err(AttestationError::FileSubject {
            name,
            expected,
            found,
        }) => {
            assert_eq!(name, ARM);
            assert_eq!(expected, intel.to_string());
            assert!(found.contains("\"act_Linux_arm64.tar.gz\""), "{found}");
        }
        other => panic!("expected a file subject refusal, got {:?}", other.err()),
    }
}

#[test]
fn right_name_with_a_wrong_digest_is_refused() {
    let wrong = some_digest();
    let asked = [FileSubject {
        name: ARM,
        digest: &wrong,
    }];
    assert!(matches!(
        verify(BUNDLE, &asked, &config()),
        Err(AttestationError::FileSubject { .. })
    ));
}

#[test]
fn every_subject_is_checked_not_only_the_first() {
    let (arm, intel) = (attested(ARM), attested(INTEL));
    let asked = [
        FileSubject {
            name: ARM,
            digest: &arm,
        },
        FileSubject {
            name: ARM,
            digest: &intel,
        },
    ];
    assert!(matches!(
        verify(BUNDLE, &asked, &config()),
        Err(AttestationError::FileSubject { .. })
    ));
}

#[test]
fn name_that_only_contains_the_wanted_name_is_refused() {
    for (in_statement, asked) in [
        ("act_Linux_arm64.tar.gz.evil", ARM),
        ("evil-act_Linux_arm64.tar.gz", ARM),
        (ARM, "Linux_arm64.tar.gz"),
        (ARM, "act_Linux_arm64"),
    ] {
        assert_name_alone_refuses(in_statement, asked);
    }

    // The same, on the real statement: part of a real name, with its real digest.
    let arm = attested(ARM);
    let asked = [FileSubject {
        name: "Linux_arm64.tar.gz",
        digest: &arm,
    }];
    assert!(matches!(
        verify(BUNDLE, &asked, &config()),
        Err(AttestationError::FileSubject { .. })
    ));
}

/// Each pair is one name in two spellings, either way round: a file is only ever
/// the bytes of its name, so none of these is the other.
#[test]
fn another_spelling_of_the_name_is_refused() {
    for (one, other) in [
        ("./x", "x"),
        ("a/x", "x"),
        ("/x", "x"),
        ("X", "x"),
        ("x ", "x"),
        (" x", "x"),
        ("x\0", "x"),
        ("x\n", "x"),
        // NFC and NFD of one word.
        ("caf\u{e9}", "cafe\u{301}"),
        // A Cyrillic letter for the Latin one.
        ("\u{445}", "x"),
    ] {
        assert_name_alone_refuses(one, other);
        assert_name_alone_refuses(other, one);
    }
}

/// Having the name twice says nothing of which file it means, so it isn't for
/// the digest asked for to choose: an honest `subject-path` over two directories
/// with the same basename signs just this.
#[test]
fn a_name_given_with_two_digests_is_refused_for_either() {
    let (one, other) = (some_digest(), attested(ARM));
    for statement in [
        statement_of(&[("x", &one), ("x", &other)]),
        statement_of(&[("x", &other), ("x", &one)]),
    ] {
        for digest in [&one, &other] {
            let asked = FileSubject { name: "x", digest };
            let error = find_subject(&statement, &asked).unwrap_err();
            let AttestationError::FileSubject { found, .. } = &error else {
                panic!("expected a file subject refusal, got {error:?}");
            };
            assert_eq!(found, "\"x\" 2 times, not all with this digest");
        }
    }
}

/// The same name and digest twice leaves no doubt what the name means.
#[test]
fn a_name_given_twice_with_one_digest_is_found() {
    let digest = some_digest();
    let statement = statement_of(&[("x", &digest), ("x", &digest)]);
    let asked = FileSubject {
        name: "x",
        digest: &digest,
    };
    assert_eq!(find_subject(&statement, &asked), Ok(()));

    let other = attested(ARM);
    let elsewhere = FileSubject {
        name: "x",
        digest: &other,
    };
    assert!(matches!(
        find_subject(&statement, &elsewhere),
        Err(AttestationError::FileSubject { .. })
    ));
}

#[test]
fn a_same_name_subject_with_no_sha256_is_refused() {
    let digest = some_digest();
    let statement: Statement = serde_json::from_value(json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            { "name": "x", "digest": { "sha256": "ab".repeat(32) } },
            { "name": "x", "digest": { "sha512": "cd".repeat(64) } },
        ],
        "predicateType": SLSA_PROVENANCE,
    }))
    .unwrap();
    let asked = FileSubject {
        name: "x",
        digest: &digest,
    };
    assert!(matches!(
        find_subject(&statement, &asked),
        Err(AttestationError::FileSubject { .. })
    ));
}

/// Another file's duplicate is no reason to refuse this file.
#[test]
fn a_name_given_twice_does_not_touch_another_name() {
    let (one, other) = (some_digest(), attested(ARM));
    let statement = statement_of(&[("y", &one), ("y", &other), ("x", &one)]);
    let asked = FileSubject {
        name: "x",
        digest: &one,
    };
    assert_eq!(find_subject(&statement, &asked), Ok(()));
}

#[test]
fn the_exact_name_and_digest_are_found_among_others() {
    let (one, other) = (some_digest(), attested(ARM));
    let statement = statement_of(&[("one", &one), ("other", &other)]);
    let asked = FileSubject {
        name: "other",
        digest: &other,
    };
    assert_eq!(find_subject(&statement, &asked), Ok(()));
}

/// Asking for no name is refused for that, and not as if the digest were at fault: both
/// subjects here have the digest asked for.
#[test]
fn asking_for_an_empty_name_does_not_blame_the_digest() {
    let digest = some_digest();
    let statement = statement_of(&[("", &digest), ("", &digest)]);
    let asked = FileSubject {
        name: "",
        digest: &digest,
    };
    let error = find_subject(&statement, &asked).unwrap_err();
    let AttestationError::FileSubject { found, .. } = &error else {
        panic!("expected a file subject refusal, got {error:?}");
    };
    assert!(!found.contains("not all with this digest"), "{found}");
}

#[test]
fn a_subject_with_no_name_is_nothing_to_find() {
    // A subject's name may be left out of a statement, and reads as empty.
    let digest = some_digest();
    let statement: Statement = serde_json::from_value(json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{ "digest": { "sha256": "ab".repeat(32) } }],
        "predicateType": SLSA_PROVENANCE,
    }))
    .unwrap();
    let asked = FileSubject {
        name: "",
        digest: &digest,
    };
    assert!(matches!(
        find_subject(&statement, &asked),
        Err(AttestationError::FileSubject { .. })
    ));
}

#[test]
fn what_a_hostile_statement_names_is_quoted_and_bounded() {
    let digest = some_digest();
    let long = format!("evil\n{}", "x".repeat(10_000));
    let many: Vec<(&str, &ImageDigest)> = std::iter::repeat_n((long.as_str(), &digest), 1_000)
        .chain([("evil\u{202e}", &digest)])
        .collect();
    let asked = FileSubject {
        name: ARM,
        digest: &digest,
    };
    let error = find_subject(&statement_of(&many), &asked).unwrap_err();
    let AttestationError::FileSubject { found, .. } = &error else {
        panic!("expected a file subject refusal, got {error:?}");
    };
    assert!(found.contains("\"evil\\nxxx"), "{found}");
    assert!(found.contains("and 985 more"), "{found}");
    assert!(found.len() < 2_000, "{} bytes", found.len());
    assert!(!error.to_string().contains('\n'));

    let bidi = statement_of(&[("evil\u{202e}", &digest)]);
    let error = find_subject(&bidi, &asked).unwrap_err();
    assert!(!error.to_string().contains('\u{202e}'), "{error}");

    let nothing = statement_of(&[]);
    let error = find_subject(&nothing, &asked).unwrap_err();
    assert!(error.to_string().contains("no subject"), "{error}");
}

#[test]
fn the_list_of_names_says_how_many_it_left_out() {
    let digest = some_digest();
    let asked = FileSubject {
        name: ARM,
        digest: &digest,
    };
    for (names, ends) in [(16, "\"n\""), (17, "and 1 more")] {
        let statement = statement_of(&vec![("n", &digest); names]);
        let Err(AttestationError::FileSubject { found, .. }) = find_subject(&statement, &asked)
        else {
            panic!("expected a file subject refusal");
        };
        assert!(found.ends_with(ends), "{found}");
    }
}

#[test]
fn a_refusal_says_the_statement_is_not_yet_verified() {
    let digest = some_digest();
    let asked = FileSubject {
        name: ARM,
        digest: &digest,
    };
    let error = find_subject(&statement_of(&[]), &asked).unwrap_err();
    assert!(error.to_string().contains("unverified"), "{error}");
}

#[test]
fn another_payload_type_is_refused() {
    let mut bundle: Value = serde_json::from_slice(BUNDLE).unwrap();
    bundle["dsseEnvelope"]["payloadType"] = Value::String("text/plain".to_owned());
    let edited = serde_json::to_vec(&bundle).unwrap();
    let arm = attested(ARM);
    let asked = [FileSubject {
        name: ARM,
        digest: &arm,
    }];
    let result = verify(&edited, &asked, &config());
    let Err(AttestationError::Bundle(message)) = result else {
        panic!("expected a malformed bundle, got {:?}", result.err());
    };
    assert!(message.contains("payload type"), "{message}");
}

#[test]
fn no_subjects_is_refused() {
    assert_eq!(
        verify(BUNDLE, &[], &config()),
        Err(AttestationError::NoFileSubjects)
    );
}

#[test]
fn wrong_repo_id_is_refused() {
    let arm = attested(ARM);
    let asked = [FileSubject {
        name: ARM,
        digest: &arm,
    }];
    let mut config = config();
    config.repo_id = REPO_ID + 1;
    assert_eq!(
        mismatched_field(verify(BUNDLE, &asked, &config)),
        "source_repository_identifier"
    );
}

#[test]
fn wrong_commit_is_refused() {
    let arm = attested(ARM);
    let asked = [FileSubject {
        name: ARM,
        digest: &arm,
    }];
    let mut config = config();
    config.commit = "1".repeat(40).parse().unwrap();
    assert_eq!(
        mismatched_field(verify(BUNDLE, &asked, &config)),
        "source_repository_digest"
    );
}

#[test]
fn dispatch_trigger_is_refused() {
    let config = config();
    let expected = config.expected();
    assert!(match_identity(&act_identity(), &expected).is_ok());

    let dispatched = CertificateIdentity {
        build_trigger: Some("workflow_dispatch".to_owned()),
        ..act_identity()
    };
    assert_eq!(
        mismatched_field(match_identity(&dispatched, &expected)),
        "build_trigger"
    );
}

/// The two files' names swapped in the payload, so the name check passes on the
/// edited statement for a digest the signed one gives to the other file: only
/// the signature can catch it.
#[test]
fn tampered_payload_is_refused() {
    let tampered = with_edited_statement(|statement| {
        for subject in statement["subject"].as_array_mut().unwrap() {
            let swapped = match subject["name"].as_str() {
                Some(ARM) => INTEL,
                Some(INTEL) => ARM,
                _ => continue,
            };
            subject["name"] = Value::String(swapped.to_owned());
        }
    });
    let intel = attested(INTEL);
    let asked = [FileSubject {
        name: ARM,
        digest: &intel,
    }];
    assert!(matches!(
        verify(&tampered, &asked, &config()),
        Err(AttestationError::Signature(_))
    ));
}

#[test]
fn another_predicate_is_refused() {
    // GitHub's `release` attestation names the same digests, and isn't provenance.
    let other = with_edited_statement(|statement| {
        statement["predicateType"] =
            Value::String("https://in-toto.io/attestation/release/v0.2".to_owned());
    });
    let arm = attested(ARM);
    let asked = [FileSubject {
        name: ARM,
        digest: &arm,
    }];
    assert!(matches!(
        verify(&other, &asked, &config()),
        Err(AttestationError::PredicateType { .. })
    ));
}

#[test]
fn oversized_bundle_is_refused() {
    // The real bundle, still valid JSON, so only its size can refuse it.
    let mut padded = BUNDLE.to_vec();
    padded.resize(MAX_BUNDLE_BYTES + 1, b' ');
    let arm = attested(ARM);
    let asked = [FileSubject {
        name: ARM,
        digest: &arm,
    }];
    let result = verify(&padded, &asked, &config());
    let Err(AttestationError::Bundle(message)) = result else {
        panic!("expected a malformed bundle, got {:?}", result.err());
    };
    assert!(message.contains("more than"), "{message}");
}

#[test]
fn a_wrong_file_and_no_file_are_refusals() {
    let wrong = AttestationError::FileSubject {
        name: ARM.to_owned(),
        expected: some_digest().to_string(),
        found: "\"other\"".to_owned(),
    };
    assert!(ReleaseError::Attestation(wrong).is_refusal());
    assert!(ReleaseError::Attestation(AttestationError::NoFileSubjects).is_refusal());
}
