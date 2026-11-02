//! The certificate identity: each claim that must match.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::super::{AttestationError, CertificateIdentity, match_identity, verify_bundle};
use super::{
    BUNDLE, Case, Config, INTEGRATED_TIME, OWNER_ID, REKOR_LOG_INDEX, REPO_ID, RUN_URL, SAN,
    digest, edited_bundle, fixture_identity, mismatched_field, root, verify,
};

#[test]
fn real_bundle_verifies() {
    let config = Config::fixture();
    let verified = verify_bundle(BUNDLE, &digest(), &root(), &config.expected()).unwrap();

    assert_eq!(verified.digest, digest());
    assert_eq!(verified.san, SAN);
    assert_eq!(verified.commit, config.commit);
    assert_eq!(verified.git_ref, "refs/tags/1.37.4");
    assert_eq!(verified.repo_id, REPO_ID);
    assert_eq!(verified.owner_id, OWNER_ID);
    assert_eq!(verified.run_url, RUN_URL);
    assert_eq!(verified.rekor_log_index, REKOR_LOG_INDEX);
    assert_eq!(verified.integrated_time, INTEGRATED_TIME);
}

#[test]
fn a_time_the_log_vouches_for_ahead_of_the_clock_is_the_clock_and_nothing_else_is() {
    let bundle = super::super::parse_bundle(BUNDLE).unwrap();
    let time = jiff::Timestamp::from_second(INTEGRATED_TIME).unwrap();
    let earlier = time - jiff::SignedDuration::from_secs(1);
    let integrated = || {
        sigstore_verify::Error::from(super::super::TransparencyLogError::IntegratedTime(
            "no".into(),
        ))
    };

    // Behind the release, the error can only be about the clock.
    assert!(matches!(
        super::super::refused_verification(&integrated(), &bundle, earlier),
        AttestationError::ClockBehind(_)
    ));
    // Past it, this is a time outside the certificate's validity: final.
    assert!(matches!(
        super::super::refused_verification(&integrated(), &bundle, time),
        AttestationError::Signature(_)
    ));
    // And no other failure is the clock's, whatever the clock says.
    let other = sigstore_verify::Error::from(super::super::TransparencyLogError::InclusionProof(
        "no".into(),
    ));
    assert!(matches!(
        super::super::refused_verification(&other, &bundle, earlier),
        AttestationError::Signature(_)
    ));
}

#[test]
fn repo_name_is_compared_case_insensitively() {
    let mut config = Config::fixture();
    config.repo = "Dani-Garcia/VaultWarden".parse().unwrap();
    assert_eq!(verify(BUNDLE, &config), Ok(()));
}

#[test]
fn each_identity_mismatch_is_named() {
    let cases: [Case; 6] = [
        (
            "repo id",
            |c| c.repo_id = REPO_ID + 1,
            "source_repository_identifier",
        ),
        (
            "owner id",
            |c| c.owner_id = OWNER_ID + 1,
            "source_repository_owner_identifier",
        ),
        (
            "workflow",
            |c| c.workflow = ".github/workflows/docker.yml".to_owned(),
            "san",
        ),
        (
            "tag",
            |c| c.tag = "1.37.3".parse().unwrap(),
            "source_repository_ref",
        ),
        (
            "commit",
            |c| c.commit = "0000000000000000000000000000000000000000".parse().unwrap(),
            "source_repository_digest",
        ),
        (
            "repo name",
            |c| c.repo = "dani-garcia/vaultwardem".parse().unwrap(),
            "san",
        ),
    ];
    for (name, change, field) in cases {
        let mut config = Config::fixture();
        change(&mut config);
        assert_eq!(
            mismatched_field(verify(BUNDLE, &config)),
            field,
            "wrong {name}"
        );
    }
}

#[test]
fn fixture_identity_matches() {
    let config = Config::fixture();
    let identity = fixture_identity();
    let matched = match_identity(&identity, &config.expected()).unwrap();
    assert_eq!(
        (matched.san, matched.git_ref, matched.run_url),
        (SAN, "refs/tags/1.37.4", RUN_URL)
    );
}

#[test]
fn manual_trigger_is_refused() {
    let config = Config::fixture();
    let identity = CertificateIdentity {
        build_trigger: Some("workflow_dispatch".to_owned()),
        ..fixture_identity()
    };
    assert_eq!(
        match_identity(&identity, &config.expected()),
        Err(AttestationError::Identity {
            field: "build_trigger",
            expected: "push".to_owned(),
            found: "workflow_dispatch".to_owned(),
        })
    );
}

#[test]
fn self_hosted_runner_is_refused() {
    let config = Config::fixture();
    let identity = CertificateIdentity {
        runner_environment: Some("self-hosted".to_owned()),
        ..fixture_identity()
    };
    assert_eq!(
        mismatched_field(match_identity(&identity, &config.expected())),
        "runner_environment"
    );
}

#[test]
fn other_issuer_is_refused() {
    let config = Config::fixture();
    let identity = CertificateIdentity {
        issuer: Some("https://issuer.example".to_owned()),
        ..fixture_identity()
    };
    assert_eq!(
        mismatched_field(match_identity(&identity, &config.expected())),
        "issuer"
    );
}

#[test]
fn reusable_workflow_call_is_refused() {
    // The configured workflow signed, but another workflow called it.
    let config = Config::fixture();
    let identity = CertificateIdentity {
        build_config_uri: Some(SAN.replace("release.yml", "caller.yml")),
        ..fixture_identity()
    };
    assert_eq!(
        mismatched_field(match_identity(&identity, &config.expected())),
        "build_config_uri"
    );
}

#[test]
fn missing_claim_is_refused() {
    let config = Config::fixture();
    let identity = CertificateIdentity {
        source_repository_identifier: None,
        ..fixture_identity()
    };
    assert_eq!(
        mismatched_field(match_identity(&identity, &config.expected())),
        "source_repository_identifier"
    );
}

#[test]
fn san_with_a_suffix_is_refused() {
    let config = Config::fixture();
    let identity = CertificateIdentity {
        san: Some(format!("{SAN}x")),
        ..fixture_identity()
    };
    assert_eq!(
        mismatched_field(match_identity(&identity, &config.expected())),
        "san"
    );
}

#[test]
fn other_predicate_type_is_refused() {
    let config = Config::fixture();
    let sbom = edited_bundle(|b| {
        let payload = &mut b["dsseEnvelope"]["payload"];
        let mut statement: Value =
            serde_json::from_slice(&STANDARD.decode(payload.as_str().unwrap()).unwrap()).unwrap();
        statement["predicateType"] = Value::from("https://spdx.dev/Document/v2.3");
        *payload = Value::from(STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
    });
    assert_eq!(
        verify(&sbom, &config),
        Err(AttestationError::PredicateType {
            expected: "https://slsa.dev/provenance/v1".to_owned(),
            found: "https://spdx.dev/Document/v2.3".to_owned(),
        })
    );
}
