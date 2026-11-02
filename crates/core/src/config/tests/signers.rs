//! Signer keys, and when signed tags are required.

use super::super::ConfigError;
use super::{EXAMPLE, edited, fixture_key, id, parse_str, with_signer};
use crate::ids::PrincipalId;

#[test]
fn signer_keys_are_parsed() {
    let config = parse_str(EXAMPLE).unwrap();
    let maintainer: PrincipalId = "maintainer".parse().unwrap();
    let key = config.signer(&maintainer).unwrap();
    assert_eq!(
        key.fingerprint(),
        "SHA256:aN9xB/PG8u3ubV37qOIeOe3nPDkWfAzfFl+We+g5ASA"
    );
    assert!(config.signer(&"nobody".parse().unwrap()).is_none());

    // The comment is ignored: the same key with one is the same key.
    let commented = with_signer(&format!(
        "{} laptop key",
        fixture_key("signer.pub").trim_end()
    ));
    let other = parse_str(&commented).unwrap();
    assert_eq!(other.signer(&maintainer), Some(key));
}

#[test]
fn non_ed25519_signer_is_rejected() {
    let err = parse_str(&with_signer(&fixture_key("ecdsa.pub"))).unwrap_err();
    let ConfigError::InvalidSigner { signer, reason } = &err else {
        panic!("{err}");
    };
    assert_eq!(signer.to_string(), "maintainer");
    assert!(reason.contains("ecdsa-sha2-nistp256"), "{reason}");
}

#[test]
fn garbage_signer_is_rejected() {
    for garbage in [
        "",
        "not a key",
        "ssh-ed25519",
        "ssh-ed25519 AAAA",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly",
    ] {
        let err = parse_str(&with_signer(garbage)).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidSigner { signer, .. } if signer.to_string() == "maintainer"),
            "{garbage:?}: {err}"
        );
    }
}

#[test]
fn duplicate_signer_keys_are_rejected() {
    let key = fixture_key("signer.pub");
    let text = EXAMPLE.replacen(
        "[approval]",
        &format!(
            "backup = {:?}\n\n[approval]",
            format!("{} spare", key.trim_end())
        ),
        1,
    );
    assert_eq!(
        parse_str(&text).unwrap_err(),
        ConfigError::DuplicateSignerKey {
            first: "backup".parse().unwrap(),
            second: "maintainer".parse().unwrap(),
        }
    );
}

#[test]
fn signed_tags_defaults_to_true() {
    let config = parse_str(EXAMPLE).unwrap();
    let prod = config.deployment(&id("app/prod")).unwrap();
    assert!(prod.origin().signed_tags());
}

#[test]
fn unsigned_deployment_needs_no_signers() {
    let text = edited(
        "tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
        "tags = \"v*\", signed_tags = false }\nrule = { auto = \"patch\"",
    );
    let config = parse_str(&text).unwrap();
    let prod = config.deployment(&id("app/prod")).unwrap();
    assert!(!prod.origin().signed_tags());
    assert_eq!(prod.origin().signers(), &[]);
    // An explicit empty list is accepted too.
    let explicit = edited(
        "tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
        "tags = \"v*\", signed_tags = false, signers = [] }\nrule = { auto = \"patch\"",
    );
    assert!(parse_str(&explicit).is_ok());
    // signed_tags on (the default) still needs signers.
    let err = parse_str(&edited(
        "signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
        "signed_tags = true }\nrule = { auto = \"patch\"",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::NoSigners(_)), "{err}");
}

#[test]
fn signers_with_signed_tags_off_is_rejected() {
    let err = parse_str(&edited(
        "signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
        "signers = [\"maintainer\"], signed_tags = false }\nrule = { auto = \"patch\"",
    ))
    .unwrap_err();
    assert_eq!(err, ConfigError::SignersWithoutSignedTags(id("app/prod")));
}
