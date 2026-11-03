//! Signer keys, and when signed tags are required.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::super::ConfigError;
use super::super::signer::SignerKey;
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

/// The key's OpenSSH line, for these 32 bytes.
fn key_line(key: &[u8; 32]) -> String {
    let mut wire = Vec::new();
    wire.extend_from_slice(&11_u32.to_be_bytes());
    wire.extend_from_slice(b"ssh-ed25519");
    wire.extend_from_slice(&32_u32.to_be_bytes());
    wire.extend_from_slice(key);
    format!("ssh-ed25519 {}", STANDARD.encode(wire))
}

/// 32 bytes from 64 hex digits.
fn bytes(hex: &str) -> [u8; 32] {
    let mut key = [0_u8; 32];
    for (at, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).unwrap();
    }
    key
}

/// Every point of small order, in its canonical encoding, as
/// `.github/scripts/release_preflight_support.py` lists them and checks them by
/// the arithmetic. For each, anyone can forge a signature.
fn small_order_points() -> Vec<(&'static str, [u8; 32])> {
    const ONE: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const MINUS_ONE: &str = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_SIGN: &str = "0000000000000000000000000000000000000000000000000000000000000080";
    const ORDER_8: &str = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05";
    const ORDER_8_SIGN: &str = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85";
    const OTHER_8: &str = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";
    const OTHER_8_SIGN: &str = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa";
    [
        ("the identity", ONE),
        ("y = -1", MINUS_ONE),
        ("y = 0", ZERO),
        ("y = 0, the other x", ZERO_SIGN),
        ("order 8", ORDER_8),
        ("order 8, the other x", ORDER_8_SIGN),
        ("order 8, the other y", OTHER_8),
        ("order 8, the other y and x", OTHER_8_SIGN),
    ]
    .into_iter()
    .map(|(name, hex)| (name, bytes(hex)))
    .collect()
}

/// Issue 36: for such a key a tag can be forged with no secret, and `verify_tag`
/// would accept it, so it must not load.
#[test]
fn a_signer_of_small_order_is_rejected_and_named() {
    for (name, key) in small_order_points() {
        let err = parse_str(&with_signer(&key_line(&key))).unwrap_err();
        let ConfigError::InvalidSigner { signer, reason } = &err else {
            panic!("{name}: {err}");
        };
        assert_eq!(signer.to_string(), "maintainer", "{name}");
        assert!(reason.contains("small order"), "{name}: {reason}");
    }
}

/// A y of p or more is another spelling of a smaller y, and so is a sign on x = 0.
#[test]
fn a_signer_key_that_is_not_canonical_is_rejected() {
    for (name, hex) in [
        (
            "y = p",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            "y = p + 1",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            "y = 2^255 - 1",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            "a sign on x = 0 at y = 1",
            "0100000000000000000000000000000000000000000000000000000000000080",
        ),
        (
            "a sign on x = 0 at y = -1",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ] {
        let err = SignerKey::parse(&key_line(&bytes(hex))).unwrap_err();
        assert!(err.contains("canonical"), "{name}: {err}");
    }
}

#[test]
fn a_signer_key_not_on_the_curve_is_rejected() {
    let mut key = [0_u8; 32];
    key[0] = 2;
    let err = SignerKey::parse(&key_line(&key)).unwrap_err();
    assert!(err.contains("not a point"), "{err}");
}

#[test]
fn a_good_signer_key_still_passes() {
    // RFC 8032's first test vector, so it is nobody's.
    let good = bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    SignerKey::parse(&key_line(&good)).unwrap();
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
