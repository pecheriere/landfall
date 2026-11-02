//! A configuration, loaded through the real check on approver keys.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use landfall_core::config::{Config, ConfigError};

use super::{CHALLENGE, ORIGIN, RP_ID, authenticators, ceremony};
use crate::cose::{encode_eddsa, encode_es256};
use crate::{Algorithm, CoseKey, Expect, parse_config, verify};

/// The public key of RFC 8032's first test vector, a key no one needs to hold.
const ED25519_X: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
/// The P-256 base point.
const P256_X: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_Y: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn config_with(credential_id: &[u8], key: &[u8]) -> String {
    format!(
        "[approval]\nrp_id = {RP_ID:?}\norigin = {ORIGIN:?}\n\n\
         [approvers]\noperator = {{ credential_id = {:?}, public_key = {:?} }}\n",
        base64url(credential_id),
        base64url(key),
    )
}

fn load(key: &[u8]) -> Result<Config, ConfigError> {
    parse_config(config_with(b"credential", key).as_bytes())
}

/// The reason `key` was refused, which has to be about the operator's approver.
fn refusal(key: &[u8]) -> String {
    match load(key) {
        Err(ConfigError::InvalidApprover { approver, reason }) => {
            assert_eq!(approver.to_string(), "operator");
            reason
        }
        other => panic!("{key:02x?} was not refused: {other:?}"),
    }
}

#[test]
fn both_algorithms_load_as_the_bytes_the_verifier_reads() {
    for (key, algorithm) in [
        (encode_es256(&P256_X, &P256_Y), Algorithm::Es256),
        (encode_eddsa(&ED25519_X), Algorithm::EdDsa),
    ] {
        let config = load(&key).unwrap();
        let approver = config.approver(&"operator".parse().unwrap()).unwrap();
        assert_eq!(approver.public_key(), key);
        assert_eq!(approver.credential_id(), b"credential");
        let parsed = CoseKey::parse(approver.public_key()).unwrap();
        assert_eq!(parsed.algorithm(), algorithm);
    }
}

/// The whole path a key takes: a passkey registers, the operator copies the result into
/// the file, the host loads the file and verifies an approval with what it read.
#[test]
fn a_registered_key_loads_and_verifies() {
    for authenticator in authenticators() {
        let attestation = authenticator.attestation(&ceremony());
        let registered = crate::parse_registration(
            &attestation.attestation_object,
            &attestation.client_data_json,
            RP_ID,
            ORIGIN,
            &CHALLENGE,
        )
        .unwrap();
        let text = config_with(&registered.credential_id, registered.key.as_bytes());
        let config = parse_config(text.as_bytes()).unwrap();

        let approval = config.approval().unwrap();
        let approver = config.approver(&"operator".parse().unwrap()).unwrap();
        let key = CoseKey::parse(approver.public_key()).unwrap();
        let assertion = authenticator.assertion(&ceremony()).unwrap();
        verify(
            &assertion,
            &Expect {
                key: &key,
                credential_id: approver.credential_id(),
                rp_id: approval.rp_id(),
                origin: approval.origin(),
                challenge: &CHALLENGE,
            },
        )
        .unwrap();
    }
}

#[test]
fn approver_key_must_parse() {
    let es256 = encode_es256(&P256_X, &P256_Y);
    let eddsa = encode_eddsa(&ED25519_X);
    let mut off_curve = P256_Y;
    off_curve[31] ^= 1;
    // The Ed25519 identity, a point of small order.
    let mut identity = [0; 32];
    identity[0] = 1;
    // y = 3 + p, a second spelling of the point at y = 3.
    let mut beyond_prime = [0xff; 32];
    beyond_prime[0] = 0xf0;
    beyond_prime[31] = 0x7f;
    // The labels of an ES256 key in the wrong order.
    let mut reordered = vec![0xa5, 0x03, 0x26, 0x01, 0x02];
    reordered.extend_from_slice(&es256[5..]);
    let mut with_trailing_byte = eddsa.clone();
    with_trailing_byte.push(0);
    // An EdDSA key that also carries its private part, label -4.
    let mut with_private_part = eddsa.clone();
    with_private_part[0] = 0xa5;
    with_private_part.extend_from_slice(&[0x23, 0x41, 0x00]);

    for (bad, reason) in [
        (vec![], "malformed"),
        (vec![0xff; 16], "malformed"),
        (eddsa[..eddsa.len() - 1].to_vec(), "malformed"),
        (es256[..40].to_vec(), "malformed"),
        (encode_es256(&P256_X, &off_curve), "not a point"),
        (encode_es256(&[0; 32], &[0; 32]), "not a point"),
        (encode_eddsa(&identity), "small order"),
        (
            encode_eddsa(&beyond_prime),
            "canonical encoding of its point",
        ),
        (reordered, "not in the canonical encoding"),
        (with_trailing_byte, "follow the COSE key"),
        (with_private_part, "unexpected label -4"),
    ] {
        let found = refusal(&bad);
        assert!(found.contains(reason), "{bad:02x?}: {found}");
    }
}

#[test]
fn unsupported_algorithm_names_the_approver() {
    // RS256: {1: 3, 3: -257, -1: h'01', -2: h'03'}.
    let rs256 = [
        0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x41, 0x01, 0x21, 0x41, 0x03,
    ];
    // ES384: {1: 2, 3: -35, ...}, whose coordinates the algorithm is refused before.
    let es384 = [0xa2, 0x01, 0x02, 0x03, 0x38, 0x22];
    for (key, algorithm) in [(&rs256[..], "-257"), (&es384[..], "-35")] {
        let err = load(key).unwrap_err().to_string();
        assert!(err.contains("operator"), "{err}");
        assert!(err.contains(algorithm), "{err}");
        assert!(err.contains("ES256") && err.contains("EdDSA"), "{err}");
    }
}

#[test]
fn a_refusal_never_shows_the_key() {
    let mut key = encode_es256(&P256_X, &P256_Y);
    let last = key.len() - 1;
    key[last] ^= 1;
    let encoded = base64url(&key);
    let err = load(&key).unwrap_err().to_string();
    assert!(err.contains("operator"), "{err}");
    assert!(!err.contains(&encoded), "{err}");
    assert!(!err.contains(&encoded[..16]), "{err}");
    assert!(!err.contains(&STANDARD_NO_PAD.encode(&key)), "{err}");
}

/// What the configuration guide shows has to load, against the real check.
#[test]
fn the_documented_example_loads() {
    let guide = include_str!("../../../../docs/configuration.md");
    let (_, rest) = guide.split_once("```toml\n").unwrap();
    let (example, _) = rest.split_once("```").unwrap();
    let config = parse_config(example.as_bytes()).unwrap();
    assert!(config.approval().is_some());
    assert_ne!(config.deployments(), []);
}
