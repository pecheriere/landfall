//! The subject digest, tampering and downgraded bundles.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use landfall_core::ids::ImageDigest;
use serde_json::Value;

use super::super::{AttestationError, MAX_BUNDLE_BYTES, verify_bundle};
use super::{BUNDLE, Config, REKOR_LOG_INDEX, digest, edited_bundle, root, verify};

#[test]
fn wrong_digest_is_refused() {
    let other: ImageDigest = format!("sha256:{}", "ab".repeat(32)).parse().unwrap();
    let config = Config::fixture();
    let result = verify_bundle(BUNDLE, &other, &root(), &config.expected());
    assert_eq!(
        result,
        Err(AttestationError::Subject {
            expected: other.to_string(),
            found: digest().to_string(),
        })
    );
}

#[test]
fn tampered_bundle_is_refused() {
    let config = Config::fixture();

    let signature = edited_bundle(|b| {
        let sig = &mut b["dsseEnvelope"]["signatures"][0]["sig"];
        let mut text = sig.as_str().unwrap().to_owned();
        let flipped = if text.as_bytes()[20] == b'A' {
            "B"
        } else {
            "A"
        };
        text.replace_range(20..21, flipped);
        *sig = Value::String(text);
    });
    assert!(
        matches!(
            verify(&signature, &config),
            Err(AttestationError::Signature(_))
        ),
        "flipped signature character"
    );

    let payload = edited_bundle(|b| {
        let field = &mut b["dsseEnvelope"]["payload"];
        let mut bytes = STANDARD.decode(field.as_str().unwrap()).unwrap();
        // A byte inside the predicate, so the statement still parses and
        // still names the right subject: only the signature can catch it.
        let at = bytes
            .windows(b"\"predicate\"".len())
            .position(|w| w == b"\"predicate\"")
            .unwrap();
        let letter = at
            + bytes[at..]
                .iter()
                .position(|b| b.is_ascii_lowercase() && *b != b'p')
                .unwrap();
        bytes[letter] ^= 0x01;
        *field = Value::String(STANDARD.encode(bytes));
    });
    assert!(
        matches!(
            verify(&payload, &config),
            Err(AttestationError::Signature(_))
        ),
        "flipped payload byte"
    );

    let no_proof = edited_bundle(|b| {
        b["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionProof")
            .unwrap();
    });
    assert!(
        matches!(verify(&no_proof, &config), Err(AttestationError::Bundle(_))),
        "inclusion proof dropped"
    );

    let no_promise = edited_bundle(|b| {
        b["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionPromise")
            .unwrap();
    });
    assert!(
        matches!(
            verify(&no_promise, &config),
            Err(AttestationError::Bundle(_))
        ),
        "inclusion promise dropped"
    );

    let other_log_index = edited_bundle(|b| {
        b["verificationMaterial"]["tlogEntries"][0]["logIndex"] =
            Value::String((REKOR_LOG_INDEX + 1).to_string());
    });
    assert!(
        matches!(
            verify(&other_log_index, &config),
            Err(AttestationError::Signature(_))
        ),
        "log index changed"
    );
}

/// The fixture bundle relabelled as bundle format v0.1, which does not
/// require an inclusion proof. The media type is not signed.
fn downgraded_bundle(drop_proof: bool) -> Vec<u8> {
    edited_bundle(|b| {
        b["mediaType"] =
            Value::String("application/vnd.dev.sigstore.bundle+json;version=0.1".to_owned());
        if drop_proof {
            b["verificationMaterial"]["tlogEntries"][0]
                .as_object_mut()
                .unwrap()
                .remove("inclusionProof")
                .unwrap();
        }
    })
}

#[test]
fn downgraded_media_type_without_proof_is_refused() {
    let config = Config::fixture();
    assert!(matches!(
        verify(&downgraded_bundle(true), &config),
        Err(AttestationError::Bundle(_))
    ));
}

#[test]
fn downgraded_media_type_is_refused() {
    let config = Config::fixture();
    assert!(matches!(
        verify(&downgraded_bundle(false), &config),
        Err(AttestationError::Bundle(_))
    ));
}

#[test]
fn garbage_is_refused() {
    let config = Config::fixture();
    for input in [&b""[..], b"{}", &vec![b'['; MAX_BUNDLE_BYTES]] {
        assert!(
            matches!(verify(input, &config), Err(AttestationError::Bundle(_))),
            "{} bytes",
            input.len()
        );
    }
}
