//! What a signature covers, and what it refuses.

pub use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use super::super::{Nonce, RequestSignature, SignatureError, sign, signing_bytes, verify};
use super::{host, identity_key_bytes, key, nonce};
use crate::hex;
use crate::ids::HostId;

#[test]
fn signature_covers_host_method_path_nonce_and_body() {
    let k = key(1);
    let h = host("host-a");
    let sig = sign(&k, &h, "POST", "/agent/v1/work", &nonce(2), b"{}");
    let public = k.verifying_key();
    assert_eq!(
        verify(
            &public,
            &sig,
            &h,
            "POST",
            "/agent/v1/work",
            &nonce(2),
            b"{}"
        ),
        Ok(())
    );
    let other = host("host-b");
    let cases: [(&HostId, &str, &str, Nonce, &[u8]); 6] = [
        (&other, "POST", "/agent/v1/work", nonce(2), b"{}"),
        (&h, "GET", "/agent/v1/work", nonce(2), b"{}"),
        (&h, "POST", "/agent/v1/report", nonce(2), b"{}"),
        (&h, "POST", "/agent/v1/work?a=1", nonce(2), b"{}"),
        (&h, "POST", "/agent/v1/work", nonce(3), b"{}"),
        (&h, "POST", "/agent/v1/work", nonce(2), b"{ }"),
    ];
    for (host, method, path, n, body) in cases {
        assert_eq!(
            verify(&public, &sig, host, method, path, &n, body),
            Err(SignatureError::Invalid),
            "{host} {method} {path} {n} {body:?}"
        );
    }
}

#[test]
fn signing_bytes_has_a_pinned_layout() {
    let mut expected = Vec::new();
    let mut field = |bytes: &[u8]| {
        expected.extend_from_slice(&u64::try_from(bytes.len()).unwrap().to_be_bytes());
        expected.extend_from_slice(bytes);
    };
    field(b"landfall-agent-v1");
    field(b"host-a");
    field(b"POST");
    field(b"/agent/v1/work");
    field(&[7; 32]);
    field(&Sha256::digest(b"body"));
    assert_eq!(
        signing_bytes(
            &host("host-a"),
            "POST",
            "/agent/v1/work",
            &nonce(7),
            b"body"
        ),
        expected
    );
}

#[test]
fn signing_bytes_cannot_be_confused_across_fields() {
    let h = host("host-a");
    let n = nonce(9);
    let body = b"x";
    let mut seen = vec![signing_bytes(&h, "GET", "/a", &n, body)];
    // Newlines, and text that looks like the neighbouring field, moved
    // across every boundary.
    let attempts = [
        ("GET\n/a", ""),
        ("GET", "/a\n"),
        ("GET\n", "/a"),
        ("GET", "/a\n/b"),
        ("", "GET\n/a"),
        ("GET/a", ""),
    ];
    for (method, path) in attempts {
        let bytes = signing_bytes(&h, method, path, &n, body);
        assert!(!seen.contains(&bytes), "{method:?} {path:?}");
        seen.push(bytes);
    }
    // A path that spells out the nonce and body hash cannot stand in for
    // the real fields.
    let forged_path = format!("/a\n{n}\n{}", hex::encode(&Sha256::digest(body)));
    let bytes = signing_bytes(&h, "GET", &forged_path, &nonce(0), b"");
    assert!(!seen.contains(&bytes));
    // Nor can the host id and the method trade bytes.
    let bytes = signing_bytes(&host("host-ag"), "ET", "/a", &n, body);
    assert!(!seen.contains(&bytes));
}

#[test]
fn signature_from_another_key_is_refused() {
    let h = host("h");
    let sig = sign(&key(1), &h, "GET", "/p", &nonce(1), b"");
    assert_eq!(
        verify(
            &key(2).verifying_key(),
            &sig,
            &h,
            "GET",
            "/p",
            &nonce(1),
            b""
        ),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn a_weak_key_with_a_trivial_signature_is_refused() {
    // The identity point as key and as R, with s = 0, satisfies the plain
    // Ed25519 equation for every message. Strict verification refuses it.
    let weak = VerifyingKey::from_bytes(&identity_key_bytes()).unwrap();
    assert!(weak.is_weak());
    let mut raw = [0_u8; 64];
    raw[..32].copy_from_slice(&identity_key_bytes());
    let sig = RequestSignature::from_bytes(raw);
    assert_eq!(
        verify(&weak, &sig, &host("h"), "GET", "/p", &nonce(1), b""),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn a_non_canonical_scalar_is_refused() {
    // s + L is the same scalar modulo the group order, so a lax verifier
    // accepts a second encoding of every signature.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let k = key(3);
    let h = host("h");
    let sig = sign(&k, &h, "GET", "/p", &nonce(1), b"");
    let public = k.verifying_key();
    assert_eq!(
        verify(&public, &sig, &h, "GET", "/p", &nonce(1), b""),
        Ok(())
    );

    let mut raw = *sig.as_bytes();
    let mut carry = 0_u16;
    for (s, l) in raw[32..].iter_mut().zip(L) {
        let sum = u16::from(*s) + u16::from(l) + carry;
        *s = u8::try_from(sum & 0xff).unwrap();
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        verify(
            &public,
            &RequestSignature::from_bytes(raw),
            &h,
            "GET",
            "/p",
            &nonce(1),
            b""
        ),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn signature_and_nonce_round_trip_through_their_text_form() {
    let sig = sign(&key(1), &host("h"), "GET", "/p", &nonce(1), b"");
    let text = sig.to_string();
    assert_eq!(text.len(), 128);
    assert_eq!(text.parse::<RequestSignature>(), Ok(sig));
    assert_eq!(nonce(0xab).to_string(), "ab".repeat(32));
    assert_eq!("ab".repeat(32).parse::<Nonce>(), Ok(nonce(0xab)));
    for bad in [
        "",
        "AB",
        &"ab".repeat(31),
        &"ab".repeat(33),
        &"zz".repeat(32),
    ] {
        assert!(bad.parse::<Nonce>().is_err(), "{bad:?}");
    }
    assert!("ab".repeat(63).parse::<RequestSignature>().is_err());
}
