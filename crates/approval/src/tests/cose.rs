use crate::cose::{encode_eddsa, encode_es256};
use crate::{Algorithm, CoseError, CoseKey};

/// The P-256 base point, a valid key no one needs to hold.
const P256_X: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_Y: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];
/// The public key of RFC 8032's first test vector.
const ED25519_X: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fn es256() -> Vec<u8> {
    encode_es256(&P256_X, &P256_Y)
}

fn eddsa() -> Vec<u8> {
    encode_eddsa(&ED25519_X)
}

/// CBOR for a map: the entry count, then the given encoded labels and values.
fn map(entries: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0xa0 | u8::try_from(entries.len() / 2).unwrap()];
    for entry in entries {
        out.extend_from_slice(entry);
    }
    out
}

/// CBOR for a byte string of up to 255 bytes.
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x58, u8::try_from(value.len()).unwrap()];
    out.extend_from_slice(value);
    out
}

#[test]
fn both_algorithms_parse() {
    let key = CoseKey::parse(&es256()).unwrap();
    assert_eq!(key.algorithm(), Algorithm::Es256);
    assert_eq!(key.as_bytes(), es256());
    let key = CoseKey::parse(&eddsa()).unwrap();
    assert_eq!(key.algorithm(), Algorithm::EdDsa);
    assert_eq!(key.as_bytes(), eddsa());
}

#[test]
fn fingerprint_is_the_hash_of_the_encoding() {
    // Pinned: an operator compares this, so it doesn't change. Computed separately
    // with Python's hashlib over the same bytes.
    assert_eq!(
        CoseKey::parse(&es256()).unwrap().fingerprint(),
        "SHA256:cggOF4d8f+ELEF6kDupHSXWhbPd3PAN0WqZMAltqTmM"
    );
    assert_eq!(
        CoseKey::parse(&eddsa()).unwrap().fingerprint(),
        "SHA256:2tysiLu3Ugl6kKiNB66D9sKs/dXCAFXtCmW3pt02G84"
    );
}

#[test]
fn curve_point_off_the_curve_is_refused() {
    let mut y = P256_Y;
    y[31] ^= 1;
    for (x, y) in [
        (P256_X, y),
        ([0; 32], [0; 32]),
        // Beyond the field's prime.
        ([0xff; 32], [0xff; 32]),
    ] {
        assert_eq!(
            CoseKey::parse(&encode_es256(&x, &y)),
            Err(CoseError::NotOnCurve)
        );
    }

    // 2 is a y with no x on edwards25519.
    let mut y = [0; 32];
    y[0] = 2;
    assert_eq!(
        CoseKey::parse(&encode_eddsa(&y)),
        Err(CoseError::NotOnCurve)
    );
}

#[test]
fn small_order_ed25519_keys_are_refused() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut negative_identity = [0xff; 32];
    negative_identity[0] = 0xec;
    negative_identity[31] = 0x7f;
    let order_eight = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ];
    for x in [identity, negative_identity, [0; 32], order_eight] {
        assert_eq!(CoseKey::parse(&encode_eddsa(&x)), Err(CoseError::WeakKey));
    }
}

#[test]
fn unknown_algorithm_is_refused() {
    // RS256's real shape, whose -1 and -2 are bytes rather than a curve and x: what
    // matters to the person reading the error is the algorithm.
    let rs256 = map(&[
        &[0x01],
        &[0x03],
        &[0x03],
        &[0x39, 0x01, 0x00],
        &[0x20],
        &bytes(&[0xaa; 200]),
        &[0x21],
        &bytes(&[0x01, 0x00, 0x01]),
    ]);
    assert_eq!(
        CoseKey::parse(&rs256),
        Err(CoseError::UnsupportedAlgorithm(-257))
    );

    let mut es384 = es256();
    es384[4] = 0x38;
    es384.insert(5, 0x22);
    assert_eq!(
        CoseKey::parse(&es384),
        Err(CoseError::UnsupportedAlgorithm(-35))
    );

    let no_algorithm = map(&[
        &[0x01],
        &[0x01],
        &[0x20],
        &[0x06],
        &[0x21],
        &bytes(&ED25519_X),
    ]);
    assert_eq!(
        CoseKey::parse(&no_algorithm),
        Err(CoseError::MissingParameter("alg"))
    );
}

#[test]
fn a_key_type_or_curve_that_does_not_fit_the_algorithm_is_refused() {
    let mut key = es256();
    key[2] = 0x01;
    assert_eq!(
        CoseKey::parse(&key),
        Err(CoseError::KeyType {
            expected: 2,
            found: 1
        })
    );
    // ES256 on P-384: COSE allows it, WebAuthn doesn't.
    let mut key = es256();
    key[6] = 0x02;
    assert_eq!(
        CoseKey::parse(&key),
        Err(CoseError::Curve {
            expected: 1,
            found: 2
        })
    );
    let mut key = eddsa();
    key[2] = 0x02;
    assert_eq!(
        CoseKey::parse(&key),
        Err(CoseError::KeyType {
            expected: 1,
            found: 2
        })
    );
    // Ed448's curve.
    let mut key = eddsa();
    key[6] = 0x07;
    assert_eq!(
        CoseKey::parse(&key),
        Err(CoseError::Curve {
            expected: 6,
            found: 7
        })
    );
}

#[test]
fn duplicate_labels_are_refused() {
    let key = map(&[
        &[0x01],
        &[0x01],
        &[0x03],
        &[0x27],
        &[0x20],
        &[0x06],
        &[0x21],
        &bytes(&ED25519_X),
        &[0x21],
        &bytes(&[0; 32]),
    ]);
    assert_eq!(CoseKey::parse(&key), Err(CoseError::DuplicateLabel(-2)));
}

#[test]
fn parameters_webauthn_forbids_are_refused() {
    // 6.5.1: nothing but alg and what the key type requires. A `kid`, and a private
    // key, which an operator must never be able to paste into a configuration.
    let with_kid = map(&[
        &[0x01],
        &[0x01],
        &[0x02],
        &bytes(b"kid"),
        &[0x03],
        &[0x27],
        &[0x20],
        &[0x06],
        &[0x21],
        &bytes(&ED25519_X),
    ]);
    assert_eq!(
        CoseKey::parse(&with_kid),
        Err(CoseError::UnexpectedParameter(2))
    );
    let with_private = map(&[
        &[0x01],
        &[0x01],
        &[0x03],
        &[0x27],
        &[0x20],
        &[0x06],
        &[0x21],
        &bytes(&ED25519_X),
        &[0x23],
        &bytes(&[0x11; 32]),
    ]);
    assert_eq!(
        CoseKey::parse(&with_private),
        Err(CoseError::UnexpectedParameter(-4))
    );
    // An OKP key has no y.
    let with_y = map(&[
        &[0x01],
        &[0x01],
        &[0x03],
        &[0x27],
        &[0x20],
        &[0x06],
        &[0x21],
        &bytes(&ED25519_X),
        &[0x22],
        &bytes(&[0x11; 32]),
    ]);
    assert_eq!(
        CoseKey::parse(&with_y),
        Err(CoseError::UnexpectedParameter(-3))
    );
}

#[test]
fn parameters_webauthn_forbids_are_refused_on_es256_too() {
    let with_private = map(&[
        &[0x01],
        &[0x02],
        &[0x03],
        &[0x26],
        &[0x20],
        &[0x01],
        &[0x21],
        &bytes(&P256_X),
        &[0x22],
        &bytes(&P256_Y),
        &[0x23],
        &bytes(&[0x11; 32]),
    ]);
    assert_eq!(
        CoseKey::parse(&with_private),
        Err(CoseError::UnexpectedParameter(-4))
    );
}

#[test]
fn a_compressed_point_is_refused() {
    for sign in [0xf4, 0xf5] {
        let key = map(&[
            &[0x01],
            &[0x02],
            &[0x03],
            &[0x26],
            &[0x20],
            &[0x01],
            &[0x21],
            &bytes(&P256_X),
            &[0x22],
            &[sign],
        ]);
        assert_eq!(CoseKey::parse(&key), Err(CoseError::CompressedPoint));
    }
}

#[test]
fn a_missing_or_short_coordinate_is_refused() {
    let no_y = map(&[
        &[0x01],
        &[0x02],
        &[0x03],
        &[0x26],
        &[0x20],
        &[0x01],
        &[0x21],
        &bytes(&P256_X),
    ]);
    assert_eq!(CoseKey::parse(&no_y), Err(CoseError::MissingParameter("y")));
    let no_x = map(&[&[0x01], &[0x01], &[0x03], &[0x27], &[0x20], &[0x06]]);
    assert_eq!(CoseKey::parse(&no_x), Err(CoseError::MissingParameter("x")));
    let short = map(&[
        &[0x01],
        &[0x01],
        &[0x03],
        &[0x27],
        &[0x20],
        &[0x06],
        &[0x21],
        &bytes(&ED25519_X[..31]),
    ]);
    assert_eq!(
        CoseKey::parse(&short),
        Err(CoseError::CoordinateLength {
            name: "x",
            found: 31
        })
    );
    let long_y = map(&[
        &[0x01],
        &[0x02],
        &[0x03],
        &[0x26],
        &[0x20],
        &[0x01],
        &[0x21],
        &bytes(&P256_X),
        &[0x22],
        &bytes(&[0x11; 33]),
    ]);
    assert_eq!(
        CoseKey::parse(&long_y),
        Err(CoseError::CoordinateLength {
            name: "y",
            found: 33
        })
    );
}

#[test]
fn non_canonical_encodings_of_a_valid_key_are_refused() {
    let x = bytes(&ED25519_X);
    let noncanonical: &[Vec<u8>] = &[
        // Labels out of order: alg before kty, and x before crv.
        map(&[
            &[0x03],
            &[0x27],
            &[0x01],
            &[0x01],
            &[0x20],
            &[0x06],
            &[0x21],
            &x,
        ]),
        map(&[
            &[0x01],
            &[0x01],
            &[0x03],
            &[0x27],
            &[0x21],
            &x,
            &[0x20],
            &[0x06],
        ]),
        // A label, a value, a length, and the map's own count, each longer than needed.
        map(&[
            &[0x18, 0x01],
            &[0x01],
            &[0x03],
            &[0x27],
            &[0x20],
            &[0x06],
            &[0x21],
            &x,
        ]),
        map(&[
            &[0x01],
            &[0x18, 0x01],
            &[0x03],
            &[0x27],
            &[0x20],
            &[0x06],
            &[0x21],
            &x,
        ]),
        map(&[
            &[0x01],
            &[0x01],
            &[0x03],
            &[0x27],
            &[0x20],
            &[0x06],
            &[0x21],
            &[&[0x59, 0x00, 0x20][..], &ED25519_X].concat(),
        ]),
        [&[0xb8, 0x04][..], &eddsa()[1..]].concat(),
        // An indefinite-length map.
        [&[0xbf][..], &eddsa()[1..], &[0xff]].concat(),
    ];
    for key in noncanonical {
        assert_eq!(
            CoseKey::parse(key),
            Err(CoseError::NotCanonical),
            "{key:02x?}"
        );
    }
}

#[test]
fn bytes_after_the_key_are_refused() {
    for mut key in [es256(), eddsa()] {
        key.push(0x00);
        assert_eq!(CoseKey::parse(&key), Err(CoseError::TrailingBytes(1)));
    }
}

#[test]
fn a_map_with_too_many_entries_is_refused_before_reading_them() {
    // Seventeen distinct labels: past the cap the count is refused, before the scan
    // for duplicates, which would otherwise grow with the square of what was sent.
    let mut key = vec![0xb1];
    for label in 0..17 {
        key.extend_from_slice(&[label, 0x00]);
    }
    assert_eq!(
        CoseKey::parse(&key),
        Err(CoseError::Malformed("17 parameters".to_owned()))
    );
}
