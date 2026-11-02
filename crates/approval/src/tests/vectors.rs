//! What a real browser sends. `vectors/README.md` says where this came from.

use landfall_core::intent::DeployIntent;
use serde::Deserialize;

use crate::{
    Algorithm, Assertion, AssertionError, ClientDataError, Expect, Registered, parse_registration,
    verify, wire,
};

const VECTORS: &str = include_str!("../../vectors/chromium.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct File {
    #[serde(rename = "source")]
    _source: String,
    pub(super) rp_id: String,
    pub(super) origin: String,
    #[serde(with = "wire")]
    pub(super) registration_challenge: Vec<u8>,
    pub(super) intent: DeployIntent,
    pub(super) credentials: Vec<Credential>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Credential {
    pub(super) algorithm: String,
    #[serde(with = "wire")]
    pub(super) attestation_object: Vec<u8>,
    #[serde(with = "wire")]
    pub(super) registration_client_data_json: Vec<u8>,
    pub(super) assertion: Assertion,
}

pub(super) fn load() -> File {
    serde_json::from_str(VECTORS).unwrap()
}

pub(super) fn registered(file: &File, credential: &Credential) -> Registered {
    parse_registration(
        &credential.attestation_object,
        &credential.registration_client_data_json,
        &file.rp_id,
        &file.origin,
        &file.registration_challenge,
    )
    .unwrap()
}

#[test]
fn real_browser_vectors_verify() {
    let file = load();
    let names: Vec<&str> = file
        .credentials
        .iter()
        .map(|c| c.algorithm.as_str())
        .collect();
    assert_eq!(names, ["ES256", "EdDSA"]);

    for credential in &file.credentials {
        let registered = registered(&file, credential);
        let algorithm = registered.key.algorithm().to_string();
        assert_eq!(algorithm, credential.algorithm);
        assert_eq!(
            matches!(registered.key.algorithm(), Algorithm::Es256),
            credential.algorithm == "ES256"
        );
        assert_eq!(credential.assertion.credential_id, registered.credential_id);
        verify(
            &credential.assertion,
            &Expect {
                key: &registered.key,
                credential_id: &registered.credential_id,
                rp_id: &file.rp_id,
                origin: &file.origin,
                // Recomputed here from the intent, as a host does.
                challenge: &file.intent.challenge(),
            },
        )
        .unwrap();
    }
}

#[test]
fn a_real_browser_assertion_does_not_verify_for_anything_else() {
    let file = load();
    for credential in &file.credentials {
        let registered = registered(&file, credential);
        let challenge = file.intent.challenge();
        let honest = Expect {
            key: &registered.key,
            credential_id: &registered.credential_id,
            rp_id: &file.rp_id,
            origin: &file.origin,
            challenge: &challenge,
        };
        verify(&credential.assertion, &honest).unwrap();

        let other_intent = DeployIntent {
            nonce: [8; 32],
            ..file.intent.clone()
        }
        .challenge();
        assert!(matches!(
            verify(
                &credential.assertion,
                &Expect {
                    challenge: &other_intent,
                    ..honest
                }
            ),
            Err(AssertionError::ClientData(
                ClientDataError::Challenge { .. }
            ))
        ));
        assert!(matches!(
            verify(
                &credential.assertion,
                &Expect {
                    origin: "https://other.example",
                    ..honest
                }
            ),
            Err(AssertionError::ClientData(ClientDataError::Origin { .. }))
        ));
        assert!(matches!(
            verify(
                &credential.assertion,
                &Expect {
                    rp_id: "example",
                    ..honest
                }
            ),
            Err(AssertionError::AuthenticatorData(_))
        ));
    }

    // Each credential's key against the other's signature.
    let first = registered(&file, &file.credentials[0]);
    let challenge = file.intent.challenge();
    assert_eq!(
        verify(
            &file.credentials[1].assertion,
            &Expect {
                key: &first.key,
                credential_id: &file.credentials[1].assertion.credential_id,
                rp_id: &file.rp_id,
                origin: &file.origin,
                challenge: &challenge,
            }
        ),
        Err(AssertionError::Signature)
    );
}
