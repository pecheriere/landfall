//! What parsing refuses, and the problem codes.

use serde_json::Value;

use super::super::{
    DeployReportBody, EnrolRequest, ProblemCode, ReportedCheck, ReportedDetail, ReportedStep,
    WorkRequest, WorkResponse,
};
use super::identity_key_bytes;
use super::wire::{all_outcomes, enrol, report, step, work_request, work_response};
use crate::hex;

#[test]
fn null_keys_must_be_present() {
    let mut wire = serde_json::to_value(WorkResponse {
        work: None,
        held_back: Vec::new(),
    })
    .unwrap();
    assert!(wire["work"].is_null());
    wire.as_object_mut().unwrap().remove("work");
    assert!(serde_json::from_value::<WorkResponse>(wire).is_err());

    let mut wire = serde_json::to_value(step(None, None)).unwrap();
    assert!(wire["failure"].is_null());
    wire.as_object_mut().unwrap().remove("failure");
    assert!(serde_json::from_value::<ReportedStep>(wire).is_err());
}

#[test]
fn unknown_fields_are_refused() {
    fn refuses<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) {
        let mut v = serde_json::to_value(value).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), Value::Null);
        assert!(serde_json::from_value::<T>(v).is_err());
    }
    refuses(&work_request());
    refuses(&work_response());
    refuses(&report());
    refuses(&enrol());
    for (outcome, _) in all_outcomes() {
        refuses(&outcome);
    }

    // And in nested values.
    let mut v = serde_json::to_value(work_response()).unwrap();
    v["work"]["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<WorkResponse>(v).is_err());
    let mut v = serde_json::to_value(work_request()).unwrap();
    v["running"][0]["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<WorkRequest>(v).is_err());
    let mut v = serde_json::to_value(work_request()).unwrap();
    v["running"][0]["deployed"]["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<WorkRequest>(v).is_err());
    let mut v = serde_json::to_value(report()).unwrap();
    v["steps"][0]["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<DeployReportBody>(v).is_err());
    let mut v = serde_json::to_value(report()).unwrap();
    v["steps"][0]["detail"]["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<DeployReportBody>(v).is_err());
}

#[test]
fn hostile_values_are_refused() {
    let mut v = serde_json::to_value(work_response()).unwrap();
    v["work"]["tag"] = Value::String("v1\n".to_owned());
    assert!(serde_json::from_value::<WorkResponse>(v).is_err());
    let mut v = serde_json::to_value(work_request()).unwrap();
    v["config_hash"] = Value::String("05".repeat(31));
    assert!(serde_json::from_value::<WorkRequest>(v).is_err());
    let mut v = serde_json::to_value(enrol()).unwrap();
    v["public_key"] = Value::String("00".repeat(31));
    assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
    let mut v = serde_json::to_value(enrol()).unwrap();
    v["code"] = Value::String("5E".repeat(32));
    assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
    let mut v = serde_json::to_value(enrol()).unwrap();
    v["code"] = Value::String("x".to_owned());
    assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
}

#[test]
fn a_weak_enrolment_key_is_refused() {
    let mut v = serde_json::to_value(enrol()).unwrap();
    v["public_key"] = Value::String(hex::encode(&identity_key_bytes()));
    assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
}

#[test]
fn the_number_of_checks_is_not_limited_at_parse() {
    let check = ReportedCheck {
        check: "c".to_owned(),
        attempts: 1,
        millis: 1,
    };
    let detail = ReportedDetail::Checks {
        checks: vec![check; 1000],
    };
    let wire = serde_json::to_value(&detail).unwrap();
    assert_eq!(
        serde_json::from_value::<ReportedDetail>(wire).unwrap(),
        detail
    );
}

/// Pinned: a client decides by these, so a change is a wire change.
#[test]
fn problem_codes_are_pinned_with_what_to_do_about_them() {
    use super::super::Disposition::{Final, Retry};
    for (code, text, disposition) in [
        (ProblemCode::Unsigned, "unsigned", Final),
        (ProblemCode::BadNonce, "bad_nonce", Retry),
        (ProblemCode::BadSignature, "bad_signature", Final),
        (ProblemCode::InvalidCode, "invalid_code", Final),
        (ProblemCode::AlreadyEnrolled, "already_enrolled", Final),
        (ProblemCode::KeyInUse, "key_in_use", Final),
        (ProblemCode::BadRequest, "bad_request", Final),
        (ProblemCode::BodyTooLarge, "body_too_large", Final),
        (ProblemCode::SlowRequest, "slow_request", Retry),
        (ProblemCode::RateLimited, "rate_limited", Retry),
        (ProblemCode::NoncesExhausted, "nonces_exhausted", Retry),
        (ProblemCode::Busy, "busy", Retry),
        (ProblemCode::UnknownDeploy, "unknown_deploy", Final),
        (ProblemCode::NotClaimed, "not_claimed", Final),
        (ProblemCode::Internal, "internal", Retry),
    ] {
        assert_eq!(code.as_str(), text);
        assert_eq!(ProblemCode::parse(text), Some(code));
        assert_eq!(code.disposition(), disposition, "{text}");
    }
    assert_eq!(ProblemCode::parse("nonsense"), None);
}
