//! The file of signers: the same rows as `.github/scripts/test_release_signers.py`,
//! as the Python and the Rust parsers of it must not disagree.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::{OWNER_ID, ProjectError, REPO, REPO_ID, SIGNERS, WORKFLOW, parse_signers, signers};

/// RFC 8032's public keys, so neither is anybody's.
const RFC_KEY_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC_KEY_2: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

/// y = 2 is not the y of any point on the curve.
const NOT_ON_THE_CURVE: &str = "0200000000000000000000000000000000000000000000000000000000000000";

/// Each small-order point, in its canonical encoding: `SMALL_ORDER` in
/// `release_preflight_support.py`, where a test multiplies them out.
const SMALL_ORDER: [(&str, &str); 8] = [
    (
        "the identity",
        "0100000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "y = -1",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
    (
        "y = 0",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "y = 0, the other x",
        "0000000000000000000000000000000000000000000000000000000000000080",
    ),
    (
        "order 8",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    ),
    (
        "order 8, the other x",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ),
    (
        "order 8, the other y",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ),
    (
        "order 8, the other y and x",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ),
];

/// A y of p or more is another spelling of a smaller y; so is a sign on x = 0.
const NOT_CANONICAL: [(&str, &str); 5] = [
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
];

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

/// A public key in the SSH wire format.
fn wire(key: &[u8], key_type: &[u8], key_length: u32) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(&u32::try_from(key_type.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(key_type);
    wire.extend_from_slice(&key_length.to_be_bytes());
    wire.extend_from_slice(key);
    wire
}

fn line_of(key: &[u8]) -> String {
    let length = u32::try_from(key.len()).unwrap();
    format!(
        "ssh-ed25519 {}",
        STANDARD.encode(wire(key, b"ssh-ed25519", length))
    )
}

fn line(hex: &str) -> String {
    line_of(&bytes(hex))
}

fn good() -> String {
    line(RFC_KEY_1)
}

fn second() -> String {
    line(RFC_KEY_2)
}

fn encoded() -> String {
    good().split(' ').nth(1).unwrap().to_owned()
}

fn count(text: &str) -> usize {
    parse_signers(text).unwrap().len()
}

fn assert_refused(name: &str, text: &str) {
    let error = parse_signers(text).unwrap_err();
    assert!(
        matches!(
            error,
            ProjectError::Line { .. }
                | ProjectError::CarriageReturn
                | ProjectError::Repeated { .. }
        ),
        "{name}: {error:?}"
    );
}

#[test]
fn no_signers_refuses_and_says_why() {
    let spelled = "this build of landfall trusts no release-signing key, so it can't verify an \
                   agent: crates/cli/assets/release-signers holds no key. Use an official \
                   release of landfall, or see the guide for forks.";
    for text in ["", "\n", "\n\n", "# nothing yet\n", "#\n#c\n\n"] {
        let error = parse_signers(text).unwrap_err();
        assert_eq!(error, ProjectError::NoSigners, "{text:?}");
        assert_eq!(error.to_string(), spelled);
    }
}

#[test]
fn only_a_good_key_on_its_own_line_is_trusted() {
    assert_eq!(count(&format!("{}\n", good())), 1, "one key");
    assert_eq!(count(&good()), 1, "no final end of line");
    assert_refused("only blank lines", "\n\n  \n");
    assert_refused("a non-ed25519 key", &format!("ssh-rsa {}\n", encoded()));
    assert_refused("bad base64", "ssh-ed25519 !!!!\n");
    assert_refused(
        "a wrong length",
        &format!(
            "ssh-ed25519 {}\n",
            STANDARD.encode(wire(&bytes(RFC_KEY_1)[..31], b"ssh-ed25519", 31))
        ),
    );
}

#[test]
fn two_signers_are_both_trusted() {
    let text = format!("# the old key\n{}\n\n# the new key\n{}\n", good(), second());
    let keys = parse_signers(&text).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].0.to_string(), "release-1");
    assert_eq!(keys[1].0.to_string(), "release-2");
    assert_ne!(keys[0].1.fingerprint(), keys[1].1.fingerprint());
    let by_itself = parse_signers(&good()).unwrap();
    assert_eq!(keys[0].1, by_itself[0].1);
}

#[test]
fn trailing_comment_is_refused() {
    assert_refused(
        "a trailing comment",
        &format!("{} someone@example.invalid\n", good()),
    );
    assert_refused(
        "a comment after a key on the line",
        &format!("{} # the key\n", good()),
    );
}

#[test]
fn lines_that_only_nearly_hold_a_key_are_refused() {
    let (good, encoded) = (good(), encoded());
    for (name, text) in [
        ("the type alone", "ssh-ed25519\n".to_owned()),
        ("the key alone", format!("{encoded}\n")),
        ("a leading space", format!(" {good}\n")),
        ("two spaces", format!("ssh-ed25519  {encoded}\n")),
        ("a tab", format!("ssh-ed25519\t{encoded}\n")),
        ("a trailing space", format!("{good} \n")),
        ("a carriage return", format!("{good}\r\n")),
        ("a type in another case", format!("SSH-ED25519 {encoded}\n")),
        ("the same key twice", format!("{good}\n{good}\n")),
    ] {
        assert_refused(name, &text);
    }
}

/// A key hidden after any other separator is neither trusted nor let through.
#[test]
fn only_a_newline_ends_a_line() {
    let (key, stranger) = (good(), second());
    for (name, separator) in [
        ("a vertical tab", '\u{0B}'),
        ("a form feed", '\u{0C}'),
        ("a file separator", '\u{1C}'),
        ("a group separator", '\u{1D}'),
        ("a record separator", '\u{1E}'),
        ("a next line", '\u{85}'),
        ("a line separator", '\u{2028}'),
        ("a paragraph separator", '\u{2029}'),
    ] {
        assert_eq!(
            parse_signers(&format!("# old{separator}{key}\n")).unwrap_err(),
            ProjectError::NoSigners,
            "{name}: all one comment"
        );
        let error = parse_signers(&format!("{stranger}{separator}{key}\n")).unwrap_err();
        assert!(
            matches!(error, ProjectError::Line { line: 1, .. }),
            "{name}: {error:?}"
        );
    }
}

#[test]
fn blank_means_empty_and_a_comment_starts_the_line() {
    let good = good();
    for (name, stray) in [
        ("spaces", "   "),
        ("a tab", "\t"),
        ("an indented comment", " # old"),
        ("a file separator, which some trim as space", "\u{1C}"),
        ("a no-break space", "\u{A0}"),
    ] {
        assert_refused(name, &format!("{good}\n{stray}\n"));
    }
    assert_eq!(count(&format!("#\n#c\n\n{good}\n\n")), 1);
}

#[test]
fn wire_formats_that_are_not_an_ed25519_key_are_refused() {
    let key = bytes(RFC_KEY_1);
    let mut too_long = wire(&key, b"ssh-ed25519", 32);
    too_long.push(0);
    let mut too_short = wire(&key, b"ssh-ed25519", 32);
    too_short.pop();
    for (name, raw) in [
        ("another type in the bytes", wire(&key, b"ssh-ed25518", 32)),
        ("a key length that lies", wire(&key, b"ssh-ed25519", 31)),
        ("too long", too_long),
        ("too short", too_short),
    ] {
        assert_refused(name, &format!("ssh-ed25519 {}\n", STANDARD.encode(raw)));
    }
}

#[test]
fn base64_with_anything_more_is_refused() {
    let encoded = encoded();
    for (name, spelled) in [
        ("stray padding", format!("{encoded}=")),
        (
            "a character outside the alphabet",
            format!("{}!{}", &encoded[..10], &encoded[10..]),
        ),
        ("the URL-safe alphabet", encoded.replace('A', "-")),
        ("one character more", format!("{encoded}A")),
        (
            "one character less",
            encoded[..encoded.len() - 1].to_owned(),
        ),
    ] {
        // By the rule here, and not only by what the key's library happens to accept.
        let error = parse_signers(&format!("ssh-ed25519 {spelled}\n")).unwrap_err();
        assert!(error.to_string().contains("base64"), "{name}: {error}");
    }
}

#[test]
fn keys_of_small_order_are_refused() {
    for (name, hex) in SMALL_ORDER {
        let error = parse_signers(&format!("{}\n", line(hex))).unwrap_err();
        assert!(error.to_string().contains("small order"), "{name}: {error}");
    }
}

#[test]
fn keys_that_are_not_canonical_are_refused() {
    for (name, hex) in NOT_CANONICAL {
        let error = parse_signers(&format!("{}\n", line(hex))).unwrap_err();
        assert!(error.to_string().contains("canonical"), "{name}: {error}");
    }
}

#[test]
fn a_key_not_on_the_curve_is_refused() {
    let error = parse_signers(&format!("{}\n", line(NOT_ON_THE_CURVE))).unwrap_err();
    assert!(error.to_string().contains("not a point"), "{error}");
}

/// Strictness that refused a real key would be no use to anyone.
#[test]
fn a_key_from_ssh_keygen_passes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("key");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    let fields: Vec<&str> = public.split_whitespace().collect();
    let line = format!("{} {}\n", fields[0], fields[1]);
    assert_eq!(count(&line), 1, "{line}");
}

#[test]
fn a_carriage_return_anywhere_is_refused() {
    let (key, stranger) = (good(), second());
    for (name, text) in [
        ("a line ending in CRLF", format!("{key}\r\n")),
        (
            "a key after a CR on a comment line",
            format!("# old\r{key}\n"),
        ),
        ("two keys with a CR between", format!("{stranger}\r{key}\n")),
        (
            "a CR in a comment, beside a good key",
            format!("# old\r{stranger}\n{key}\n"),
        ),
        (
            "a blank line of a CR, beside a good key",
            format!("{key}\n\r\n"),
        ),
    ] {
        assert_eq!(
            parse_signers(&text).unwrap_err(),
            ProjectError::CarriageReturn,
            "{name}"
        );
    }
}

/// The real file, so a mistyped key fails here and not on every host: it holds comments
/// until the owner supplies a key, and good keys after.
#[test]
fn embedded_signers_parse_or_are_empty() {
    match signers() {
        Ok(keys) => assert_ne!(keys.len(), 0),
        Err(error) => assert_eq!(error, ProjectError::NoSigners),
    }
    assert!(!SIGNERS.contains('\r'));
}

#[test]
fn project_constants_match_the_workspace() {
    let repository = env!("CARGO_PKG_REPOSITORY");
    assert_eq!(repository.strip_prefix("https://github.com/"), Some(REPO));
    assert_eq!(WORKFLOW, ".github/workflows/release.yml");
    assert_ne!(REPO_ID, OWNER_ID);
    REPO.parse::<landfall_core::ids::RepoName>().unwrap();
}

/// The ids are what they say, against GitHub, as nothing else checks them.
#[tokio::test]
#[ignore = "needs the network"]
async fn live_project_ids_are_this_repository() {
    let client = reqwest::Client::builder()
        .user_agent("landfall-test")
        .build()
        .unwrap();
    let mut request = client.get(format!("https://api.github.com/repos/{REPO}"));
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        request = request.bearer_auth(token);
    }
    let body = request.send().await.unwrap().bytes().await.unwrap();
    let repository: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(repository["id"], REPO_ID, "{repository}");
    assert_eq!(repository["owner"]["id"], OWNER_ID, "{repository}");
    assert_eq!(repository["full_name"], REPO, "{repository}");
}
