//! Reading a file of checksums.

use super::super::{FileError, parse_sums};
use super::{REAL_FILE, REAL_SUMS, REAL_SUMS_NAME};

#[test]
fn sums_are_read_strictly() {
    let sum = "a".repeat(64);
    assert_eq!(
        parse_sums(format!("{sum}  x\n").as_bytes()).unwrap().len(),
        1
    );
    assert_eq!(
        parse_sums(format!("{sum}  x\n{sum}  y\n").as_bytes())
            .unwrap()
            .len(),
        2,
        "two names may have one sum"
    );
    assert_eq!(
        parse_sums(format!("{sum}  a  b\n").as_bytes()).unwrap()["a  b"].to_string(),
        format!("sha256:{sum}")
    );

    for (name, text) in [
        ("empty", String::new()),
        ("only a newline", "\n".to_owned()),
        ("no final end of line", format!("{sum}  x")),
        ("a blank line", format!("{sum}  x\n\n")),
        ("a CRLF", format!("{sum}  x\r\n")),
        ("one space", format!("{sum} x\n")),
        ("a tab", format!("{sum}\tx\n")),
        (
            "sha256sum's binary mode spelled with one space",
            format!("{sum} *x\n"),
        ),
        ("no name", format!("{sum}  \n")),
        ("upper case", format!("{}  x\n", "A".repeat(64))),
        ("too short", format!("{}  x\n", "a".repeat(63))),
        ("too long", format!("{}  x\n", "a".repeat(65))),
        ("not hex", format!("{}  x\n", "g".repeat(64))),
        ("a prefix", format!("sha256:{sum}  x\n")),
        ("a leading space", format!(" {sum}  x\n")),
        (
            "a control character in the name",
            format!("{sum}  x\u{1b}\n"),
        ),
    ] {
        let error = parse_sums(text.as_bytes()).unwrap_err();
        assert!(
            matches!(error, FileError::SumsMalformed { .. }),
            "{name}: {error:?}"
        );
        assert!(error.is_refusal(), "{name}");
    }

    assert!(matches!(
        parse_sums(b"\xff  x\n").unwrap_err(),
        FileError::SumsMalformed { .. }
    ));
    let twice = format!("{sum}  x\n{}  x\n", "b".repeat(64));
    assert!(matches!(
        parse_sums(twice.as_bytes()).unwrap_err(),
        FileError::SumsDuplicate { .. }
    ));
}

#[test]
fn a_real_file_of_checksums_is_read() {
    let sums = parse_sums(REAL_SUMS).unwrap();
    assert_eq!(sums.len(), 11);
    assert!(!sums.contains_key(REAL_SUMS_NAME));
    assert!(sums.contains_key(REAL_FILE));
}
