//! Escaping what the controller says before a terminal sees it.

use std::borrow::Cow;

use serde_json::json;

use super::{safe, safe_lines, write_json};

#[test]
fn safe_escapes_controls_and_bidi() {
    for (text, want) in [
        ("\x1b[31m", "\\u{1b}[31m"),
        ("\u{9b}31m", "\\u{9b}31m"),
        ("a\rb", "a\\u{d}b"),
        ("a\nb", "a\\u{a}b"),
        ("\u{202e}gpj.exe", "\\u{202e}gpj.exe"),
        ("\u{2066}x\u{2069}", "\\u{2066}x\\u{2069}"),
        ("\u{200f}", "\\u{200f}"),
        ("\u{2028}", "\\u{2028}"),
        ("\u{61c}", "\\u{61c}"),
        ("\x07", "\\u{7}"),
        ("\x7f", "\\u{7f}"),
        ("\0", "\\u{0}"),
    ] {
        assert_eq!(safe(text), want, "{text:?}");
    }
    let plain = "déploiement réussi: app/prod v1.2.3 ✓";
    assert!(matches!(safe(plain), Cow::Borrowed(text) if text == plain));
}

#[test]
fn safe_lines_keeps_newlines_and_escapes_carriage_returns() {
    assert_eq!(
        safe_lines("first\nsecond\r\nthird\x1b[2K"),
        "first\nsecond\\u{d}\nthird\\u{1b}[2K"
    );
    assert!(matches!(safe_lines("a\nb"), Cow::Borrowed("a\nb")));
}

#[test]
fn json_output_escapes_c1_del_and_bidi() {
    let value = json!({
        "title": "\u{9b}2J\x7f\u{202e}\x1b]0;x\x07\u{2028}é",
        "list": ["\u{2066}", 1, null],
        "\u{85}key": true,
    });
    let mut out = Vec::new();
    write_json(&mut out, &value).unwrap();

    let text = String::from_utf8(out.clone()).unwrap();
    for forbidden in [
        '\u{9b}', '\u{7f}', '\u{202e}', '\u{1b}', '\u{7}', '\u{2028}', '\u{2066}', '\u{85}',
    ] {
        assert!(!text.contains(forbidden), "{forbidden:?} in {text}");
    }
    assert!(text.contains("\\u009b"), "{text}");
    assert!(text.contains("\\u202e"), "{text}");
    assert!(text.contains('é'), "plain text stays as it is: {text}");
    assert!(
        text.ends_with("}\n"),
        "pretty, with a final newline: {text}"
    );
    assert!(text.contains("\n  \"list\""), "pretty: {text}");
    let back: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(back, value);
}
