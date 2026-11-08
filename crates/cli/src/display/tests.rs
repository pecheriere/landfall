//! Escaping what the controller says before a terminal sees it.

use std::borrow::Cow;

use serde_json::json;

use super::{safe, write_json};

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
        // Invisible characters that could hide one in a name.
        ("ad\u{ad}min", "ad\\u{ad}min"),
        (
            "a\u{200b}b\u{200c}c\u{200d}d",
            "a\\u{200b}b\\u{200c}c\\u{200d}d",
        ),
        ("\u{2060}", "\\u{2060}"),
        ("\u{feff}app/prod", "\\u{feff}app/prod"),
        // A backslash is doubled, so that text can't pass for an escape.
        ("\\u{1b}[31m", "\\\\u{1b}[31m"),
        ("C:\\x", "C:\\\\x"),
    ] {
        assert_eq!(safe(text), want, "{text:?}");
    }
    let plain = "déploiement réussi: app/prod v1.2.3 ✓";
    assert!(matches!(safe(plain), Cow::Borrowed(text) if text == plain));
}

#[test]
fn json_output_escapes_c1_del_and_bidi() {
    let value = json!({
        "title": "\u{9b}2J\x7f\u{202e}\x1b]0;x\x07\u{2028}é",
        "list": ["\u{2066}", 1, null, "\u{200b}\u{feff}\u{ad}\\"],
        "\u{85}key": true,
    });
    let mut out = Vec::new();
    write_json(&mut out, &value).unwrap();

    let text = String::from_utf8(out.clone()).unwrap();
    for forbidden in [
        '\u{9b}', '\u{7f}', '\u{202e}', '\u{1b}', '\u{7}', '\u{2028}', '\u{2066}', '\u{85}',
        '\u{200b}', '\u{feff}', '\u{ad}',
    ] {
        assert!(!text.contains(forbidden), "{forbidden:?} in {text}");
    }
    assert!(text.contains("\\u009b"), "{text}");
    assert!(text.contains("\\u202e"), "{text}");
    assert!(text.contains("\\u200b\\ufeff\\u00ad\\\\"), "{text}");
    assert!(text.contains('é'), "plain text stays as it is: {text}");
    assert!(
        text.ends_with("}\n"),
        "pretty, with a final newline: {text}"
    );
    assert!(text.contains("\n  \"list\""), "pretty: {text}");
    let back: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(back, value);
}
