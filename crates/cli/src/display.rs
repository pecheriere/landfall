//! What reaches a terminal: text from the controller is hostile, so every string it sent is
//! escaped before it is printed, in human output, in `--json` and on the error path.
//!
//! The escaped characters are those a terminal acts on, that reorder what it shows, or that
//! show as nothing: C0 controls, DEL, C1 controls (`U+009B` alone starts a CSI on many
//! terminals), the bidi and line controls (`U+061C`, `U+200E`, `U+200F`, `U+2028`, `U+2029`,
//! `U+202A` to `U+202E` and `U+2066` to `U+2069`), and the invisible ones (`U+00AD`, `U+200B`
//! to `U+200D`, `U+2060` and `U+FEFF`), which could hide a character in a name. In human
//! output a backslash is doubled too, so that hostile text can't pass for an escape.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{self, Write};

use serde::Serialize;

#[cfg(test)]
mod tests;

/// Whether a terminal could act on `c`, reorder what follows it, or show it as nothing.
fn is_dangerous(c: char) -> bool {
    matches!(
        c,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{ad}'
            | '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// `text` for one line of a terminal: every character the module names, `\r` and `\n`
/// included, as `\u{XX}`, and a backslash as `\\`, so that what looks like an escape is
/// one. Borrowed when there is nothing to escape.
#[must_use]
pub fn safe(text: &str) -> Cow<'_, str> {
    let escape = |c: char| c == '\\' || is_dangerous(c);
    if !text.chars().any(escape) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if is_dangerous(c) {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// The name `value` has on the wire, such as `not_found` or `token`, or `unknown` for one
/// from a newer controller, which has none.
pub(crate) fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unknown".to_owned(),
    }
}

/// Prints `json`, the text of one JSON value as the controller sent it, pretty, and a newline.
/// It is never parsed into a tree, so its keys, numbers and order stay as received. Escapes in
/// its strings are kept as they are; DEL, C1, the bidi and line controls and the invisible
/// characters, which JSON lets a string hold raw, are escaped as `\uXXXX`. So the output
/// parses back to the same value and a terminal acts on none of it.
///
/// `json` must be one JSON value, as [`crate::api_client::ApiClient::get`] checks it to be;
/// anything else is printed escaped, but not as JSON.
///
/// # Errors
///
/// What writing to `out` gives.
pub fn write_json(out: &mut dyn Write, json: &str) -> io::Result<()> {
    // Written as it goes, so that nothing the size of the pretty text is held: indenting a
    // deeply nested answer can make it far larger than the answer.
    let mut out = io::BufWriter::new(out);
    let mut depth = 0usize;
    let mut chars = json.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                out.write_all(b"\"")?;
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            // An escape is ASCII: its first character decides where it ends,
                            // and the hex digits of `\uXXXX` follow as ordinary characters.
                            out.write_all(b"\\")?;
                            if let Some(escaped) = chars.next() {
                                write_char(&mut out, escaped)?;
                            }
                        }
                        '"' => {
                            out.write_all(b"\"")?;
                            break;
                        }
                        c => write_char(&mut out, c)?,
                    }
                }
            }
            '{' | '[' => {
                while chars.next_if(char::is_ascii_whitespace).is_some() {}
                let close = if c == '{' { '}' } else { ']' };
                write_char(&mut out, c)?;
                if chars.next_if_eq(&close).is_some() {
                    write_char(&mut out, close)?;
                } else {
                    depth += 1;
                    new_line(&mut out, depth)?;
                }
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                new_line(&mut out, depth)?;
                write_char(&mut out, c)?;
            }
            ',' => {
                out.write_all(b",")?;
                new_line(&mut out, depth)?;
            }
            ':' => out.write_all(b": ")?,
            ' ' | '\t' | '\n' | '\r' => {}
            c => write_char(&mut out, c)?,
        }
    }
    out.write_all(b"\n")?;
    out.flush()
}

/// `c`, or `\uXXXX` if a terminal could act on it.
fn write_char(out: &mut impl Write, c: char) -> io::Result<()> {
    if is_dangerous(c) {
        // Every character escaped here is in the Basic Multilingual Plane: one `\uXXXX`.
        write!(out, "\\u{:04x}", u32::from(c))
    } else {
        out.write_all(c.encode_utf8(&mut [0; 4]).as_bytes())
    }
}

/// A line break, and two spaces for each level of `depth`.
fn new_line(out: &mut impl Write, depth: usize) -> io::Result<()> {
    out.write_all(b"\n")?;
    for _ in 0..depth {
        out.write_all(b"  ")?;
    }
    Ok(())
}
