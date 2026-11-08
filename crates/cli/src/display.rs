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
use serde_json::ser::{Formatter, PrettyFormatter};

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

/// Prints `value` as pretty JSON and a newline. `serde_json` already escapes C0 controls and
/// the backslash; DEL, C1, the bidi and line controls and the invisible ones are escaped too,
/// as `\uXXXX`, so the output parses back
/// to the same value and a terminal acts on none of it.
///
/// # Errors
///
/// What writing to `out` gives.
pub fn write_json(out: &mut dyn Write, value: &serde_json::Value) -> io::Result<()> {
    let mut serializer = serde_json::Serializer::with_formatter(&mut *out, Escaping::default());
    value.serialize(&mut serializer).map_err(io::Error::from)?;
    writeln!(out)
}

/// [`PrettyFormatter`], escaping what it leaves alone.
#[derive(Default)]
struct Escaping(PrettyFormatter<'static>);

impl Formatter for Escaping {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut rest = fragment;
        while let Some((at, c)) = rest.char_indices().find(|&(_, c)| is_dangerous(c)) {
            writer.write_all(&rest.as_bytes()[..at])?;
            // Every character escaped here is in the Basic Multilingual Plane: one `\uXXXX`.
            write!(writer, "\\u{:04x}", u32::from(c))?;
            rest = &rest[at + c.len_utf8()..];
        }
        writer.write_all(rest.as_bytes())
    }

    fn begin_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_array(writer)
    }

    fn end_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_array(writer)
    }

    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_array_value(writer)
    }

    fn begin_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_object(writer)
    }

    fn end_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_object(writer)
    }

    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_object_key(writer, first)
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_object_value(writer)
    }

    fn end_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_object_value(writer)
    }
}
