//! What reaches a terminal: text from the controller is hostile, so every string it sent is
//! escaped before it is printed, in human output, in `--json` and on the error path.
//!
//! The escaped characters are those a terminal acts on or that reorder what it shows: C0
//! controls, DEL, C1 controls (`U+009B` alone starts a CSI on many terminals), and the bidi
//! and line controls: `U+061C`, `U+200E`, `U+200F`, `U+2028`, `U+2029`, `U+202A` to `U+202E`
//! and `U+2066` to `U+2069`.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{self, Write};

use serde::Serialize;
use serde_json::ser::{Formatter, PrettyFormatter};

#[cfg(test)]
mod tests;

/// Whether a terminal could act on `c`, or reorder what follows it, other than as text.
fn is_dangerous(c: char) -> bool {
    matches!(
        c,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{61c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// `text` with every character [`is_dangerous`] says, other than those `keep` says, written
/// as `\u{XX}`. Borrowed when there is none.
fn escaped(text: &str, keep: impl Fn(char) -> bool) -> Cow<'_, str> {
    let escape = |c: char| is_dangerous(c) && !keep(c);
    if !text.chars().any(escape) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if escape(c) {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// `text` for one line of a terminal: every control, including `\r` and `\n`, and every bidi
/// and line control, as `\u{XX}`.
#[must_use]
pub fn safe(text: &str) -> Cow<'_, str> {
    escaped(text, |_| false)
}

/// [`safe`], keeping `\n`, for text that is several lines on purpose.
#[must_use]
pub fn safe_lines(text: &str) -> Cow<'_, str> {
    escaped(text, |c| c == '\n')
}

/// The name `value` has on the wire, such as `not_found` or `token`, or `unknown` for one
/// from a newer controller, which has none.
pub(crate) fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unknown".to_owned(),
    }
}

/// Prints `value` as pretty JSON and a newline. `serde_json` already escapes C0 controls; DEL,
/// C1 and the bidi and line controls are escaped too, as `\uXXXX`, so the output parses back
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
