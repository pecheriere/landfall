//! Showing untrusted text in error messages.

/// Quotes `text` for an error message (Rust debug quoting, so control
/// characters are escaped), shortened to 64 characters followed by `...` so
/// a hostile value cannot flood a log line.
#[must_use]
pub fn shown(text: &str) -> String {
    quoted(text, 64)
}

/// Quotes `text` as [`shown`] does, shortened to `max_chars` characters: for
/// keeping untrusted text where more of it is worth the room.
#[must_use]
pub fn quoted(text: &str, max_chars: usize) -> String {
    let cut: String = text.chars().take(max_chars).collect();
    if cut.len() < text.len() {
        format!("{cut:?}...")
    } else {
        format!("{cut:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::{quoted, shown};

    #[test]
    fn quoted_keeps_what_it_is_asked_to() {
        assert_eq!(quoted("a\nbcd", 3), "\"a\\nb\"...");
        assert_eq!(quoted("abc", 3), "\"abc\"");
    }

    #[test]
    fn quotes_escapes_and_truncates() {
        assert_eq!(shown("tree"), "\"tree\"");
        assert_eq!(shown("a\nb"), "\"a\\nb\"");
        let long = "x".repeat(65);
        assert_eq!(shown(&long), format!("\"{}\"...", "x".repeat(64)));
        assert_eq!(shown(&long[..64]), format!("\"{}\"", "x".repeat(64)));
    }
}
