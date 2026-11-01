//! Showing untrusted text in error messages.

/// Quotes `text` for an error message (Rust debug quoting, so control
/// characters are escaped), shortened to 64 characters followed by `...` so
/// a hostile value cannot flood a log line.
pub(crate) fn shown(text: &str) -> String {
    const MAX: usize = 64;
    let cut: String = text.chars().take(MAX).collect();
    if cut.len() < text.len() {
        format!("{cut:?}...")
    } else {
        format!("{cut:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::shown;

    #[test]
    fn quotes_escapes_and_truncates() {
        assert_eq!(shown("tree"), "\"tree\"");
        assert_eq!(shown("a\nb"), "\"a\\nb\"");
        let long = "x".repeat(65);
        assert_eq!(shown(&long), format!("\"{}\"...", "x".repeat(64)));
        assert_eq!(shown(&long[..64]), format!("\"{}\"", "x".repeat(64)));
    }
}
