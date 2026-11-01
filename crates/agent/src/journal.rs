//! The host journal: one JSON object per line on stderr, with a `<N>` syslog
//! priority prefix, which journald reads with `SyslogLevelPrefix` (its
//! default). This is the only code in the agent that writes to stderr.
//!
//! An event carries the agent's own words and reasons that already quote and
//! truncate whatever a container said. JSON escapes newlines, so an event is
//! always one line.

use std::io::{self, Write};

use serde::Serialize;

/// How serious an event is, by syslog priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// A person has to act: a rollback failed.
    Critical,
    /// Something failed, and the agent dealt with it.
    Error,
    /// A deploy did not go through, and the previous version is back.
    Warning,
    /// The normal course of events.
    Info,
}

impl Priority {
    /// The syslog priority number.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Info => 6,
        }
    }
}

/// Writes `event` to the journal. A journal that cannot be written cannot be
/// told so, and must not stop a deploy or a rollback, so that failure is
/// dropped.
pub fn emit(priority: Priority, event: &impl Serialize) {
    let _ = write_line(&mut io::stderr().lock(), priority, event);
}

fn write_line(out: &mut impl Write, priority: Priority, event: &impl Serialize) -> io::Result<()> {
    let json = serde_json::to_vec(event).unwrap_or_else(|_| {
        // The priority still has to reach the journal if an event cannot be
        // serialised.
        br#"{"event":"journal_event_not_serialisable"}"#.to_vec()
    });
    let mut line = format!("<{}>", priority.code()).into_bytes();
    line.extend_from_slice(&json);
    line.push(b'\n');
    // One write, so that lines from other threads don't interleave.
    out.write_all(&line)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::ser::Error as _;
    use serde::{Serialize, Serializer};
    use serde_json::json;

    use super::{Priority, write_line};

    fn line(priority: Priority, event: &impl Serialize) -> String {
        let mut out = Vec::new();
        write_line(&mut out, priority, event).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_line_is_the_priority_and_one_json_object() {
        assert_eq!(
            line(Priority::Critical, &json!({"event": "x"})),
            "<2>{\"event\":\"x\"}\n"
        );
        assert_eq!(
            line(Priority::Info, &json!({})),
            "<6>{}\n",
            "journald reads the prefix as the priority"
        );
    }

    #[test]
    fn a_newline_in_a_reason_cannot_start_another_line() {
        let text = line(Priority::Error, &json!({"reason": "a\n<2>forged"}));
        assert_eq!(text.lines().count(), 1, "{text}");
    }

    #[test]
    fn priorities_are_the_syslog_numbers() {
        let codes = [
            Priority::Critical,
            Priority::Error,
            Priority::Warning,
            Priority::Info,
        ]
        .map(Priority::code);
        assert_eq!(codes, [2, 3, 4, 6]);
    }

    struct Unserialisable;

    impl Serialize for Unserialisable {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(S::Error::custom("no"))
        }
    }

    #[test]
    fn an_event_that_cannot_be_serialised_still_reaches_the_journal() {
        let text = line(Priority::Critical, &Unserialisable);
        assert!(text.starts_with("<2>{"), "{text}");
        let _: BTreeMap<String, String> = serde_json::from_str(&text[3..]).unwrap();
    }
}
