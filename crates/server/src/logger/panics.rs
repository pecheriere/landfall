//! Panics while serving, sent to the log rather than written to stderr by the panicking thread,
//! where a stuck stderr would block it.

use std::backtrace::{Backtrace, BacktraceStatus};
use std::ffi::OsStr;

use super::log;

/// How much of a backtrace a panic gets, as the default hook decides it from `RUST_BACKTRACE`:
/// `0` or unset for none, `full` for every frame, and anything else for the frames of the code that
/// panicked, without the runtime's and the panic machinery's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Off,
    Short,
    Full,
}

impl Style {
    fn from_var(value: Option<&OsStr>) -> Self {
        match value {
            None => Self::Off,
            Some(value) if value == "0" => Self::Off,
            Some(value) if value == "full" => Self::Full,
            Some(_) => Self::Short,
        }
    }
}

/// From here on, what a panic says goes to the log: its thread, place and message on one line, and
/// then, when `RUST_BACKTRACE` asks for one as the default hook reads it, the backtrace one frame a
/// line, so that each is escaped and cut short on its own. The rest of what a panic does is
/// unchanged.
pub(crate) fn log_panics() {
    let style = Style::from_var(std::env::var_os("RUST_BACKTRACE").as_deref());
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let thread = thread.name().unwrap_or("<unnamed>");
        let location = info
            .location()
            .map_or_else(|| "an unknown place".to_owned(), ToString::to_string);
        let message = info.payload_as_str().unwrap_or("with no message");
        log(&format!(
            "thread '{thread}' panicked at {location}: {message}"
        ));
        if style == Style::Off {
            return;
        }
        let backtrace = Backtrace::force_capture();
        if backtrace.status() == BacktraceStatus::Captured {
            for frame in frames(&backtrace.to_string(), style) {
                log(&format!("backtrace: {frame}"));
            }
        }
    }));
}

/// A backtrace as [`Backtrace`] writes it, one frame a line with where it is, and with
/// [`Style::Short`] only the frames between the panic machinery and the start of the thread, as
/// the default hook shows them.
fn frames(backtrace: &str, style: Style) -> Vec<String> {
    let mut frames: Vec<String> = Vec::new();
    for line in backtrace.lines().map(str::trim) {
        match frames.last_mut() {
            Some(frame) if line.starts_with("at ") => {
                frame.push(' ');
                frame.push_str(line);
            }
            _ if !line.is_empty() => frames.push(line.to_owned()),
            _ => {}
        }
    }
    if style == Style::Short {
        if let Some(end) = frames
            .iter()
            .position(|frame| frame.contains("__rust_end_short_backtrace"))
        {
            frames.drain(..=end);
        }
        if let Some(begin) = frames
            .iter()
            .position(|frame| frame.contains("__rust_begin_short_backtrace"))
        {
            frames.truncate(begin);
        }
    }
    frames
}

#[cfg(test)]
mod tests;
