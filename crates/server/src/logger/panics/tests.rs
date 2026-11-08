use std::ffi::OsStr;

use super::{NO_SYMBOLS, Style, frames};

/// A backtrace as `Backtrace` writes one from a panic hook, cut down.
const CAPTURED: &str = "   0: std::backtrace_rs::backtrace::libunwind::trace
             at /rustc/x/library/std/src/../../backtrace/src/backtrace/libunwind.rs:117:9
   1: <std::backtrace::Backtrace>::create
             at /rustc/x/library/std/src/backtrace.rs:331:13
   2: std::panicking::panic_with_hook
             at /rustc/x/library/std/src/panicking.rs:823:13
   3: std::sys::backtrace::__rust_end_short_backtrace::<std::panicking::panic_handler::{closure#0}, !>
             at /rustc/x/library/std/src/sys/backtrace.rs:182:18
   4: __rustc::rust_begin_unwind
             at /rustc/x/library/std/src/panicking.rs:679:5
   5: landfall_server::watcher::tick
             at ./crates/server/src/watcher.rs:10:5
   6: std::sys::backtrace::__rust_begin_short_backtrace::<fn(), ()>
             at /rustc/x/library/std/src/sys/backtrace.rs:166:18
   7: std::rt::lang_start_internal
";

#[test]
fn the_style_is_read_as_the_default_hook_reads_it() {
    for (value, style) in [
        (None, Style::Off),
        (Some("0"), Style::Off),
        (Some("full"), Style::Full),
        (Some("1"), Style::Short),
        (Some(""), Style::Short),
    ] {
        assert_eq!(Style::from_var(value.map(OsStr::new)), style, "{value:?}");
    }
}

#[test]
fn a_short_backtrace_is_the_code_that_panicked_one_frame_a_line() {
    assert_eq!(
        frames(CAPTURED, Style::Short),
        [
            "4: __rustc::rust_begin_unwind at /rustc/x/library/std/src/panicking.rs:679:5",
            "5: landfall_server::watcher::tick at ./crates/server/src/watcher.rs:10:5",
        ]
    );
}

#[test]
fn a_full_backtrace_is_every_frame_one_a_line() {
    let frames = frames(CAPTURED, Style::Full);
    assert_eq!(frames.len(), 8, "{frames:?}");
    assert_eq!(
        frames[5],
        "5: landfall_server::watcher::tick at ./crates/server/src/watcher.rs:10:5"
    );
    assert_eq!(frames[7], "7: std::rt::lang_start_internal");
}

/// Without the markers, as on a thread std didn't start, a short backtrace keeps everything.
#[test]
fn a_short_backtrace_without_its_markers_keeps_every_frame() {
    let unmarked = "   0: a\n             at a.rs:1:1\n   1: b\n";
    assert_eq!(frames(unmarked, Style::Short), ["0: a at a.rs:1:1", "1: b"]);
}

/// A stripped build, as releases are, names no frame: rather than a line of nothing each, it says
/// so once.
#[test]
fn a_backtrace_with_no_symbols_says_so_once() {
    let stripped = "   0: <unknown>\n   1: <unknown>\n   2: <unknown>\n";
    for style in [Style::Short, Style::Full] {
        assert_eq!(frames(stripped, style), [NO_SYMBOLS], "{style:?}");
    }
    let mac = "   0: __mh_execute_header\n   1: __mh_execute_header\n";
    assert_eq!(frames(mac, Style::Short), [NO_SYMBOLS]);
}

/// Frames with no symbol among those with one are left out.
#[test]
fn frames_with_no_symbol_are_left_out() {
    let partly = "   0: <unknown>\n   1: landfall_server::watcher::tick\n             at ./w.rs:1:1\n   \
                  2: <unknown>\n";
    assert_eq!(
        frames(partly, Style::Full),
        ["1: landfall_server::watcher::tick at ./w.rs:1:1"]
    );
}
