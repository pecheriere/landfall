//! Lets a test act at a point where a racing container could, so that what a
//! race would do happens every time. Compiled out of production.

use std::cell::RefCell;
use std::ffi::CStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Point {
    /// A source entry has been seen with `lstat` and is about to be opened.
    LstatToOpen,
    /// A symlink has been created and its metadata is about to be set.
    SymlinkCreated,
    /// A removal has read a name and is about to open it.
    RemovalOpen,
    /// A removal is about to move a directory up.
    MoveUp,
}

type Hook = Box<dyn FnMut(Point, &CStr)>;

thread_local! {
    // Per thread, as each test runs on its own and others run alongside.
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

pub(super) fn set(hook: impl FnMut(Point, &CStr) + 'static) {
    HOOK.set(Some(Box::new(hook)));
}

pub(super) fn run(point: Point, name: &CStr) {
    HOOK.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(point, name);
        }
    });
}
