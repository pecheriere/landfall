//! Where the cache goes, and which token is used.

use std::ffi::OsString;
use std::path::PathBuf;

use super::{AccessError, default_cache_dir, github_token};

#[test]
fn github_token_is_used_only_when_set_and_non_empty() {
    assert!(github_token(None).unwrap().is_none());
    assert!(github_token(Some(OsString::new())).unwrap().is_none());
    assert_eq!(
        github_token(Some(OsString::from("t0ken")))
            .unwrap()
            .as_deref(),
        Some("t0ken")
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_github_token_is_an_error_that_does_not_show_it() {
    use std::os::unix::ffi::OsStringExt;
    let error = github_token(Some(OsString::from_vec(b"secret\xff".to_vec()))).unwrap_err();
    assert!(matches!(error, AccessError::Token), "{error:?}");
    assert!(!error.to_string().contains("secret"), "{error}");
}

#[test]
fn cache_dir_follows_xdg_then_home() {
    let os = |s: &str| Some(OsString::from(s));
    assert_eq!(
        default_cache_dir(os("/xdg"), os("/home/u")),
        Some(PathBuf::from("/xdg/landfall/tuf"))
    );
    assert_eq!(
        default_cache_dir(None, os("/home/u")),
        Some(PathBuf::from("/home/u/.cache/landfall/tuf"))
    );
    // Relative or empty values are ignored.
    assert_eq!(
        default_cache_dir(os("cache"), os("/home/u")),
        Some(PathBuf::from("/home/u/.cache/landfall/tuf"))
    );
    assert_eq!(default_cache_dir(os(""), os("")), None);
    assert_eq!(default_cache_dir(None, None), None);
}
