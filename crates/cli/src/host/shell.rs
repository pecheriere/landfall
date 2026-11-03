//! Quoting for a POSIX shell.

/// The `PATH` a probe and a script set for themselves, as an `ssh` login's own may leave
/// out the `sbin` directories that hold `runuser`.
pub const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Holds what a shell other than a POSIX one reads differently inside single quotes. A probe
/// prints it back through [`quote`], so that a login shell that would change what runs from
/// what was hashed is caught before anything does run.
pub const QUOTE_CHECK: &str = "a'b\\c\\\\d\ne";

/// `text` as one word in a POSIX shell, whatever it holds.
#[must_use]
pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The command that has a login shell run `script` under `sh`, whichever shell it is, as
/// long as it quotes as a POSIX one does.
#[must_use]
pub fn remote_command(script: &str) -> String {
    format!("exec sh -c {}", quote(script))
}

/// The command that has a login shell run `script` as root: through `sudo` unless it already is,
/// and with no terminal behind it, through a `sudo` that won't ask. `script` goes as an argument,
/// so that no file a login can write is run as root.
#[must_use]
pub fn privileged_command(script: &str, interactive: bool) -> String {
    let sudo = if interactive { "sudo" } else { "sudo -n" };
    let wrapper =
        format!(r#"if [ "$(id -u)" = 0 ]; then exec sh -c "$1"; fi; exec {sudo} sh -c "$1""#);
    format!("exec sh -c {} sh {}", quote(&wrapper), quote(script))
}
