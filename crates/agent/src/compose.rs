//! The compose override the agent owns, and the compose directories it works
//! in.
//!
//! `compose.landfall.yaml` is written only by the agent: the pinned image and
//! the labels that say what is running. The stack's `.env` names it in
//! `COMPOSE_FILE` (design 7.1).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::PathBuf;

use landfall_core::config::Config;
use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, ReleaseTag, RepoName};
use landfall_origin::release::{REGISTRY_HOST, image_name};

/// The override's file name, in the compose directory.
pub const OVERRIDE_FILE: &str = "compose.landfall.yaml";

const HEADER: &str =
    "# Managed by landfall. Do not edit: the agent rewrites this file on every deploy.\n";

/// The override of a service nothing has been deployed to yet: it names no
/// service, so a `COMPOSE_FILE` listing it still works.
pub const PLACEHOLDER: &str = "# Managed by landfall. Do not edit: the agent rewrites this file on every deploy.\nservices: {}\n";

/// A failure resolving the compose directories of a host.
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    /// The directory cannot be resolved (missing, not searchable).
    #[error("deployment {deployment}: compose directory {dir:?} cannot be used: {source}")]
    Unusable {
        /// The deployment.
        deployment: DeploymentId,
        /// The configured directory.
        dir: String,
        /// The underlying error.
        source: io::Error,
    },
    /// The path resolves to something that is not a directory.
    #[error("deployment {deployment}: compose directory {dir:?} is not a directory")]
    NotADirectory {
        /// The deployment.
        deployment: DeploymentId,
        /// The configured directory.
        dir: String,
    },
    /// Two deployments resolve to the same directory (a symlink, a bind
    /// mount path or a different spelling): overrides and backups are per
    /// directory, so this is refused.
    #[error("deployments {first} and {second} resolve to the same compose directory {resolved:?}")]
    Aliased {
        /// One deployment.
        first: DeploymentId,
        /// The other.
        second: DeploymentId,
        /// The directory both resolve to.
        resolved: PathBuf,
    },
}

/// The image reference a release is deployed by: the repository's image on
/// the registry, pinned by `digest`. The name is derived by
/// [`landfall_origin::release::image_name`], as it is for verification.
#[must_use]
pub fn image_ref(repo: &RepoName, digest: &ImageDigest) -> String {
    format!("{REGISTRY_HOST}/{}@{digest}", image_name(repo))
}

/// Renders the override that pins `service` to `image` and labels it with
/// what is running. Every value is double-quoted and escaped, so nothing in
/// it can end the scalar or start another key.
#[must_use]
pub fn render_override(
    service: &str,
    image: &str,
    deployment: &DeploymentId,
    tag: &ReleaseTag,
    commit: &CommitSha,
) -> String {
    format!(
        "{HEADER}services:\n  {}:\n    image: {}\n    labels:\n      dev.landfall.deployment: {}\n      dev.landfall.version: {}\n      dev.landfall.commit: {}\n",
        quote(service),
        quote(image),
        quote(deployment.as_ref()),
        quote(tag.as_ref()),
        quote(commit.as_ref()),
    )
}

/// A YAML double-quoted scalar for `text`.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Resolves the compose directory of each deployment on `host` to its
/// canonical path, once, at start-up. A directory that is missing or not a
/// directory, or two deployments that resolve to the same one, is an error,
/// so the agent does not run with an ambiguous layout.
///
/// # Errors
///
/// [`ComposeError`] for the first deployment that fails.
pub fn resolve_dirs(
    config: &Config,
    host: &HostId,
) -> Result<BTreeMap<DeploymentId, PathBuf>, ComposeError> {
    let mut resolved: BTreeMap<DeploymentId, PathBuf> = BTreeMap::new();
    let mut owners: BTreeMap<PathBuf, DeploymentId> = BTreeMap::new();
    for d in config.deployments_for_host(host) {
        let dir = d.compose().dir();
        let unusable = |source| ComposeError::Unusable {
            deployment: d.id().clone(),
            dir: dir.to_owned(),
            source,
        };
        let canonical = fs::canonicalize(dir).map_err(unusable)?;
        if !fs::metadata(&canonical).map_err(unusable)?.is_dir() {
            return Err(ComposeError::NotADirectory {
                deployment: d.id().clone(),
                dir: dir.to_owned(),
            });
        }
        if let Some(first) = owners.insert(canonical.clone(), d.id().clone()) {
            return Err(ComposeError::Aliased {
                first,
                second: d.id().clone(),
                resolved: canonical,
            });
        }
        resolved.insert(d.id().clone(), canonical);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use landfall_core::config::parse;
    use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, ReleaseTag, RepoName};

    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn override_has_the_pinned_image() {
        let repo: RepoName = "Example/App".parse().unwrap();
        let digest: ImageDigest = DIGEST.parse().unwrap();
        let image = image_ref(&repo, &digest);
        assert_eq!(image, format!("ghcr.io/example/app@{DIGEST}"));
        let text = render_override(
            "app",
            &image,
            &"app/prod".parse::<DeploymentId>().unwrap(),
            &"v1.2.3".parse::<ReleaseTag>().unwrap(),
            &COMMIT.parse::<CommitSha>().unwrap(),
        );
        let expected = format!(
            "# Managed by landfall. Do not edit: the agent rewrites this file on every deploy.\n\
             services:\n  \"app\":\n    image: \"ghcr.io/example/app@{DIGEST}\"\n    labels:\n      \
             dev.landfall.deployment: \"app/prod\"\n      dev.landfall.version: \"v1.2.3\"\n      \
             dev.landfall.commit: \"{COMMIT}\"\n"
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn quoting_escapes_what_could_break_out() {
        let text = render_override(
            "a\"b\\c\nd",
            "i",
            &"app/prod".parse().unwrap(),
            &"v1".parse().unwrap(),
            &COMMIT.parse().unwrap(),
        );
        assert!(text.contains("\"a\\\"b\\\\c\\nd\":"), "{text}");
    }

    #[test]
    fn placeholder_is_an_empty_services_map() {
        assert!(PLACEHOLDER.ends_with("services: {}\n"));
        assert_eq!(OVERRIDE_FILE, "compose.landfall.yaml");
    }

    fn config(dirs: &[(&str, &str)]) -> landfall_core::config::Config {
        let mut text = String::from(
            "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
             [approvers]\noperator = { credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }\n",
        );
        for (id, dir) in dirs {
            write!(
                text,
                "[[deployment]]\nid = \"{id}\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
                 host = \"home-1\"\ncompose = {{ dir = \"{dir}\", service = \"app\" }}\n\
                 origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
                 rule = {{ auto = \"any\", approvers = [\"operator\"] }}\nchecks = [\"container-healthy\"]\n"
            )
            .unwrap();
        }
        write!(
            text,
            "[[grant]]\nprincipal = \"operator\"\ndeployments = [{}]\ncan = [\"approve\"]\n",
            dirs.iter()
                .map(|(id, _)| format!("\"{id}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
        parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn directories_resolve_to_their_canonical_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let cfg = config(&[
            ("app/prod", real.to_str().unwrap()),
            ("app/staging", other.to_str().unwrap()),
        ]);
        let host: HostId = "home-1".parse().unwrap();
        let dirs = resolve_dirs(&cfg, &host).unwrap();
        assert_eq!(dirs.len(), 2);
        assert_eq!(
            dirs[&"app/prod".parse::<DeploymentId>().unwrap()],
            real.canonicalize().unwrap()
        );
        let elsewhere: HostId = "home-2".parse().unwrap();
        assert!(resolve_dirs(&cfg, &elsewhere).unwrap().is_empty());
    }

    #[test]
    fn aliased_directories_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = tmp.path().join("alias");
        symlink(&real, &alias).unwrap();
        let cfg = config(&[
            ("app/prod", real.to_str().unwrap()),
            ("app/staging", alias.to_str().unwrap()),
        ]);
        let err = resolve_dirs(&cfg, &"home-1".parse().unwrap()).unwrap_err();
        assert!(matches!(err, ComposeError::Aliased { .. }), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("app/prod") && text.contains("app/staging"),
            "{text}"
        );
    }

    #[test]
    fn missing_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let gone = tmp.path().join("gone");
        let cfg = config(&[("app/prod", gone.to_str().unwrap())]);
        let err = resolve_dirs(&cfg, &"home-1".parse().unwrap()).unwrap_err();
        assert!(matches!(err, ComposeError::Unusable { .. }), "{err}");
        assert!(err.to_string().contains("app/prod"));
    }

    #[test]
    fn a_file_is_not_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let cfg = config(&[("app/prod", file.to_str().unwrap())]);
        let err = resolve_dirs(&cfg, &"home-1".parse().unwrap()).unwrap_err();
        assert!(matches!(err, ComposeError::NotADirectory { .. }), "{err}");
    }
}
