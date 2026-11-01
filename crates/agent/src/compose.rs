//! The compose override the agent owns, and the compose directories it works
//! in.
//!
//! `compose.landfall.yaml` is written only by the agent: the pinned image and
//! the labels that say what is running. The stack's `.env` names it in
//! `COMPOSE_FILE` (design 7.1).

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::PathBuf;

use landfall_core::config::Deployment;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag, RepoName};
use landfall_origin::release::{REGISTRY_HOST, image_name};

/// The override's file name, in the compose directory.
pub const OVERRIDE_FILE: &str = "compose.landfall.yaml";

/// The comment the override starts with. A macro so that [`PLACEHOLDER`] can
/// be spelled from the same text with `concat!`.
macro_rules! header {
    () => {
        "# Managed by landfall. Do not edit: the agent rewrites this file on every deploy.\n"
    };
}

const HEADER: &str = header!();

/// The override of a service nothing has been deployed to yet: it names no
/// service, so a `COMPOSE_FILE` listing it still works.
pub const PLACEHOLDER: &str = concat!(header!(), "services: {}\n");

/// What an override file says of a service's image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin<'a> {
    /// The placeholder: nothing is pinned yet.
    Nothing,
    /// The image, in the form the agent writes.
    Image(&'a str),
    /// Not a file the agent wrote for this service. The file is in a directory
    /// others can write to, so what it does say is not to be repeated.
    Unrecognised,
}

/// Reads the pinned image of `service` out of an override, without reading it
/// as YAML: it recognises what [`render_override`] writes, and nothing else.
#[must_use]
pub fn pinned_image<'a>(file: &'a [u8], service: &str) -> Pin<'a> {
    if file == PLACEHOLDER.as_bytes() {
        return Pin::Nothing;
    }
    let Ok(text) = std::str::from_utf8(file) else {
        return Pin::Unrecognised;
    };
    let is_image = |line: &str| line.trim_start().starts_with("image:");
    if text.lines().filter(|line| is_image(line)).count() != 1 {
        return Pin::Unrecognised;
    }
    let key = format!("  {}:", yaml_string(service));
    let mut lines = text.lines().skip_while(|line| *line != key);
    lines.next();
    let image = lines
        .next()
        .and_then(|line| line.strip_prefix("    image: \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .filter(|image| !image.is_empty() && !image.contains(['"', '\\']));
    image.map_or(Pin::Unrecognised, Pin::Image)
}

/// A failure resolving a compose directory.
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
        yaml_string(service),
        yaml_string(image),
        yaml_string(deployment.as_ref()),
        yaml_string(tag.as_ref()),
        yaml_string(commit.as_ref()),
    )
}

/// A YAML double-quoted scalar for `text`.
fn yaml_string(text: &str) -> String {
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

/// The canonical path of the compose directory of `deployment`, on its own,
/// for what reports on one deployment whatever the state of the others.
///
/// # Errors
///
/// [`ComposeError`] when it is missing or not a directory.
pub fn resolve_dir(deployment: &Deployment) -> Result<PathBuf, ComposeError> {
    let dir = deployment.compose().dir();
    let unusable = |source| ComposeError::Unusable {
        deployment: deployment.id().clone(),
        dir: dir.to_owned(),
        source,
    };
    let canonical = fs::canonicalize(dir).map_err(unusable)?;
    let meta = fs::metadata(&canonical).map_err(unusable)?;
    if !meta.is_dir() {
        return Err(ComposeError::NotADirectory {
            deployment: deployment.id().clone(),
            dir: dir.to_owned(),
        });
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use landfall_core::config::parse;
    use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag, RepoName};

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

    fn rendered(service: &str, image: &str) -> String {
        render_override(
            service,
            image,
            &"app/prod".parse::<DeploymentId>().unwrap(),
            &"v1.2.3".parse::<ReleaseTag>().unwrap(),
            &COMMIT.parse::<CommitSha>().unwrap(),
        )
    }

    #[test]
    fn pinned_image_reads_what_the_agent_writes() {
        let file = rendered("app", "ghcr.io/example/app@sha256:00");
        assert_eq!(
            pinned_image(file.as_bytes(), "app"),
            Pin::Image("ghcr.io/example/app@sha256:00")
        );
        assert_eq!(pinned_image(PLACEHOLDER.as_bytes(), "app"), Pin::Nothing);
    }

    #[test]
    fn pinned_image_recognises_nothing_else() {
        let good = rendered("app", "example");
        let other_service = rendered("web", "example");
        let two_images = format!("{good}  \"web\":\n    image: \"other\"\n");
        let hidden = good.replace("    labels:", "    image: \"other\"\n    labels:");
        let unquoted = good.replace("image: \"example\"", "image: example");
        let escaped = good.replace("image: \"example\"", "image: \"a\\u0041\"");
        let trailing = good.replace("image: \"example\"", "image: \"example\" # no");
        let cases = [
            "",
            "services: {}\n",
            "garbage",
            other_service.as_str(),
            two_images.as_str(),
            hidden.as_str(),
            unquoted.as_str(),
            escaped.as_str(),
            trailing.as_str(),
        ];
        for file in cases {
            assert_eq!(
                pinned_image(file.as_bytes(), "app"),
                Pin::Unrecognised,
                "{file}"
            );
        }
        assert_eq!(pinned_image(b"\xff\xfe", "app"), Pin::Unrecognised);
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

    fn deployment_in(dir: &std::path::Path) -> Deployment {
        let dir = dir.to_str().unwrap();
        let text = format!(
            "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
             [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
             [[deployment]]\nid = \"app/prod\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = \"{dir}\", service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\nchecks = [\"container-healthy\"]\n\
             [[grant]]\nprincipal = \"operator\"\ndeployments = [\"app/prod\"]\ncan = [\"approve\"]\n"
        );
        parse(text.as_bytes()).unwrap().deployments()[0].clone()
    }

    #[test]
    fn a_directory_resolves_to_its_canonical_path() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            resolve_dir(&deployment_in(&link)).unwrap(),
            real.canonicalize().unwrap()
        );
    }

    #[test]
    fn missing_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_dir(&deployment_in(&tmp.path().join("gone"))).unwrap_err();
        assert!(matches!(err, ComposeError::Unusable { .. }), "{err}");
        assert!(err.to_string().contains("app/prod"));
    }

    #[test]
    fn a_file_is_not_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let err = resolve_dir(&deployment_in(&file)).unwrap_err();
        assert!(matches!(err, ComposeError::NotADirectory { .. }), "{err}");
    }
}
