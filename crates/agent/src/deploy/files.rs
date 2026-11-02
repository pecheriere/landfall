//! The override file and the paths a deploy works on.

use std::fs;
use std::path::Path;

use jiff::Timestamp;
use jiff::tz::TimeZone;

use super::DeployPlan;
use crate::compose;
use crate::safefs::{self, RelPath, Root, SafeFsError};

/// The largest override the agent reads. It writes far less; the file is in a
/// directory others can write to.
const OVERRIDE_CAP: usize = 1024 * 1024;

/// The bytes of the override in `dir`, if there is one.
pub(super) fn read_override_file(dir: &Path) -> Result<Option<Vec<u8>>, SafeFsError> {
    let root = Root::open(dir)?;
    let name = RelPath::new(compose::OVERRIDE_FILE)?;
    safefs::read_file(&root, &name, OVERRIDE_CAP)
}

pub(super) const OVERRIDE_MODE: u32 = 0o644;

/// The override this plan runs with.
pub(super) fn render(plan: &DeployPlan, service: &str) -> Vec<u8> {
    compose::render_override(
        service,
        plan.image(),
        plan.deployment(),
        plan.tag(),
        plan.commit(),
    )
    .into_bytes()
}

/// `time` as a plain name that sorts by time: fixed width, UTC. Backups are
/// pruned by this order. A year past 9999 would not sort; no clock is there.
pub(super) fn timestamp_id(time: Timestamp) -> String {
    let utc = time.to_zoned(TimeZone::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}-{:09}Z",
        utc.year(),
        utc.month(),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.subsec_nanosecond()
    )
}

pub(super) fn rel_paths(paths: &[String]) -> Result<Vec<RelPath>, SafeFsError> {
    paths.iter().map(|p| RelPath::new(p)).collect()
}

/// For each compose working directory label, whether it names `dir`, through
/// symlinks or not. A label that is missing, relative or doesn't resolve names
/// no directory of this deployment. Nothing is opened: the paths are only
/// compared.
pub(super) fn labelled_with(
    dir: &Path,
    labels: &[Option<String>],
) -> Result<Vec<bool>, SafeFsError> {
    let own = fs::canonicalize(dir).map_err(|source| SafeFsError::Io {
        op: "canonicalize",
        path: dir.to_owned(),
        source,
    })?;
    Ok(labels
        .iter()
        .map(|label| {
            label
                .as_deref()
                .map(Path::new)
                .filter(|label| label.is_absolute())
                .is_some_and(|label| fs::canonicalize(label).is_ok_and(|theirs| theirs == own))
        })
        .collect())
}
