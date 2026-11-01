-- What the release watcher keeps.

-- What a recorded decision was made from: the git object the tag's ref named and
-- the configuration, so that a release is verified again only when one of them
-- changes. `origin` is where it came from, as JSON with its text quoted and
-- bounded. A row with no `digest` was refused before any digest was settled.
ALTER TABLE releases ADD COLUMN tag_object TEXT;
ALTER TABLE releases ADD COLUMN config_hash TEXT;
ALTER TABLE releases ADD COLUMN origin TEXT;

-- When the current release began counting as healthy, for promotion: the report
-- that first named it, or that said its drift had cleared. NULL while nothing is
-- deployed or it has drifted.
ALTER TABLE running_states ADD COLUMN healthy_since INTEGER;

-- Why something could not be decided yet, recorded once for as long as the reason
-- stands: a tag whose material cannot be read, or, with `tag` empty, a whole
-- deployment. `reason` is quoted and bounded. Gone when it no longer holds.
CREATE TABLE release_holds (
    deployment TEXT NOT NULL,
    tag        TEXT NOT NULL,
    reason     TEXT NOT NULL,
    since      INTEGER NOT NULL,
    last_try   INTEGER NOT NULL,
    PRIMARY KEY (deployment, tag)
) STRICT;
