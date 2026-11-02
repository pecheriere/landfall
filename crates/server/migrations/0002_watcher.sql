-- What the release watcher keeps.

-- What a recorded decision was made from: the git object the tag's ref named and
-- the configuration, so that a release is verified again only when one of them
-- changes. `origin` is where it came from, as JSON with its text quoted and
-- bounded. `origin_refused` says verification refused it, for good until those
-- inputs change; a `digest` it had before stays recorded.
ALTER TABLE releases ADD COLUMN tag_object TEXT;
ALTER TABLE releases ADD COLUMN config_hash TEXT;
ALTER TABLE releases ADD COLUMN origin TEXT;
ALTER TABLE releases ADD COLUMN origin_refused INTEGER NOT NULL DEFAULT 0
    CHECK (origin_refused IN (0, 1));

-- When the current release began counting as healthy, for promotion: the report
-- that first named it, or that said its drift had cleared. NULL while nothing is
-- deployed or it has drifted. `last_report` is when the host last said anything
-- about the deployment, written at most once a minute when nothing else changed,
-- so that silence can be told from health.
ALTER TABLE running_states ADD COLUMN healthy_since INTEGER;
ALTER TABLE running_states ADD COLUMN last_report INTEGER;

-- Why something could not be decided yet, recorded once for as long as the reason
-- stands: a tag whose material cannot be read, or, with `tag` empty, a whole
-- deployment. `reason` is quoted and bounded. `slow` says it is retried on the
-- slow schedule from the start. Gone when it no longer holds.
CREATE TABLE release_holds (
    deployment TEXT NOT NULL,
    tag        TEXT NOT NULL,
    reason     TEXT NOT NULL,
    since      INTEGER NOT NULL,
    last_try   INTEGER NOT NULL,
    slow       INTEGER NOT NULL CHECK (slow IN (0, 1)),
    PRIMARY KEY (deployment, tag)
) STRICT;
