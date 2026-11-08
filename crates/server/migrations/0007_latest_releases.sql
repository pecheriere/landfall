-- What a page of deployments reads of their releases, by key, so that it costs the same
-- however long their histories are.

-- A deployment's releases first recorded most recently, which a list of its releases sorts
-- by version: the index hands them over in order, without sorting its whole history.
CREATE INDEX releases_by_first_seen ON releases (deployment, first_seen_at DESC, tag);

-- Each deployment's highest release by semantic version, for each prefix a tag pattern
-- could have: `tag` is the highest of its releases whose tag reads as a version after
-- `prefix`, as the configuration's pattern `<prefix>*` reads it. A tag that reads under
-- several prefixes, such as `v15.0.0` under `v` and `v1`, counts under each. Kept by the
-- store where it records a release, in the same transaction.
CREATE TABLE highest_releases (
    deployment TEXT NOT NULL,
    prefix     TEXT NOT NULL,
    tag        TEXT NOT NULL,
    PRIMARY KEY (deployment, prefix)
) STRICT;

-- Each deployment's first release tag in string order: its latest when its pattern reads
-- none of its tags, as a list puts those last in string order.
CREATE TABLE first_tags (
    deployment TEXT PRIMARY KEY,
    tag        TEXT NOT NULL
) STRICT;

-- The two tables above are filled from the releases already recorded the next time the
-- controller opens the database, since reading a version takes the controller's own code.
-- This row says that hasn't happened yet; filling them removes it.
CREATE TABLE latest_unfilled (
    pending INTEGER NOT NULL CHECK (pending = 1)
) STRICT;

INSERT INTO latest_unfilled (pending) VALUES (1);
