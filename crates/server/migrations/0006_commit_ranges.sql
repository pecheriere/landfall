-- The commits between two verified releases, as GitHub's compare lists them.

-- A range of a repository from one release commit to another, stored by commit and not
-- by tag: a moved tag leaves its old range behind, and two deployments of one repository
-- share one. `state` is what came of it: `listed` with its commits, `too_large` for
-- GitHub to show, `base_not_found` when the base isn't an ancestor of the head, or
-- `unavailable`, tried again after a while. `total` is GitHub's count of every commit of
-- a listed range, which may be more than are kept. `last_try` is when it was fetched.
CREATE TABLE commit_ranges (
    repo        TEXT NOT NULL,
    base_commit TEXT NOT NULL,
    head_commit TEXT NOT NULL,
    state       TEXT NOT NULL
        CHECK (state IN ('listed', 'too_large', 'base_not_found', 'unavailable')),
    total       INTEGER,
    last_try    INTEGER NOT NULL,
    PRIMARY KEY (repo, base_commit, head_commit)
) STRICT;

-- The newest commits of a listed range, newest first from position 0. `summary` is the
-- first line of the message, quoted and bounded; `author` the login GitHub attributes it
-- to, unverified.
CREATE TABLE range_commits (
    repo        TEXT NOT NULL,
    base_commit TEXT NOT NULL,
    head_commit TEXT NOT NULL,
    position    INTEGER NOT NULL,
    sha         TEXT NOT NULL,
    summary     TEXT NOT NULL,
    author      TEXT,
    PRIMARY KEY (repo, base_commit, head_commit, position)
) STRICT;

-- When this migration ran: only releases first recorded since then are compared, so
-- an upgrade fetches nothing for the history it already has.
CREATE TABLE commits_since (
    at INTEGER NOT NULL
) STRICT;

INSERT INTO commits_since (at) VALUES (unixepoch());

-- When the controller first recorded a release, set on insert and never changed:
-- `seen_at` moves on every verification, a configuration change included.
ALTER TABLE releases ADD COLUMN first_seen_at INTEGER NOT NULL DEFAULT 0;

UPDATE releases SET first_seen_at = seen_at;
