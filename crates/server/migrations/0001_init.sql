-- The controller's state and its audit log. Times are unix seconds by the
-- controller's own clock. STRICT tables: a value of the wrong type is an error,
-- not a conversion.

-- Hosts with an enrolled Ed25519 key.
CREATE TABLE hosts (
    id          TEXT PRIMARY KEY,
    public_key  BLOB NOT NULL CHECK (length(public_key) = 32),
    enrolled_at INTEGER NOT NULL
) STRICT;

-- One-time enrolment codes, stored only as a SHA-256 and deleted when used. No
-- reference to `hosts`: a code is issued before its host has a key.
CREATE TABLE enrol_codes (
    code_hash  BLOB PRIMARY KEY CHECK (length(code_hash) = 32),
    host       TEXT NOT NULL,
    replace    INTEGER NOT NULL CHECK (replace IN (0, 1)),
    expires_at INTEGER NOT NULL
) STRICT;

-- Outstanding single-use request nonces, deleted when used.
CREATE TABLE nonces (
    nonce      BLOB PRIMARY KEY CHECK (length(nonce) = 32),
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX nonces_by_expiry ON nonces (expires_at);

-- What was decided about each release of each deployment.
CREATE TABLE releases (
    deployment TEXT NOT NULL,
    tag        TEXT NOT NULL,
    commit_sha TEXT,
    digest     TEXT,
    decision   TEXT NOT NULL CHECK (decision IN ('auto', 'needs_approval', 'manual', 'refused')),
    reason     TEXT NOT NULL,
    seen_at    INTEGER NOT NULL,
    PRIMARY KEY (deployment, tag)
) STRICT;

-- `host` is the deployment's host in the configuration, whether or not it has
-- enrolled yet, so it does not reference `hosts`.
CREATE TABLE deploys (
    id          TEXT PRIMARY KEY,
    deployment  TEXT NOT NULL,
    host        TEXT NOT NULL,
    tag         TEXT NOT NULL,
    digest      TEXT NOT NULL,
    commit_sha  TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('queued', 'claimed', 'finished')),
    outcome     TEXT,
    created_at  INTEGER NOT NULL,
    claimed_at  INTEGER,
    finished_at INTEGER,
    CHECK ((state = 'finished') = (outcome IS NOT NULL)),
    FOREIGN KEY (deployment, tag) REFERENCES releases (deployment, tag)
) STRICT;

CREATE UNIQUE INDEX one_active_deploy_per_deployment
    ON deploys (deployment)
    WHERE state IN ('queued', 'claimed');

CREATE INDEX deploys_by_host ON deploys (host, state);

-- The steps an agent reported for a deploy. `started_at` is the agent's own
-- timestamp, kept as it was reported.
CREATE TABLE deploy_steps (
    deploy_id  TEXT NOT NULL REFERENCES deploys (id),
    position   INTEGER NOT NULL,
    name       TEXT NOT NULL,
    started_at TEXT NOT NULL,
    millis     INTEGER NOT NULL,
    result     TEXT NOT NULL,
    detail     TEXT,
    PRIMARY KEY (deploy_id, position)
) STRICT;

-- The hash-chained log; `audit.rs` documents the hash. AUTOINCREMENT because
-- `sqlite_sequence` then remembers the highest `seq` ever written, which is how
-- `Store::verify_audit` sees rows deleted from the end of the chain, where no
-- later row's `prev_hash` would give them away.
CREATE TABLE audit_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    deployment TEXT,
    host       TEXT,
    detail     TEXT NOT NULL,
    prev_hash  BLOB NOT NULL,
    hash       BLOB NOT NULL
) STRICT;

-- No code path may change the log. These stop a bug, not an attacker with the
-- file: the hash chain is what finds that.
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
