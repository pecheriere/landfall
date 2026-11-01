-- The controller's state and its audit log. Times are unix seconds by the
-- controller's own clock. STRICT tables: a value of the wrong type is an error,
-- not a conversion.

-- Hosts with an enrolled Ed25519 key. A key belongs to one host: whoever holds a
-- key enrolled twice could sign as either.
-- `drifted_config_hash` is the hash the host last reported when it differed
-- from the controller's, and NULL when the two agree, so a host polling with a
-- wrong configuration is recorded once and not on every poll.
CREATE TABLE hosts (
    id                  TEXT PRIMARY KEY,
    public_key          BLOB NOT NULL UNIQUE CHECK (length(public_key) = 32),
    enrolled_at         INTEGER NOT NULL,
    drifted_config_hash BLOB CHECK (length(drifted_config_hash) = 32)
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
-- enrolled yet, so it does not reference `hosts`. `id` is the wire's `DeployId`:
-- AUTOINCREMENT, so an id is never used twice, even after rows are deleted.
-- `reason` and `rollback_reason` are the agent's text, quoted and bounded.
CREATE TABLE deploys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment      TEXT NOT NULL,
    host            TEXT NOT NULL,
    tag             TEXT NOT NULL,
    digest          TEXT NOT NULL,
    commit_sha      TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('queued', 'claimed', 'finished')),
    outcome         TEXT,
    reason          TEXT,
    rollback_reason TEXT,
    created_at      INTEGER NOT NULL,
    claimed_at      INTEGER,
    finished_at     INTEGER,
    CHECK ((state = 'finished') = (outcome IS NOT NULL)),
    FOREIGN KEY (deployment, tag) REFERENCES releases (deployment, tag)
) STRICT;

CREATE UNIQUE INDEX one_active_deploy_per_deployment
    ON deploys (deployment)
    WHERE state IN ('queued', 'claimed');

CREATE INDEX deploys_by_host ON deploys (host, state);

-- The steps an agent reported for a deploy, its text quoted and bounded. At most
-- `report::MAX_STORED_STEPS` for a deploy. `failure` is NULL for a step that did
-- what it should; `detail` is JSON, when the step had more to say.
CREATE TABLE deploy_steps (
    deploy_id INTEGER NOT NULL REFERENCES deploys (id),
    position  INTEGER NOT NULL,
    name      TEXT NOT NULL,
    millis    INTEGER NOT NULL,
    failure   TEXT,
    detail    TEXT,
    PRIMARY KEY (deploy_id, position)
) STRICT;

-- What each host last said about its deployments, only for deployments the
-- configuration gives it. `tag` and `digest` are both NULL for a deployment that
-- has never been deployed. `inconsistent` says the host last said idle and busy
-- together, which is stored as not busy and audited once until it stops.
CREATE TABLE running_states (
    deployment   TEXT PRIMARY KEY,
    host         TEXT NOT NULL,
    tag          TEXT,
    digest       TEXT,
    drift        INTEGER NOT NULL CHECK (drift IN (0, 1)),
    phase        TEXT NOT NULL,
    busy         INTEGER NOT NULL CHECK (busy IN (0, 1)),
    inconsistent INTEGER NOT NULL CHECK (inconsistent IN (0, 1)),
    updated_at   INTEGER NOT NULL,
    CHECK ((tag IS NULL) = (digest IS NULL))
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

-- INSERT OR REPLACE deletes the row it replaces without firing the trigger above.
CREATE TRIGGER audit_events_no_replace BEFORE INSERT ON audit_events
WHEN EXISTS (SELECT 1 FROM audit_events WHERE seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
