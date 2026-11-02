-- Who may ask for a deploy and sign it, and what was asked.

-- API tokens, stored only as a SHA-256. `id` is what `token revoke` and the audit log
-- name a token by, and is not a secret. A revoked row stays, so that an id is never
-- used again and the log can always be read against it.
CREATE TABLE api_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    principal  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;

-- One-time links to register a passkey, stored only as a SHA-256, one a principal at a
-- time.
CREATE TABLE passkey_invites (
    code_hash  BLOB PRIMARY KEY CHECK (length(code_hash) = 32),
    principal  TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL
) STRICT;

-- Sessions of people signed in with a passkey, stored only as a SHA-256. A row is gone
-- when the session ends by sign-out.
CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    principal  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX sessions_by_expiry ON sessions (expires_at);

-- A person's or a token's request for a deploy, and the intent an approver signs. It is
-- not a deploy: it holds no deploy number and doesn't stand in the way of the watcher's
-- deploys. Approving it makes one `deploys` row under a number never used before, which
-- is what a host needs to run it, since a number it has refused stays refused.
--
-- awaiting_approval -> approved, when a verified assertion queues its deploy
-- awaiting_approval -> stale, when the running digest moves away from expected_running,
--                      or the release's record changes
-- awaiting_approval -> expired, by the controller's clock
-- awaiting_approval -> cancelled, by whoever may, or by a rollback that takes its place
--
-- Nothing leaves the last four: asking again makes a new row with a new nonce.
-- `expected_running` is NULL for a first deploy. `closed_reason` is the controller's own
-- text. `is_rollback` says it asked for a lower version than ran when it was made, which is
-- what exempts it from promotion, then and when it is approved: what a host says later
-- doesn't make a request one.
CREATE TABLE deploy_requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment       TEXT NOT NULL,
    host             TEXT NOT NULL,
    tag              TEXT NOT NULL,
    commit_sha       TEXT NOT NULL,
    digest           TEXT NOT NULL,
    expected_running TEXT,
    is_rollback      INTEGER NOT NULL CHECK (is_rollback IN (0, 1)),
    nonce           BLOB NOT NULL UNIQUE CHECK (length(nonce) = 32),
    state            TEXT NOT NULL
        CHECK (state IN ('awaiting_approval', 'approved', 'stale', 'expired', 'cancelled')),
    requested_by     TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    approved_by      TEXT,
    closed_reason    TEXT,
    closed_at        INTEGER,
    CHECK ((state = 'approved') = (approved_by IS NOT NULL)),
    CHECK ((state = 'awaiting_approval') = (closed_at IS NULL)),
    FOREIGN KEY (deployment, tag) REFERENCES releases (deployment, tag)
) STRICT;

CREATE UNIQUE INDEX one_open_request_per_deployment
    ON deploy_requests (deployment)
    WHERE state = 'awaiting_approval';

-- What a queued deploy carries to its host: the intent and the assertion, as the JSON of
-- `landfall_core::protocol::Approval`, and the request it came from. Either both or
-- neither: the watcher's automatic deploys have neither. A request queues one deploy,
-- ever.
ALTER TABLE deploys ADD COLUMN approval TEXT
    CHECK (approval IS NULL OR json_valid(approval));
ALTER TABLE deploys ADD COLUMN request_id INTEGER REFERENCES deploy_requests (id)
    CHECK ((request_id IS NULL) = (approval IS NULL));

CREATE UNIQUE INDEX one_deploy_per_request
    ON deploys (request_id)
    WHERE request_id IS NOT NULL;
