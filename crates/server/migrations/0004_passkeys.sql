-- The key a person registered, kept for signing in. It is the controller's copy and nothing
-- a host reads: hosts go by [approvers] in their own configuration, and so does sign-in for
-- anyone listed there. One a principal: registering again replaces it.
CREATE TABLE passkeys (
    credential_id BLOB PRIMARY KEY
        CHECK (length(credential_id) BETWEEN 1 AND 1023),
    principal     TEXT NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    created_at    INTEGER NOT NULL
) STRICT;
