-- What the API reads of the audit log, each on an index, so that a page costs the same however
-- long the log is: one branch for each deployment the principal may view, newest first, with
-- or without a kind, and one for each host they see a deployment on and each kind of row about
-- a host alone that the API shows. Indexes only: the append-only triggers are unaffected.
CREATE INDEX audit_by_deployment ON audit_events (deployment, seq);

CREATE INDEX audit_by_deployment_kind ON audit_events (deployment, kind, seq);

CREATE INDEX audit_by_host_alone ON audit_events (host, kind, seq) WHERE deployment IS NULL;
