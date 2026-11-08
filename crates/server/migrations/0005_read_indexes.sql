-- What the API reads, each on an index, so that a deployment with a long history is read a
-- page at a time and not scanned: its deploys in order, the deploys of one of its releases,
-- and the requests for one of its releases.
CREATE INDEX deploys_by_deployment ON deploys (deployment, id);

CREATE INDEX deploys_by_release ON deploys (deployment, tag, id);

CREATE INDEX requests_by_release ON deploy_requests (deployment, tag);
