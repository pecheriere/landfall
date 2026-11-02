# Operating landfall

`landfall-server`, the controller, runs on one host: it watches releases, verifies
them, decides what may deploy and keeps the audit log. `landfall-agent` runs on every
host that deploys a service: it asks the controller for work, verifies it again for
itself and deploys it. This guide covers what each needs and what to do when a deploy
goes wrong. The design is in [`design/landfall.md`](design/landfall.md), and the
configuration file in [`configuration.md`](configuration.md).

The agent has four commands: `enrol` and `run` connect it to a controller, `status` and
`recover` work on the host alone.

**The first deploy of a deployment can't be asked for yet.** Only automatic deploys run
in this version, and a first deploy is manual: the controller records it as such and
waits, and a host refuses it. A deployment starts to move once the agent has a release on
record. Requests and approvals come with the approval ceremony and the human API.

## Running the controller

```sh
landfall-server serve --config /etc/landfall/fleet.toml \
  --db /var/lib/landfall-server/controller.db --listen 127.0.0.1:8080
```

- `--config` is the fleet configuration, the same file every host has, byte for byte.
  It is read once: restart after changing it. A host whose file differs gets no work
  until the two agree.
- `--db` is the database, created mode 0600 if it is missing. [Back it up](#backing-up-and-restoring)
  with `landfall-server backup`, as a copy of the file is not a backup.
- `--listen` serves plain HTTP: see [the transport rule](#the-transport-rule).
- `--trust-cache` is where the Sigstore trust root is kept, by default `<db>.tuf` beside
  the database. It is refreshed at most once a day. With no root that verifies, nothing
  is verified, and every deployment is held with that reason.

It looks at releases when it starts and every five minutes after that, so a host that
reports for the first time is looked at on the next round. SIGTERM ends it in seconds:
long polls are answered at once, and requests in flight have five seconds. Agents wait
and try again, so stopping it never interrupts a deploy. Exit status 0 after a stop, 2
if it could not start. `GET /healthz` answers 200 while the database does.

It logs to stderr, one line each, every decision about a release and every hold, when it
changes, as well as trouble it has serving:

```text
landfall-server: decision: app/prod v1.3.0: manual: "beyond the rule's levels: it needs an operator"
landfall-server: hold: app/prod everything: "its host's configuration differs from the controller's"
```

So when nothing deploys, look there first. The whole story is in the audit log, which
this prints as JSON lines, newest last, without writing to the database, whether or not
`serve` is running:

```sh
landfall-server audit show --db controller.db --deployment app/prod --limit 50
```

Without `--deployment` it shows every row, and `--limit` defaults to 100. A host's reason
for putting a release off, or refusing it, is the `reason` of its `deploy_finished` or
`deploy_refused`.

As a unit, `/etc/systemd/system/landfall-server.service`, with a dedicated user
(`useradd --system --no-create-home --shell /usr/sbin/nologin landfall-server`):

```ini
[Unit]
Description=landfall controller
After=network-online.target
Wants=network-online.target

[Service]
User=landfall-server
EnvironmentFile=/etc/landfall/server.env
ExecStart=/usr/local/bin/landfall-server serve --config /etc/landfall/fleet.toml --db /var/lib/landfall-server/controller.db --listen 127.0.0.1:8080
Restart=always
RestartSec=5
TimeoutStopSec=30
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
StateDirectory=landfall-server
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
```

Or in its container, as uid 65532 with a volume that user can write:

```sh
docker run -d --name landfall -p 127.0.0.1:8080:8080 --env-file server.env \
  -v /srv/landfall:/data -v /etc/landfall/fleet.toml:/fleet.toml:ro \
  ghcr.io/pecheriere/landfall serve --config /fleet.toml --db /data/controller.db \
  --listen 0.0.0.0:8080
```

### `GITHUB_TOKEN`

Set it. Anonymous GitHub API requests are limited to 60 an hour per address, and a
controller's first look at a repository verifies up to 16 releases, each taking several
requests: the anonymous limit runs out on first contact, and everything waits for it to
lift, as `rate limited: waiting for the limit to lift` in the audit log.

A token with no scopes is enough for public repositories. It goes in the environment,
from a file only root can read, not on a command line:

```sh
sudo install -m 0600 /dev/null /etc/landfall/server.env
printf 'GITHUB_TOKEN=%s\n' "$token" | sudo tee /etc/landfall/server.env > /dev/null
```

It is sent to the GitHub API only, never to the registry, and never printed. A value that
can't be used stops `serve` from starting.

An agent verifies one release when it is asked to, in a few requests, so it stays well
under the limit on its own. But the limit goes by address, so hosts behind one address
share it with each other and with anything else there that asks GitHub without a token. A
host that meets it waits, with `verification could not run: ... rate limit reached` and
the time it resets in the journal as `work_waiting`, and its polls back off up to five
minutes apart meanwhile, so the deploy can start that long after the reset.

So `landfall-agent run` also reads `GITHUB_TOKEN`, when it is set and not empty. It goes
to the GitHub API only, not to the registry and not to the controller, and it is kept out
of the environment of the `docker` commands the agent runs, where a compose file could ask
for it. A value that can't be used stops `run` from starting. Use a token that can only
read public repositories, and never put it on a command line, where any user can see it.
Either give the unit a file at mode 0600 owned by root:

```ini
[Service]
EnvironmentFile=/etc/landfall/agent.env
```

or a credential, which systemd keeps from the unit's other users, read into the variable as
the agent starts. `$$` is how a unit file says a `$` for the shell:

```ini
[Service]
LoadCredential=github-token:/etc/landfall/github-token
ExecStart=/bin/sh -c 'GITHUB_TOKEN="$$(cat "$$CREDENTIALS_DIRECTORY/github-token")" exec /usr/local/bin/landfall-agent run --config /etc/landfall/fleet.toml --controller https://controller.example --host home-1'
```

### The transport rule

The controller serves plain HTTP, for a tailnet or behind a TLS-terminating proxy. An
agent's requests are signed, so a listener can't forge or replay one, but work contents
are visible, so the agent refuses to send them just anywhere: its `--controller` must be
`https://`, or `http://` to a loopback address, `localhost` or a tailnet name (`*.ts.net`)
with `--allow-insecure-controller`. See [enrolling a host](#enrolling-a-host).

### Keeping the audit head elsewhere

Every event goes in a hash chain in the database, in the same transaction as the change
it records. `landfall-server audit verify --db <file>` walks it without writing, and
exits 1 on a row edited, reordered or deleted from the middle:

```json
{"empty":false,"first_bad":null,"head_hash":"8c1f...","head_seq":412,"rows":412}
```

**The chain alone can't show everything.** It holds no secret, and nothing outside the
database vouches for it. Rows cut from the end with the sequence record lowered to match,
a dropped table, an old backup restored over the current database or a whole forged
history all verify clean. So keep the head somewhere the controller can't write, as often
as you would want to be able to tell, and compare later:

```sh
landfall-server audit verify --db controller.db --at 412
```

```json
{"at_hash":"8c1f...","at_seq":412,"empty":false,"first_bad":null,"head_hash":"d47a...","head_seq":530,"rows":530}
```

`head_seq` must not have gone down, and `at_hash` must be the hash you kept. A log that
no longer has that row prints `"at_hash":null` and exits 1. Past the last head kept
nothing is vouched for, and an external anchor is out of scope for this version. After
restoring a backup on purpose, expect the check to fail, and keep a new head.

### Backing up and restoring

**A copy of `controller.db` isn't a backup.** While the controller runs, and after it
was killed, its latest changes are in `controller.db-wal` beside it, and a host can be
missing from a copy of the one file. Use the command, which needs no `sqlite3` and works
while `serve` runs, also in its container (`docker exec landfall /landfall-server backup
...`, to a path on the volume):

```sh
landfall-server backup --db /var/lib/landfall-server/controller.db /backups/controller-2026-11-01.db
```

```json
{"empty":false,"first_bad":null,"head_hash":"8c1f...","head_seq":412,"rows":412}
```

It writes one whole file, as of one moment, private to the user who runs it, and refuses a
destination that exists. It prints what `audit verify` would of the copy, having checked
it, and exits 1 if the chain doesn't hold. The trust cache beside the database need not be
kept: it is fetched again.

That `head_hash` is the head of the backup. **Keep it somewhere the backup isn't**, as it
is what can tell later that the backup is the one you took: a backup is as easy to edit as
the database. Until you overwrite it with a restore, `audit verify --at <head_seq>` on the
live database must print the same hash, or the log has been changed since.

To restore, stop the agents first, letting any deploy finish, then the controller:

```sh
rm -f controller.db-wal controller.db-shm
cp /backups/controller-2026-11-01.db controller.db
```

Removing the other two files first matters: `SQLite` would apply a log of the old database
to the new. Then start the controller, and then the agents. An agent left running reports
deploys the backup has never heard of under numbers it hands out again. Each report says
which release it is of, so one for another release can't finish the deploy under its
number: it is refused for good (`report_refused` on the controller, `report_rejected` on
the host), and the outcome then is only in the engine's copy under
`<deployment>/reports/`. Hosts stay enrolled as of the backup, and tell it what runs on
their next poll. Whatever happened since is gone from the log, so `audit verify --at`
with a head kept since fails, as it should: keep a new head. Deploy numbers start over from
the backup, which hosts cope with: [a number goes with its release](#a-release-that-rolled-back-isnt-retried).

### Rebuilding a controller from nothing

With no backup, an empty database does: the releases are in GitHub, and what runs and what
failed are on the hosts. The audit log starts again, and hosts have to enrol again, each
with the key it has. On each host, in this order:

1. Stop the agent: `enrol` needs the lock `run` holds. If `status` shows `in_progress`, run
   [`recover`](#recover) now, so that no report under an old number is waiting.
2. On the controller, [make a code](#enrolling-a-host) for the host.
3. `landfall-agent enrol` with it.
4. Start the agent.

A host's memory of what failed stays, so a release that rolled back there isn't tried
again. Approvals and anything else only the controller knew are gone.

## Upgrading

Upgrade the agents and the controller together. Neither accepts a request or an
answer with fields or values it does not know, so a mismatched pair refuses each
other: a newer agent's new report outcome gets `bad_request` from an older
controller, and the deploy stays claimed until the two match. Reports are kept in the
meanwhile, and a deploy already running finishes. landfall never deploys itself.

## Connections to the controller

Prefer direct connections to the controller, over a tailnet for example. The
controller limits clients by the address they connect from: by default 32
connections from one address, out of 1,024 in all, and a rate limit on requests
that need no key. Past the per-address cap a connection is closed with no answer
and the controller logs the refusal to stderr, at most 60 such lines a minute. A
connection lasts at most about two minutes, after which the client reconnects.

Behind a TLS-terminating proxy, the proxy is the one address all agents share. So:

- Raise the cap to fit the fleet, with
  `landfall-server serve --max-connections-per-source <count>`, and
  `--max-connections` above it. Each agent holds one connection most of the time,
  and briefly another.
- Know what that gives up: any client that can reach the proxy can use up that
  whole allowance, and so keep the agents out, without having a key. The limits
  cannot tell them apart, since a forwarding header is something anyone can send.

## Requirements

- **Linux 5.8 or later.** Copying a symlink into a backup sets its owner and
  times through an `O_PATH` descriptor, and `utimensat(2)` takes `AT_EMPTY_PATH`
  since Linux 5.8 (`fchownat(2)` has taken it since 2.6.39; both per their man
  pages). On an older kernel a backup that holds a symlink fails. With
  `stop = true` the service has stopped by then, and the rollback restarts it on
  the previous version; the data is not touched.
- **Docker with the compose plugin**, reached through the `docker` client on the
  agent's `PATH`.
- **CA certificates**, as in the `ca-certificates` package, which slim images leave
  out: `run` reaches GitHub and the registry over TLS, and neither it nor `enrol` with an
  `https://` controller can start without them (`No CA certificates were loaded`). `enrol`
  says so before it writes a key. Only `enrol` to an `http://` controller goes without.
- **A synchronised clock (NTP).** Origin verification compares the transparency
  log's time with the host's: a clock running behind a fresh release, as on a machine
  with no battery for it that has just started, puts the release off until the clock
  is right. Log windows and backup names also go by the host's clock.

## The compose directory

A deployment names a directory and a service
(`compose = { dir = "/srv/compose/app", service = "app" }`). One directory has
one deployment. The service's image belongs to the agent:

- `compose.yaml` keeps everything about the service except the image. A service
  with a `build:` section is refused.
- `compose.landfall.yaml`, the override, is written only by the agent: the image
  pinned by digest, plus labels. The first deploy starts by writing a placeholder
  that names no service, if the file isn't there yet.
- `.env` makes every `docker compose` command, by hand or from a script, use
  both:

  ```sh
  COMPOSE_FILE=compose.yaml:compose.landfall.yaml
  ```

  A deploy checks this before stopping anything, and is refused naming this line
  when it is missing.

  With that line in place, `docker compose` needs the file to exist. Until the
  first deploy has written it, create the placeholder yourself:

  ```sh
  printf '# Managed by landfall. Do not edit: the agent rewrites this file on every deploy.\nservices: {}\n' > compose.landfall.yaml
  ```

- **The compose file must live in `compose.dir`, and the project's name must be this
  directory's alone.** A deploy looks at every container with the service's name, and
  at the working directory compose labelled each with. One in this project that was
  started from another directory, running or stopped, is refused before anything stops,
  as a deploy would stop and replace it. A project's name defaults to the directory's
  base name, so two directories with the same base name share one: give each a unique
  `name:` or `COMPOSE_PROJECT_NAME`. A compose file kept elsewhere is refused the same
  way, once it has a container. A stack elsewhere under another project's name that only
  shares the service's name is left alone. Rollback and `recover` don't repeat these
  checks, so another stack started under the same name after the preflight isn't
  noticed.
- Run `docker compose` from the directory's real path. A deploy accepts a start through
  a symlink to the directory. `status` must not load the project, so it goes by the
  label as it is spelled, and reports such a container as not running. `docker compose
  up -d --force-recreate <service>` from the real path puts the label right, and is the
  fix when the agent's user can't resolve the symlink: under `ProtectHome` or
  `PrivateTmp`, or behind a directory it can't search, a start through it is refused as
  started from elsewhere.
- One container per service. A service with `scale` or `deploy.replicas` other than 1,
  one scaled by hand, or a container running from this directory under another
  project's name (`docker compose -p other up`, also through a symlink, or one left
  behind by editing `name:`) is refused before anything stops, and the error names the
  fix.
- A service behind a profile that isn't active is not in the project, so a deploy
  is refused as having no such service. Set `COMPOSE_PROFILES` in `.env`, or remove
  the profile. The agent ignores that variable in its own environment.

Keep `compose.landfall.yaml` out of the host's configuration repository (add it
to `.gitignore`), and back it up with the host. It changes with every deploy
and rollback, so a checkout or a `git clean` would put the service back on an
old image or take its image away, and `status` would show it as `drift` or as
`override_file: missing`.

Other image updaters must not manage a service landfall manages.

**Create declared backup paths before the first deploy.** A path in
`backup.paths` that doesn't exist fails the backup, so that a running container
cannot make a backup incomplete by deleting a file. On a first deploy the outcome
is `failed_no_previous`, and the service was not started.

## Running it under systemd

Run the agent as a dedicated user in the `docker` group, with its home in its
state directory:

```sh
sudo useradd --system --home-dir /var/lib/landfall-agent --no-create-home \
  --shell /usr/sbin/nologin --groups docker landfall-agent
sudo install -d -o landfall-agent -g landfall-agent -m 0700 /var/lib/landfall-agent
```

`ProtectHome=true` below hides anything under `/home`, which is why the home is
there. No registry credentials are needed: released images must be public
([`configuration.md`](configuration.md)), and they are pulled anonymously.

**The Docker socket is root-equivalent.** Anyone in the `docker` group can start
a container that mounts `/`, so the agent is as trusted as root on its host, and
its sandbox limits mistakes rather than an attacker who has taken it over.

**The agent's uid must be unique on the host,** not shared with the uid any
container runs as, whatever its name there. Files being written to a backup are
private to the agent only by their owner, and a process with that uid could read
or change them, or signal the agent.

Files in a backed-up directory belong to whichever users its containers run as.
Reading them and restoring them with their owners, modes and set-gid bits takes
these capabilities, which the agent keeps across `exec` as ambient ones:

| Capability | Why |
|---|---|
| `CAP_DAC_OVERRIDE` | read another user's files and directories for a backup, write and remove them on a restore |
| `CAP_CHOWN` | give a restored file its owner |
| `CAP_FOWNER` | set the mode and times of a file the agent doesn't own |
| `CAP_FSETID` | keep set-uid and set-gid bits on a copied file |

`recover` restores data, so it runs with all of them, for example as this
template unit, `/etc/systemd/system/landfall-agent-recover@.service`:

```ini
[Unit]
Description=landfall-agent recover %I
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
User=landfall-agent
SupplementaryGroups=docker
ExecStart=/usr/local/bin/landfall-agent recover --config /etc/landfall/fleet.toml --deployment %I
AmbientCapabilities=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=landfall-agent
StateDirectoryMode=0700
# Every managed compose directory on this host.
ReadWritePaths=/srv/compose/app
```

The state directory holds the agent's records, the previous override, reports
and backups. It defaults to `/var/lib/landfall-agent`, and must exist, belong to
the agent's user and not be writable by group or others.

The agent writes one JSON line per event to stderr with a `<N>` syslog priority
prefix, which journald understands (`SyslogLevelPrefix`, on by default). A
failed rollback is priority 2, critical, and so is a controller asking for what
the host doesn't allow (below).

## Enrolling a host

The agent connects out to the controller, and signs every request with a key only
it has. On the controller, make a one-time code for the host, valid for an hour:

```sh
landfall-server enrol-code --host home-1 --db /var/lib/landfall-server/controller.db
```

Run it as the controller's user, as the database is private to it, while `serve` runs or
not; in a container, `docker exec landfall /landfall-server enrol-code --host home-1 --db
/data/controller.db`. The database has to exist, so start `serve` once first.

Put the code in a regular file on the host that only the agent's user can read (a
link or a FIFO is refused): it is not taken on the command line, where any user could
see it. Then, as the agent's user:

```sh
landfall-agent enrol --controller https://controller.example --host home-1 --code-file /path/to/code
```

This generates `agent.key` in the state directory if there isn't one (mode 0600,
never overwritten, never printed), sends the public key with the code, and prints
the host and the public key as JSON. Delete the code file afterwards. If it fails,
run it again with a new code: the key stays. `run` refuses a key file that anyone
else can read.

The rule for `--controller` is the same on `enrol` and `run`:

- `https://` is what to use. Only a scheme, a host and a port: no path, query or
  credentials.
- `http://` needs `--allow-insecure-controller`, and only goes to a loopback
  address, `localhost` or a tailnet name (`*.ts.net`). Requests are signed, so a
  listener can't forge or replay one, but work contents are visible. A tailnet's
  `100.x` addresses are refused, as nothing in the address says it is a tailnet's:
  use the name.

Redirects are not followed.

## Running the agent

`landfall-agent run` polls the controller, and on each work item decides for itself.
It deploys one release at a time. Run it as a unit,
`/etc/systemd/system/landfall-agent.service`, with the capabilities that deploys
need:

```ini
[Unit]
Description=landfall-agent
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
User=landfall-agent
SupplementaryGroups=docker
ExecStart=/usr/local/bin/landfall-agent run --config /etc/landfall/fleet.toml --controller https://controller.example --host home-1
Restart=always
RestartSec=5
# See "Stopping the unit" below for both of these.
KillMode=mixed
TimeoutStopSec=3h
AmbientCapabilities=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_FSETID
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=landfall-agent
StateDirectoryMode=0700
# Every managed compose directory on this host.
ReadWritePaths=/srv/compose/app

[Install]
WantedBy=multi-user.target
```

**It refuses to start** (exit status 2) if the configuration doesn't parse, the host
has no deployment in it, a compose directory is missing or isn't a directory, two
deployments resolve to the same directory (a symlink or a bind mount counts), the
host isn't enrolled, or another `run` holds the state directory. Once it has started
it doesn't stop for trouble: it waits and tries again, up to five minutes apart.

The configuration is read once. Its SHA-256 goes with every request, and the
controller holds back a host whose file differs from its own, which is logged as
`controller_holds_back`. Restart the agent after changing the file.

**A stop finishes the deploy first.** SIGTERM ends a wait for the controller at once.
A deploy in flight runs to its end and is reported before the process exits, and no
new one starts, even if the stop comes while a release is being verified.

### Stopping the unit

`KillMode=mixed` sends SIGTERM to the agent alone and, once it has exited, SIGKILL to
whatever is left of the unit:

- The default, `control-group`, would send SIGTERM to the `docker` and `docker compose`
  the agent is waiting on as well. The call would fail, and the deploy with it, which is
  what the stop was meant to let finish.
- `process` would signal only the agent too, but leave anything it left behind running, to
  go on working under the next agent if it comes to a kill.
- Under `mixed`, the agent has its children to itself until it exits, by which time it has
  none. Containers aren't in this unit's control group, as they belong to `docker.service`,
  so neither the stop nor a kill touches what runs.

`TimeoutStopSec=3h` is how long a deploy in flight gets. Its deadlines add up to about two
hours for a backup and a restore, plus the checks. Past that systemd kills the unit, which
is a crash like any other: the marker stays, and `recover` ends it. So a `systemctl stop`
or a reboot can take that long while a deploy runs, and `systemctl kill -s KILL` is the
way to not wait, followed by `recover`.

A restart of the agent is safe at any moment, by either way. After a stop, nothing is
left over. After a kill, or a power cut, the next agent finds the marker, tells the
controller the phase and is given the same deploy again, which it holds until `recover`
has run; then it reports what that came to, under the controller's number.

### What a compromised controller can and can't do

The controller orchestrates, and the host decides. It can only ask. For every work
item, the host checks by its own configuration and its own records, and runs
nothing unless all of this holds:

- The deployment is one of this host's.
- It has no unfinished deploy, and no drift: what runs is what the agent deployed.
- The deployment's rule makes the move from what the host has on record to this tag
  `Auto`. A first deploy, a downgrade, the version already running, a pre-release the
  rule doesn't opt in to, or a step that needs an approval: all are refused.
- The release verifies, with this host's own trust root, and to the digest and the
  commit the controller named.

What isn't so is answered in one of two ways, and nothing runs either way:

- **`refused`, for good:** the rule says no, a verification result failed, or the
  release is on this host's record of failures. It is journalled as
  `controller_work_refused`, and the controller doesn't ask again. For a request the rule
  or verification refuses that is priority 2, critical: **treat it as an alert**, since
  an honest controller decides by the same rule and doesn't ask.
- **`deferred`, not now:** an unfinished deploy, drift, state or evidence that can't be
  read, a clock behind the release, or a wait for verification that has reached its bound.
  All of these pass. It is journalled as `controller_work_deferred`, at priority 3, error,
  or 4, warning, for a clock or a wait, and the host's next poll is backed off. The
  controller records the release as `deferred`, and asks again under a new number after a
  wait of one look, five minutes, doubling each time it is told so, up to six hours.
  There is no last try. A newer release doesn't wait for it, and the host judges each try
  as it would any other.

What it can do: withhold work, ask again, and see what the host reports. It can
also make the host deploy a release that is allowed by all of the above sooner than
promotion rules on the controller would, which are controller-enforced only. A deployment
with `origin.signed_tags = false` has less to go on: a release is then whatever the
configured workflow built for a tag, so someone who can push a tag and run that workflow
needs no controller to ship one.

What it holds is less than it might seem: the agents' public keys, the configuration, and
a GitHub token with no scopes. It never connects to a host, and no key it holds opens one.
Its audit log is its own account of events, and [the limit of that](#keeping-the-audit-head-elsewhere)
applies. The host's journal is the record the controller can't change.

### A release that rolled back isn't retried

**A release that rolled back on this host isn't retried automatically; a newer release
is.** Retrying the same one is a manual action, which comes with the approval ceremony.
Both ends know. The controller records `rule_decision` `refused` with `it already rolled
back on its host`, and doesn't queue it again. The host goes by its own record,
`<deployment>/failed-releases.json`, the tag and digest of the newest 1,024 releases that
failed here, written before the report is sent; and after that by the engine's reports
under `<deployment>/reports/`, in case a `recover` the daemon didn't see ended one. The
record is what counts, so removing old reports doesn't forget a failure.

**Evidence that can't be read holds up the deploy.** If the record or any of the engine's
reports can't be read, it could be about the release at hand, or the next one, so no
automatic deploy of that deployment goes ahead: each is deferred. The journal says
`failure_evidence_unreadable` at priority 3, naming the file. Read or restore the file if
you can; removing it clears this, and forgets any failure it recorded, so a release that
failed can then deploy again.

**Clearing the record** is for a file that can't be read, or a failure that turned out to
have nothing to do with the release, with no newer one to go to. With the agent stopped,
remove `failed-releases.json`, which forgets every failure on it, and the reports under
`reports/` that name the release, as they count too. That is the host's half: the
controller's own memory of the outcome stays in its database, so it doesn't ask again. The
usual way past a release that failed is a newer one.

The controller can't run a release in circles either. A deploy that has finished never
runs again: delivered again under its number, it gets its original report
(`finished_work_delivered_again`), from a ledger under `<state dir>/finished/` of the
1,024 finished most recently, whatever their numbers. The ledger goes by number and
release. The same number naming another deployment, tag or digest is new, and is judged
like any other, which is what lets a controller rebuilt or restored from a backup, whose
numbers start over, go on deploying. A hostile controller gains nothing from it, as it
could already pick a number it hasn't used. And polls back off, up to five minutes apart,
after a refusal, a deferral, a rollback, a replay or a report refused for good. Only a
release that deploys in that very step, with its report acknowledged, or five minutes
without trouble, starts the backoff over.

Verification that can't run reports nothing at first: the work comes back and is tried
again, as `work_waiting` in the journal. That goes for a registry or GitHub that can't be
reached or a rate limit; a tag, image or attestation that the service says **isn't there**,
as a release may still be publishing; and an answer of the wrong shape, such as a bundle
that doesn't parse, two bundles, or a 401 or 403 from a private package. Meanwhile the
claim blocks every other deployment of this host. So every such wait has a bound of an
hour, by the monotonic clock and counting only while the agent runs. After that the work
is deferred with the reason, which frees the host, and the controller's growing wait paces
any further try. Nothing runs either way.

### Reports

A report goes to the outbox, `<state dir>/outbox/<deploy id>.json`, before it is sent,
and is removed when the controller acknowledges it. While the controller is down a
deploy finishes as usual, the agent asks for no more work, and the report is sent
when the controller is back. It can arrive twice after a crash at the wrong moment:
reports are idempotent by deploy id. Only the API's own refusal for good drops a
report: a 4xx to the signed request, as `application/problem+json`, with a code
classified final. It is journalled as `report_rejected`, and the engine's copy stays
under `<deployment>/reports/`. Any other answer keeps it, a proxy's 404, a failed nonce
and a connection reset among them.

A report in the outbox, a claim or a ledger entry that can't be read is renamed to
`<name>.corrupt.<n>`, the newest 8 of a name being kept, and journalled as
`state_file_set_aside` at priority 3, and the agent carries on. **A corrupt claim with its
marker still there** means the controller's number for that deploy is gone: when the
controller delivers the work again it ends in `deferred`, because of the marker, and the
real outcome of `recover` later has no number to be reported under. That fails closed;
`recover`'s report is under `<deployment>/reports/`.

A report over the API's size limit loses the details of its steps, then what its steps
say, then the steps, with its reasons cut short, and a last step named `report_trimmed`
says so. The agent reaches the controller directly: proxy variables in its environment
are ignored.

The controller's number for a deploy is written to
`<deployment>/controller-claim.json` before the deploy starts, and the file is removed
when the report is safe. After a crash, it stays with the marker: the agent tells the
controller the phase and waits for `recover`, and its next poll after that reports
the outcome under that number, whether or not it was running when `recover` ran. A
claim with no marker, no report and nothing recorded means that the deploy never
started: it is dropped, and the controller delivers the work again.

### Drift

Each deployment's drift goes to the controller with every poll, read at most once a
minute, and a change is journalled as `drift_changed`. A deploy always looks again
first. A deployment that has drifted gets no automatic deploys until it clears, and
one whose state or container can't be read is treated the same.

## HTTP checks

An `http` check connects from the host to the container's address on the named
Docker network. On Linux a host reaches its bridge networks unless a firewall
forbids it, which is worth trying once with `curl` from the host: the check has
no way to tell a firewall from a service that is down. Docker on a Mac has no such
route, so these checks only work on Linux.

`network` is the name Docker knows, as `docker network ls` shows it: usually
`<project>_<key>`, such as `app_app` for a network `app` in a project `app`, unless
the network sets its own `name:`. The key alone fails the check, as the container is
not attached to a network of that name.

## What a deploy does

The sequence is in the design, section 7.2. What an operator will notice:

- **Every deploy takes at least 10 seconds after `up`.** Checks must pass, then
  pass again on the same container after a settle time. A crash later than that
  is not caught unless a `no_log_match` window covers it.
- **A rollback runs the same checks on the previous version.** A check that fails
  on every version, such as a dependency that is down, therefore ends in a failed
  rollback, not a clean one.
- **A rollback starts the service, even one an operator had stopped.** The agent
  doesn't record whether it was running before the deploy; a deploy also starts
  it.
- **If a rollback's `up` of the previous version fails, whatever is running stays
  running.** The state is critical and deploys are blocked, and the agent doesn't
  force a stop. What that leaves depends on how far things got:
  - With no backup declared, nothing stopped the service, so it can be the failed
    release, still serving: `status` shows `running_image_matches: false`.
  - A failed backup with `stop = false` happens before the override and `up`, so what
    is left running is the previous version, not the release.
  - If the service stopped for a backup that then failed (`stop = true`), or for the
    restore of one that completed, it is down unless the failed `up` started it.
  - In a later `recover` from phase `restored`, nothing is stopped, so the previous
    version can still be up from the attempt before.

  What `docker compose up` itself did before it failed is compose's.
- **A rollback whose `up` leaves the container untouched waits the whole log
  window.** With a `no_log_match` check, a container that was not recreated is
  observed for all of `within_secs` from just before that `up`, however long ago it
  started.
- **A missing external network passes `docker compose config`.** The preflight can't
  see it, so with `stop = true` the service can be stopped before an `up` that fails,
  and the rollback then fails the same way if the previous version needs that
  network too. Create the network first.
- **Details of a `docker compose` failure are withheld.** It loads the stack's
  `.env` and compose files and quotes their values in its errors, so a report or
  the journal only has the exit status and the command, for example:

  ```text
  docker compose up: exit status: 1 (output withheld; to see why, run by hand: docker compose up -d --no-deps -- app in the compose directory)
  ```

  Run that command in the compose directory. Its output can hold secrets: mind
  where you paste it. `<project>` in such a command stands for the project's name.
  After a rollback the previous override is back, so the command then shows how
  the previous version fares, not the release that failed.
- **A first deploy has nothing to roll back to,** if the base file gives the
  service no image. A failed one stops the service, puts the placeholder back and
  ends as `failed_no_previous`: not the critical `rollback_failed`.
- **The newest 3 backups are kept** per deployment, whether deploys succeed or fail.
  Before a backup they are pruned to 2, to leave room for it, and after a deploy or
  a completed rollback to 3. The backup an unfinished deploy names is never pruned,
  and after a failed rollback nothing is pruned until `recover` has finished. A run in
  which file work outlasted its deadline skips the pruning and says so in the report,
  as that work may still be running; the next run does it.
- **A report records every step,** with what each check took (`attempts`, `millis`)
  and what a backup copied (`files`, `directories`, `symlinks`, `bytes`), under
  `detail`, also for checks that failed. **Reports are not pruned
  yet** ([#14](https://github.com/pecheriere/landfall/issues/14)): they are small
  JSON files under `<state dir>/<deployment>/reports/`, where the deployment's
  `/` becomes `__` (`/var/lib/landfall-agent/app__prod/reports/`), one per deploy,
  and removing old ones by hand is safe: `failed-releases.json` beside them, which
  isn't pruned beyond its newest 1,024, is what remembers a failed release. A `recover`
  with no daemon's claim to go with it is known only by its report.

## `status`

```sh
sudo -u landfall-agent landfall-agent status --config /etc/landfall/fleet.toml --host home-1
```

`status` needs the `docker` group but none of the capabilities, and it doesn't run
`docker compose`, so `.env` and `compose.yaml` don't have to be readable for it. It
reads the compose directory and the override, so the agent's user must be able to
read those, or accept an error row for that deployment. It prints one JSON object
per line, one per deployment of the host:

```json
{"deployment":"app/prod","dir":"/srv/compose/app","deployed":{"deploy_id":"...","tag":"v1.2.3","version":"1.2.3","digest":"sha256:...","commit":"...","deployed_at":"2026-11-01T10:00:00Z"},"in_progress":false,"phase":null,"override_file":"pinned","running_image":"\"ghcr.io/example/app@sha256:...\"","running_image_matches":true,"drift":false,"error":null}
```

- `deployed` is what the agent last recorded, or `null`.
- `in_progress` means a deploy started and did not finish, and `phase` says how far
  it got, or is `null`; see below.
- `override_file` is `missing`, `placeholder`, `pinned`, or `unrecognised` when the
  file isn't one the agent wrote for this service. A missing one is a state to
  report, not a failure: it is what a host looks like before its first deploy.
- `running_image` is the running container's image, quoted and truncated, only if it
  is the one the override pins. Any other can come from interpolated configuration
  (`image: ${IMG}`) and hold a secret, so it is not printed.
- `running_image_matches` says whether the running container runs the pinned image.
  Both are `null` if none is running.
- `drift` is true when a running container's image is not the one the override
  file pins, the file is `unrecognised`, or it is `missing` while a deploy is on
  record, whatever `.env` makes of the project. With nothing running it is false, as
  it is with nothing pinned and nothing on record. During a deploy a difference is
  expected, and `in_progress` says so.
- `error` says why a deployment could not be read, and what could not be found out
  is `null`. One bad deployment does not keep the others from being reported.

Exit status 0; or 2 if any row has an error, after printing them all, or if it
could not run at all, with the errors in the journal.

## `recover`

Power loss or a killed agent can interrupt a deploy. The agent writes
`in-progress.json` before it changes anything, and while that file exists further
deploys of the deployment are refused, naming this command:

```sh
sudo systemctl start "landfall-agent-recover@$(systemd-escape app/prod).service"
systemctl show -p ExecMainStatus "landfall-agent-recover@$(systemd-escape app/prod).service"
journalctl -u "landfall-agent-recover@$(systemd-escape app/prod).service"
```

`systemctl start` itself returns 1 for any failure of the unit: `ExecMainStatus` is
the agent's own exit status, from the table below.

It goes by the `phase` of the unfinished deploy, which `status` shows:

| `phase` | What `recover` does | Outcome when it works |
|---|---|---|
| `preflight` | The service was never touched: puts the previous override back and leaves the service alone | `nothing_changed` |
| `deploying` | If the deploy had in fact finished and only the clean-up was left, finishes that. Otherwise the rollback path: the previous override, the backup if one was completed, start, verify, checks | `deployed`, or `rolled_back` |
| `rolling_back` | The rollback path again, from the start | `rolled_back` |
| `restored` | The backup is back in full, and the previous version may have been running on it since. Only start, verify and checks: it does not stop the service or restore again, so what that version wrote since is kept. With no previous version it stops the service instead, as there are no writes of one to lose | `rolled_back` |
| `rolled_back` | The previous version is back and checked: removes the marker | `rolled_back` |

A `restored` marker assumes that only the previous version touched the data since
the restore. A release container with `restart: always` can come back on a daemon
restart and write to it, and `recover` keeps that too.

The outcome is `failed_no_previous` in place of `rolled_back` when there is no
previous version to start. A deployment with `rollback_failed` in its report stays
blocked until `recover` succeeds. So does one whose marker could not be removed,
whatever the outcome says: that step fails in the report and the exit status is 1.
It prints the report as JSON on stdout.

| Exit | Meaning |
|---|---|
| 0 | the previous version is back, or there is none and the service is stopped, or the deploy had finished, or it had never touched the service; and the marker is gone |
| 1 | deploys stay blocked: the rollback failed, or the marker could not be removed. Fix the cause and run it again |
| 2 | it could not run: usage, configuration, state, another process holding the lock, or nothing to recover |

### A marker that stays

`recover` is the way out, and it goes by the phase, so running it again after it failed
repeats nothing that would undo its own work.

It can discard writes in one case. With `stop = false`, a crash between recording the
backup and `up` leaves the previous version running on an unfinished marker in phase
`deploying`, and `recover` restores the backup, discarding what the service wrote since.
`status` shows the phase, so an operator can decide what to save first.

If it keeps exiting 1:

1. Read the failing step in the report it printed, or in `journalctl`. A failed
   `docker compose` step names the command to run by hand in the compose directory.
2. Fix that: a dependency that is down, a compose file that doesn't load, a network
   that is missing. A check that can never pass on the previous version needs the
   configuration changed.
3. Run `recover` again. Another deployment's missing directory doesn't stop it.

Removing the marker by hand is the last resort, and only once the service is as you
want it: nothing checks it afterwards. Hold off while any agent process for the
deployment is running, then delete `in-progress.json` from
`<state dir>/<deployment>/`, where the deployment's `/` becomes `__`. The override
and `deployed.json` stay as they are, so see that they agree with what runs: `status`
shows the override against the running image as `drift`. A backup the marker named is
then pruned like any other.
