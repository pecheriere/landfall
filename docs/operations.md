# Operating landfall

`landfall-server`, the controller, runs on one host: it watches releases, verifies
them, decides what may deploy and keeps the audit log. `landfall-agent` runs on every
host that deploys a service: it asks the controller for work, verifies it again for
itself and deploys it. This guide covers what each needs and what to do when a deploy
goes wrong. The design is in [`design/landfall.md`](design/landfall.md), and the
configuration file in [`configuration.md`](configuration.md).

The agent has four commands: `enrol` and `run` connect it to a controller, `status` and
`recover` work on the host alone.

**The first deploy of a deployment is asked for and approved.** It is manual: the controller
records it as such and waits, and a host runs it only on
[an approval it verifies itself](#an-approval-is-verified-on-the-host). [From nothing to a first
deploy](#from-nothing-to-a-first-deploy) has the steps. There is no web UI beyond the three
minimal pages yet, and no `landfall` command for any of it: a program calls
[the API](#api-tokens-requests-and-approvals). The `landfall` command does put an agent on a host, and
upgrade it: see [`landfall host install`](#installing-an-agent-with-landfall-host-install).

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
long polls are answered at once, and requests in flight have five seconds, after which
they get no answer. Agents wait and try again, so stopping it never interrupts a deploy.
[What stopping can take](#what-stopping-takes) sets how long a service manager should wait.
Exit status 0 after a stop, 2 if it could not start. `GET /healthz` answers 200 while the database does.

It logs to stderr, one line each, every decision about a release and every hold, when it
changes, as well as trouble it has serving:

```text
landfall-server: decision: app/prod v1.3.0: manual: "beyond the rule's levels: it needs an operator"
landfall-server: hold: app/prod everything: "its host's configuration differs from the controller's"
```

A control character in a line, or one that reorders text, breaks a line or isn't seen (every Unicode
format character, such as a zero-width space, and the variation selectors), is written as an escape
such as `\u000a`, as JSON writes it, with a surrogate pair past the first plane. A backslash is
written `\\`, so that nothing in a line can pass for an escape. A line past 4 KiB is cut short and
ends with ` \[cut short]`, whose single backslash no line can end with otherwise. Its lines are
written by a thread of their own, so that whatever reads stderr can't hold up the controller by not
reading: up to 256 wait for it, and those that don't fit are dropped and counted, as
`landfall-server: 12 more log lines were not written, as stderr was not taking them`, said before the
next line written or when it stops. With several lines logged at once, that can land a line or so from
where they were dropped, and the count is right. Decisions, holds and every refusal someone can be held
to are in the audit log too: only refusals that could come from anyone, already capped at 60 a minute,
are here alone.

A panic while serving goes to the same log, as `thread '<name>' panicked at <file:line:column>:
<message>`. `RUST_BACKTRACE` is read as Rust's own panic message reads it: with `1`, the frames of
the code that panicked follow, one `backtrace: <n>: <function> at <file:line:column>` line each, and
with `full`, every frame. Frames with no symbol are left out. Release binaries are stripped, so
from one the backtrace is the single line `backtrace: it has no symbols, as in a stripped build`, and
only a build of your own with symbols names frames. If `serve` fails, it says why as the last line of this log. Any other command
says why straight on stderr, waiting for it as long as it takes.

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
docker run -d --name landfall --stop-timeout 30 -p 127.0.0.1:8080:8080 --env-file server.env \
  -v /srv/landfall:/data -v /etc/landfall/fleet.toml:/fleet.toml:ro \
  ghcr.io/pecheriere/landfall serve --config /fleet.toml --db /data/controller.db \
  --listen 0.0.0.0:8080
```

### What stopping takes

SIGTERM takes well under a second with nothing in flight. Each limit below is only waited out by
something going wrong, and each goes on to the next step whatever happened:

| Step | Limit | What it's for |
|---|---|---|
| Drain | 5 s | Requests in flight finish. Those that don't get no answer. A connection that has answered waits up to 2 s for its client to close, within the drain. |
| Cut-off | 5 s | What's left is dropped at once, unless a handler is blocking its thread, which nothing is known to do. A connection still waiting for its client goes too. |
| Watcher and flushing tasks | 5 s | They were told to stop when the drain began. |
| The last flush | Up to 5 s a row, on a busy database | Writes down counted failures and dropped calls. |
| Closing the database | 5 s | So that the main file holds everything. |
| The runtime's threads | 1 s | Any still blocked are left behind as the process ends. |
| The log | 1 s | What's waiting for stderr is written. If stderr isn't taking it, it's lost. |

That's 22 s before the flush's own time, so give it **30 s**, which leaves a row's wait or two:

- **systemd:** `TimeoutStopSec=30`, as in the unit above. The agent's unit has `TimeoutStopSec=3h`,
  which is about deploys and is [its own matter](#stopping-the-unit).
- **`docker run`:** `--stop-timeout 30`, as above. `docker stop` then goes by that, unless it's given
  `-t`.
- **Compose:** `stop_grace_period: 30s` on the service.

Docker's default is 10 s, which is just the drain and the cut-off: without one of these, a controller
with a blocked handler is killed before its last flush.

**What's lost if it's killed first** is what a crash loses, and no more. Everything committed stays,
and the next start reads what's left in the write-ahead log. Failed sign-ins and dropped calls
counted since the last flush aren't written down, so that's up to five minutes' worth of them. The
log line `stopped with 1 request still running` means a handler was still blocked after all this,
and that anything it counts from then on is lost in the same way. A stderr that isn't read, from a
stalled journald or log driver, can't block one: logging never waits for it.

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

To restore:

1. **Stop the agents,** letting any deploy finish, **then the controller.** An agent left running
   reports deploys the backup has never heard of under numbers it hands out again. Each report says
   which release it is of, so one for another release can't finish the deploy under its number: it
   is refused for good (`report_refused` on the controller, `report_rejected` on the host), and the
   outcome then is only in the engine's copy under `<deployment>/reports/`.
2. **Write down what was revoked since the backup, from the database you are about to replace.** A
   token revoked since then works again once the backup is back. `audit show` has no filter of its
   own and shows the newest rows up to `--limit`, so ask for all of them. These rows name no
   deployment, so leave out `--deployment`:

   ```sh
   landfall-server audit show --db controller.db --limit 4294967295 \
     | grep -E '"kind":"(token_revoked|passkey_registered)"' > changed-since-backup.txt
   ```

   An empty file with nothing printed is a good answer: nothing was revoked. **If this printed an
   error,** the file is empty too and says nothing, so use the fallback in step 4.

3. **Put the backup in place,** as the user the controller runs as, which must be able to open it.
   Removing the other two files first matters: `SQLite` would apply a log of the old database to the
   new.

   ```sh
   rm -f controller.db-wal controller.db-shm
   cp /backups/controller-2026-11-01.db controller.db
   ```

4. **Revoke those tokens again, before `serve` starts,** so that they don't work in between. This
   needs no `serve`. An id that says `there is no API token with this id` was made after the backup,
   and is gone with it:

   ```sh
   grep '"kind":"token_revoked"' changed-since-backup.txt | sed -E 's/.*"token":([0-9]+).*/\1/' \
     | while read -r id; do landfall-server token revoke --id "$id" --db controller.db; done
   ```

   **If the old database is lost, or you don't trust it,** you can't know what was revoked. Revoke
   every token the restored log knows of, and make new ones afterwards:

   ```sh
   landfall-server audit show --db controller.db --limit 4294967295 \
     | grep '"kind":"token_created"' | sed -E 's/.*"token":([0-9]+).*/\1/' \
     | while read -r id; do landfall-server token revoke --id "$id" --db controller.db; done
   ```

   A backup from before an upgrade gets `run serve from this version once` instead. Do that on a
   port nothing forwards to, stop it, and then revoke.
5. **Start the controller, and then the agents.** Hosts stay enrolled as of the backup, and tell it
   what runs on their next poll.
6. **Someone with no key in `[approvers]` registers again,** from a new invite, if that file has a
   `passkey_registered` row for them, as their stored key is back to the old one. With no list to go
   by, that is all of them. **An approver with a key in the file doesn't register again:** signing
   in and approving go by the file's key, whatever is stored, so they need nothing. And on the same
   authenticator, registering replaces the credential the file and every host hold, so that person
   couldn't approve until the file changed everywhere. A session signed out since the backup works
   again too, until its 12 hours are up or, for someone with no key in the file, they register
   again.
7. **Keep a new head.** Whatever happened since is gone from the log, so `audit verify --at` with a
   head kept since fails, as it should.

**In its container,** these are the same steps with other commands. The image holds the one program
and no shell, so `grep`, `rm` and the rest run on the host, on the directory mounted at `/data`.
With `serve` stopped `docker exec` has nothing to run in, so each `landfall-server` command is a
one-off container. The names here are those of [the run command above](#running-the-controller), and
the backup is one made on the volume with `docker exec`:

```sh
# 1. Stop the agents, then the controller.
docker stop landfall

# 2. What was revoked since the backup. If this prints an error, the file is empty and says
#    nothing: use the fallback below.
docker run --rm -v /srv/landfall:/data ghcr.io/pecheriere/landfall \
  audit show --db /data/controller.db --limit 4294967295 \
  | grep -E '"kind":"(token_revoked|passkey_registered)"' > changed-since-backup.txt

# 3. The backup in place. `install`, as the container runs as uid 65532: a root-owned copy
#    can't be opened, and every command says `unable to open database file`.
sudo rm -f /srv/landfall/controller.db-wal /srv/landfall/controller.db-shm
sudo install -o 65532 -g 65532 -m 0600 /srv/landfall/controller-2026-11-01.db /srv/landfall/controller.db

# 4. Revoke those tokens again.
grep '"kind":"token_revoked"' changed-since-backup.txt | sed -E 's/.*"token":([0-9]+).*/\1/' \
  | while read -r id; do
      docker run --rm -v /srv/landfall:/data ghcr.io/pecheriere/landfall \
        token revoke --id "$id" --db /data/controller.db
    done

# 5. Start it, and then the agents.
docker start landfall
```

If the old database is lost or you don't trust it, step 4 goes by the restored log, and new tokens
need the file as well:

```sh
docker run --rm -v /srv/landfall:/data ghcr.io/pecheriere/landfall \
  audit show --db /data/controller.db --limit 4294967295 \
  | grep '"kind":"token_created"' | sed -E 's/.*"token":([0-9]+).*/\1/' \
  | while read -r id; do
      docker run --rm -v /srv/landfall:/data ghcr.io/pecheriere/landfall \
        token revoke --id "$id" --db /data/controller.db
    done
docker run --rm -v /srv/landfall:/data -v /etc/landfall/fleet.toml:/fleet.toml:ro \
  ghcr.io/pecheriere/landfall token create --principal ci --config /fleet.toml --db /data/controller.db
```

A backup from before an upgrade needs `serve` once before step 4. With no network and no published
port, nothing can reach it meanwhile. It is ready when its log says `listening on`:

```sh
docker run -d --name landfall-upgrade --stop-timeout 30 --network none -v /srv/landfall:/data \
  -v /etc/landfall/fleet.toml:/fleet.toml:ro ghcr.io/pecheriere/landfall \
  serve --config /fleet.toml --db /data/controller.db --listen 127.0.0.1:8080
docker logs landfall-upgrade
docker stop landfall-upgrade
docker rm landfall-upgrade
```

Deploy numbers start over from the backup, which hosts cope with:
[a number goes with its release](#a-release-that-rolled-back-isnt-retried). Invites, requests and
approvals are as of the backup too.

**An approval comes through a restore safely, as the hosts keep their own count of them:**

- One made since the backup is gone, and nothing runs on it. The request is open again if the backup
  has it open, and takes a new tap. **That tap may run nothing:** if its new deploy gets a number
  this host already finished for that release, the host answers with its report of then, with no
  `up` and nothing spent, so the row can read `deployed` while another version runs. Check what runs
  with `landfall-agent status`. If it didn't move and you still want it, ask again, which makes a
  new request and a new number.
- One the backup holds as queued, for a deploy that has since run, is delivered again under its
  number. The host answers with its report of that deploy (`finished_work_delivered_again`), and the
  service isn't touched.
- Delivered under another number, it is refused at priority 2: by what the host runs, if it has
  moved on, or by [the nonce log](#the-nonce-log), if the digest it names is running again. Deploy
  numbers aren't per deployment, so a request reopened by a restore can honestly get another number.
  Nothing ran. If you still want the release, ask again.

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
again. Approvals, tokens, sessions, stored passkeys and anything else only the controller knew are
gone: make new tokens, and anyone with grants and no key in `[approvers]` registers again.

## Upgrading

Upgrade the agents and the controller together. Neither accepts a request or an
answer with fields or values it does not know, so a mismatched pair refuses each
other: a newer agent's new report outcome gets `bad_request` from an older
controller, and the deploy stays claimed until the two match. Reports are kept in the
meanwhile, and a deploy already running finishes. landfall never deploys itself.

For an agent, [`landfall host upgrade`](#upgrading-an-agent-landfall-host-upgrade) does it, by a person's
hand and verified as an install is.

Only `serve` upgrades the database, when it starts. So run `serve` from the new version before
`token` or `passkey-invite`, which otherwise say the database is older than they are, and do
nothing.

## Connections to the controller

Prefer direct connections to the controller, over a tailnet for example. The
controller limits clients by the address they connect from: by default 32
connections from one address, out of 1,024 in all, and a rate limit on requests
that need no key. Past the per-address cap a connection is closed with no answer
and the controller logs the refusal to stderr, at most 60 such lines a minute. A
connection lasts at most about two minutes, after which the client reconnects.
Once a connection has given its last answer, the controller closes its side and
waits up to 2 s for the client to close the other, throwing away up to 64 KiB of
anything still sent. Without it, a body the controller answered before reading
would reset the connection and could lose the answer. That wait still counts
against both caps.

Behind a TLS-terminating proxy, the proxy is the one address all agents share. So:

- Raise the cap to fit the fleet, with
  `landfall-server serve --max-connections-per-source <count>`, and
  `--max-connections` above it. Each agent holds one connection most of the time,
  and briefly another.
- Know what that gives up: any client that can reach the proxy can use up that
  whole allowance of connections, and so keep the agents out, without having a key.
  This cap goes by the connection's peer, which is the proxy, whatever you set.
- Set `[server] trusted_proxies` in the configuration to the proxy's address, so
  that the rate limits, for agents and for people signing in, tell clients apart
  by `X-Forwarded-For`. See [its section](configuration.md#server) for what goes
  wrong if it is wrong.

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

## Installing an agent with `landfall host install`

`landfall host install` does what [the next section](#running-it-under-systemd) and
[enrolling a host](#enrolling-a-host) do by hand, from your own machine, over your own `ssh`. It
makes the user and the state directory, puts the configuration, a verified agent and the units in
place, enrols the host if you give it a code, and starts the agent. Those manual steps still work,
for anyone who won't run a script as root.

**landfall has no release yet,** so there's nothing for this to fetch until the first tag. So far it
has run over a real `ssh`, against a real `sshd`, systemd and `sudo` in a container, with a stand-in
for Docker and for a release. The list of what that can't show is in
`crates/cli/tests/docker_host_install/README.md`.

### What you need

**On your machine:** `landfall` itself, which [first trust](#first-trust) is about, and `ssh`. You
need to have connected to the target once by hand, as an unknown host is refused:

```sh
ssh user@host.example true
```

Compare the fingerprint `ssh` shows with the one on the host, from `ssh-keygen -lf
/etc/ssh/ssh_host_ed25519_key.pub` run there, before you say yes. landfall never accepts a key
itself, and never runs `ssh-keyscan`.

**On the target,** which a read-only probe checks before anything is sent, and says all of what's
missing at once:

- Linux 5.8 and systemd 235 or later, on arm64 or amd64.
- Docker Engine: a client of 20.10 or later, the compose v2 plugin, a `docker`
  group and a `docker.service`. Snap's Docker has another service name. A host with no D-Bus also
  reads as having no `docker.service`, as a login's `systemctl cat` needs the system bus, and so is
  told the same thing: install `dbus`.
- `sha256sum`, `runuser`, `diff` and `timeout`, which `coreutils`, `util-linux` and `diffutils` hold.
- CA certificates, for an `https://` controller.
- Each deployment's compose directory, which is never created.
- A login that's root or has `sudo`, whose shell is a POSIX one. Fish and csh are refused, as what
  they ran could differ from what was shown. Password logins are refused too: `BatchMode` is forced,
  so use a key.

**And a code,** if the host isn't enrolled yet. On the controller, as in
[enrolling a host](#enrolling-a-host):

```sh
landfall-server enrol-code --host home-1 --db /var/lib/landfall-server/controller.db
```

Put it in a file on your machine that only you can read. A code is good for an hour, and for one
host.

### Running it

Look first. `--dry-run` connects, probes, fetches and verifies the agent, and shows you the script.
It changes nothing on the target:

```sh
landfall host install user@host.example --host home-1 --config fleet.toml \
  --controller https://controller.example --code-file code --dry-run
```

`--config` is the fleet file, the same one every host and the controller have, and it goes to the
target as it is. `--host` is this host's id in it, and it must have a deployment there. An `http://`
controller needs `--allow-insecure-controller`, by [the same rule as `enrol`](#enrolling-a-host).

Then run the same without `--dry-run`. For a release other than the one matching your `landfall`,
add `--tag v1.2.3`. You'll see, in this order:

```text
landfall: connecting to user@host.example
landfall: opening an SSH connection to user@host.example: approve it if your key or agent asks
landfall: the agent is v1.2.3, signed by SHA256:..., commit ..., built by https://github.com/..., SHA-256 ...
landfall: the steps are preflight, user, state, config, binary, docker, units, enrol, start
landfall: this is what runs as root on user@host.example:
<the whole script>
landfall: the script's SHA-256 is ...
landfall: run the script with SHA-256 ... as root? [y/N]
```

Read the script: it's what you're agreeing to, and it holds no secret. Its hash differs from a dry
run's, as the upload directory's name is drawn afresh each run, and that one `upload=` line is the
only difference. Saying anything but yes changes nothing. `--yes` skips the question, and without a
terminal you need it.

Next comes `sudo`'s own prompt, if it wants a password. It goes straight to `sudo` over the
connection, and landfall doesn't see it. Then a line for each step as it starts: `landfall: step 1:
preflight`, and so on. **What the target prints during this step reaches your terminal as it is,**
as `sudo`'s prompt needs that, so it's the one place where a hostile host can put text in front of
you.

The last step waits for the agent to hold still with the same invocation and no restarts for 10 s.
Then it exits 0. Check it with:

```sh
ssh user@host.example systemctl status landfall-agent
```

**Remove the code file now.** It's been used, and landfall warned you if others could read it. Next
comes [from nothing to a first deploy](#from-nothing-to-a-first-deploy). The units are the ones shown
below, but for `EnvironmentFile=-/etc/landfall/agent.env`: to give the agent [a token](#github_token),
that's the file to fill, by hand, as root. This never sends one.
`landfall host install --help` has what each exit status means: in short, 0 is done, 1 is refused or
stopped, and 2 couldn't try or finish.

### What's verified, and against what

The agent is fetched by your `landfall` and checked three ways before anything is sent: the release's
tag must be signed by a key your `landfall` holds, in `crates/cli/assets/release-signers`, whose
fingerprints are in `SECURITY.md`; the build-provenance attestation must vouch for this repository's
release workflow, on that tag's commit, and for this exact file under this exact name; and the
release's `SHA256SUMS` must agree. There's no flag for another identity. The script then has root
hash what arrived, against the verified hash written in it, before making it executable.

**This signed tag has nothing to do with a deployment's `origin.signed_tags`.** That's a host's rule
about the releases it deploys, read from its own configuration. This is what the CLI trusts about
landfall's own binaries, and it reads no configuration. A deployment with `signed_tags = false` isn't
affected.

**A rotation** overlaps: one release's `landfall` holds both the old key and the new one and is signed
by the old, and the next is signed by the new. A `landfall` too old to know the signer refuses, says
which fingerprints it trusts, and says that a newer build may trust that key. So get a newer one, by
[first trust](#first-trust) again.

**A build with no key** refuses before connecting, `--dry-run` too. That's a fork, until it changes
`crates/cli/src/project.rs` (its repository and both ids), `crates/cli/assets/release-signers` and
`repository` in the root `Cargo.toml`. It also takes on the environment, immutable releases and
signed tags in `CONTRIBUTING.md`, and publishing its own fingerprint in its `SECURITY.md`.

### What SSH does here

It's the system's `ssh`, so it uses your agent, your `ProxyJump` and your keys, and no key material
comes near landfall. A hardware key, and an agent that asks you to approve each connection, haven't
been tried. Every call forces options ahead of your configuration, so that it can't
weaken them or change what comes back:

- Host keys are checked, and never accepted or updated: `StrictHostKeyChecking=yes`,
  `NoHostAuthenticationForLocalhost=no`, `NoHostAuthenticationForProxyCommand=no`, `VerifyHostKeyDNS=no`,
  `UpdateHostKeys=no`, and `FingerprintHash=sha256`.
- No prompts: `BatchMode=yes`.
- Nothing is forwarded or added to your agent, and no local command runs: `ForwardAgent`, `ForwardX11`,
  `GSSAPIDelegateCredentials`, `AddKeysToAgent`, `Tunnel` and `PermitLocalCommand` are off,
  `ClearAllForwardings=yes`, `RemoteCommand=none`, `EscapeChar=none`.
- A status is the command's own: `ForkAfterAuthentication=no`, `StdinNull=no`, `SessionType=default`,
  `ChannelTimeout=none`.
- `LogLevel=ERROR`, as `QUIET` would hide why it refused, and `ConnectTimeout=30`.
- `ServerAliveInterval=15` and `ServerAliveCountMax=4`, so a connection that has gone away ends within
  about a minute, during the script as well.

Those a build of `ssh` doesn't have are left out, having been asked first, as your configuration can't
set them there either. So your `IgnoreUnknown` still works.

**What you set is still yours:** `ProxyCommand`, `ProxyJump`, `KnownHostsCommand`, `UserKnownHostsFile`,
`Hostname`, `User`, `Port`, `IdentityFile` and `IdentityAgent`, and `--ssh-config` picks another file.
`UserKnownHostsFile /dev/null` makes every host unknown, and so refused. `GITHUB_TOKEN` is never sent:
it's removed from what `ssh` is given, so that `SendEnv` can't send it.

**One connection** carries all of it, so a key or an agent asks once. It lasts 60 s idle, so if you read
the script for longer than that, the next step opens another, with the same line first, and it asks
once more. Take that line as your cue, as `ssh` itself may say nothing of a key waiting for a touch
here. The connection's socket is in a private directory in `/tmp`, which goes when `landfall` ends. If
`landfall` was killed that directory stays, with nothing in it worth keeping, and the connection ends
by itself within 60 s.

**`sudo`:** all of it runs as one `sudo sh -c '<script>'`, with the script as an argument, so that no
file a login can write is run as root. Already root, it runs without `sudo`. At a terminal `sudo` may
ask for your password, and without one it runs `sudo -n true` before anything is sent, and refuses if
that fails. So **a sudoers file has to allow that login `sh`, and `true` too, with `NOPASSWD` if there's
no terminal.** One that allows only named commands can't use this: use the manual steps below.

### What it refuses

Each refusal says what to do. All of these come before anything is changed, but for one, which is said
in its row.

| What it finds | What to do |
|---|---|
| `fleet.toml` or a unit that differs from what it would write | It shows a `diff`. `--replace-config` or `--replace-unit` replaces it, keeping the old file as `<file>.previous`, and restarts the agent |
| Another `landfall-agent` binary | `landfall host upgrade` |
| The unit there and no binary | An agent may still be running from what was removed. `landfall host upgrade`, or stop the unit and remove it to install from nothing |
| No code and no `agent.key` | Give a code |
| A code, with the agent not stopped | `systemctl stop landfall-agent`, as `enrol` needs the lock it holds. The existing key is kept, and a code for a host already enrolled needs `enrol-code --replace` |
| An installed file that's a link, or isn't exactly owner, group and mode `0:0:755` for the agent and `0:0:644` for the configuration and units | Make it that, so that only root can change it and the agent can read it. That's stricter than safety alone needs, and it's one rule. Configuration and units can also be removed, to be written again |
| `/usr/local/bin`, `/etc/landfall` or `/etc/systemd/system` not root's, or writable by others, or `/etc/landfall` writable by a group | Fix it. In the other two, writable by a group is left alone, as Debian's `root:staff` has `/usr/local/bin`, **so that group is trusted:** a link left there isn't followed, but one planted at the right moment could be, and whoever can replace the agent or a unit is as good as root anyway |
| A link at `/var/lib/landfall-agent`, or a file | Move it |
| The agent's user can't reach Docker, checked as that user | Look at the daemon and the `docker` group, and run it again. The configuration and the binary are in place by then, which a rerun takes as they are |
| A `landfall-agent` user with a login shell, another home, uid 0 or a uid another user has | See the next section for what it must be |
| Uploaded bytes that don't match their hash | Look for why. **Two installs at once by one login do this,** as each removes the other's upload: run one at a time |

Without `--replace-*` nothing of yours is replaced: replacing the host's own rules silently would be the
one way this could loosen them.

**A replacement takes effect, or it says it hasn't.** The agent reads its configuration once, so a
changed one or a changed unit restarts it. A stop waits for a deploy in flight, so if the unit is still
stopping after two minutes the command says a deploy is finishing, and that what it ran with stays in
force until that deploy ends. It exits 0, as nothing's wrong. Run it again after that, to see the new
one healthy. That restarts it once more, and nothing else.

### What happens to the code

It goes over `ssh`'s input into a private directory the login owns, last, right before the script. It's
never on a command line, in the script, or in what's printed. The script reads it as the login, so a link
planted there gains nothing, and the agent's user writes it into `/var/lib/landfall-agent/.enrol-code`,
mode 0600, for `enrol`. It's removed on every way out the script can catch, and if the script fails or
never starts, `landfall` removes the upload too.

**What's left if the connection is cut, or the script is killed outright:** the code stays in that
private directory, or in `.enrol-code`, for what's left of its hour. The next run removes both, and
another login's old upload goes after an hour. A cut connection isn't noticed on the target until the
script next prints, so what's running goes on until then.

### An interrupted run

Run it again. Each step looks first and changes only what differs, and each file arrives by rename.
`agent.key` is only ever written by `landfall-agent enrol`, which never overwrites it. If a code was used
before the interruption, the rerun needs none, and if it wasn't, the same one still works, within its
hour. A change that was made and not yet restarted for is held in `/etc/landfall/.restart-pending`, so a
rerun that sees no difference still restarts.

### Upgrading an agent: `landfall host upgrade`

```sh
landfall host upgrade user@host.example --dry-run
landfall host upgrade user@host.example
```

Same verification, the same way of showing and running a script, the same `--tag`, `--yes` and
`--ssh-config`. It replaces only the binary and restarts: the configuration, the units and the key aren't
touched. **Upgrade the agents and the controller together:** see [upgrading](#upgrading).

| On the target | What it does |
|---|---|
| An older version | Upgrades |
| This version, with these bytes | Nothing, and says so, unless an earlier run failed or was stopped before its restart: then it restarts, and watches |
| A newer version | Refuses, without `--allow-downgrade` |
| This version, with other bytes | Refuses, showing both hashes, without `--allow-downgrade`: it may be a hand-built or a tampered binary |
| What doesn't say a version | Refuses, without `--allow-downgrade` |
| No binary, with the unit there | Puts it in place, and restarts. If the binary is there and only the login can't see it, it refuses, without `--allow-downgrade` |
| No unit | Refuses: use `host install` |

When it changes the binary it restarts the unit whatever state it's in, so **it starts an agent you had
stopped,** though it doesn't enable it. If you've stopped an agent to keep deploys off a host, upgrade it
when you mean to start it.

The old binary is kept as `/usr/local/bin/landfall-agent.previous`, unless a restart was still due from
before and one is kept already, as a failed upgrade or one still waiting on a deploy isn't kept over it.
So it's the last one known to have run, which can be one older than you expect. The exception is a host
with no binary at all to begin with, where it can be an earlier failed attempt. It doesn't go back by
itself. If the new one doesn't hold still you get the last journal lines, exit 1, and the command:

```text
landfall: to go back, as root: mv -f /usr/local/bin/landfall-agent.previous /usr/local/bin/landfall-agent && systemctl restart landfall-agent && rm -f /etc/landfall/.restart-pending
```

**Read the journal lines before you run it.** The new agent may not be at fault: with Docker down, say,
no agent can start, and going back doesn't help. Going back with `--tag <good> --allow-downgrade` works
too. Deployed services aren't touched either way. An older agent may refuse state a newer one wrote, as
its records allow no field it doesn't know: there's been only one format so far, so this hasn't come up.

During a deploy it says a deploy is finishing and exits 0,
and the new agent starts when the deploy ends. Run it again after that to see it healthy.

### First trust

`landfall host install` checks a tag's signature, the attestation and the sums every time, against what
the `landfall` you run holds. So **the first `landfall` you get is the one that needs this care.** What
each way of getting it does and doesn't check:

- **`gh attestation verify`,** without `--bundle`:

  ```sh
  gh attestation verify <file> --repo pecheriere/landfall \
    --signer-workflow pecheriere/landfall/.github/workflows/release.yml \
    --source-ref refs/tags/<tag> --deny-self-hosted-runners
  ```

  This checks that these exact bytes were built by this repository's release workflow, on a
  GitHub-hosted runner, from that tag. **It does not check that the maintainer signed the tag:** someone
  holding the owner's GitHub token could pass it with a release of their own.

- **To check that too,** with `tag` set to the tag you're after:

  ```sh
  git clone https://github.com/pecheriere/landfall
  ssh-keygen -lf landfall/crates/cli/assets/release-signers
  sed -n 's/^ssh-ed25519 /landfall-release ssh-ed25519 /p' \
    landfall/crates/cli/assets/release-signers > allowed-signers
  git -C landfall -c gpg.ssh.allowedSignersFile="$PWD/allowed-signers" verify-tag "$tag"
  ```

  Compare what `ssh-keygen -lf` prints with `SECURITY.md`, and with a copy of it you got some other way,
  as a stolen token can change the repository too. Keep `allowed-signers` outside the clone. It needs a
  name in front of each key, as `sed` puts there: `ssh-keygen` says `missing key` of a bare line from
  `release-signers`. Then tie the attestation to the commit that tag names:

  ```sh
  commit=$(git -C landfall rev-parse --verify "$tag^{commit}")
  echo "$commit"
  ```

  **Stop if that printed no commit,** as an empty `--source-digest` checks nothing, and passes. Otherwise
  add `--source-digest "$commit"` to the `gh attestation verify` above. `git rev-parse "$tag"` alone gives
  the tag object, which that flag refuses.

  How much of this has run: the format of `allowed-signers` with `ssh-keygen -Y` and a throwaway key, and
  `--source-digest` on another project's release. `git verify-tag` with that file hasn't run at all, on
  any tag, and there are no tags of landfall's yet.

- **`brew install`** checks only the SHA-256 in the tap's formula, so you're trusting the tap, whose
  formula the owner verified that way and copied by hand. Homebrew itself verifies neither the
  attestation nor the tag.

- **A browser download on macOS** is quarantined, and these binaries aren't notarised, so Gatekeeper
  should stop it, which hasn't been tried on a real release yet. Verify it as above first. Then `xattr -d com.apple.quarantine <file>` lets it run. `gh
  release download` and Homebrew don't set that flag. A file you download is a raw executable, so
  `chmod +x` it.

## Running it under systemd

This is by hand what [`landfall host install`](#installing-an-agent-with-landfall-host-install) does.
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

## API tokens, requests and approvals

Grants live in the configuration. A person signs in with a passkey, and a program holds an
API token, which acts for a principal the configuration names, with that principal's grants.
`approve` is never a token's, whatever the file says. On the controller, as its user:

```sh
landfall-server token create --principal ci --config fleet.toml --db /var/lib/landfall-server/controller.db
landfall-server token revoke --id 3 --db /var/lib/landfall-server/controller.db
landfall-server passkey-invite --principal operator --config fleet.toml --db /var/lib/landfall-server/controller.db
```

`token create` prints the token once, as JSON, with its id. Only a hash is kept, and revoking
works from the token's next use. A token whose principal has gone from the configuration
stops working when the controller next loads it. `passkey-invite` prints a one-time link,
valid for an hour; another for the same person replaces it. [Passkeys and signing
in](#passkeys-and-signing-in) says what happens next.

Send a token as `Authorization: Bearer <token>`. No credentials, or a token that is malformed,
unknown or revoked, all get the same `401 unauthenticated`. With credentials and no grant at
all on a deployment, the answer is the same `404 not_found` as for one that doesn't exist;
with another grant on it, `403 forbidden`. Every refusal to someone who proved who they are
is in the audit log (`request_refused`, `approval_refused`, `cancel_refused`,
`access_refused`), within the budget below.

**To ask for a deploy,** a principal with `request` sends
`POST /api/v1/deployments/{name}/{stage}/requests` with `{"tag": "v1.2.3"}`; a lower version
than the running one, a manual rollback, takes `rollback` instead. The controller makes the
intent itself, from its verified record of the release and the host's last report. The tag
must be a release the watcher verified under this configuration and hasn't refused or put on
hold since. So asking too soon after a new tag, or just after the configuration changed, gets
`409 release_not_verified` until the watcher's next look. Other refusals are
`409`s with a stable code: `request_open` (one open request a deployment), `deployment_busy`,
`host_not_ready`, `release_refused` (what is running already, or a pre-release the rule
doesn't take) and `promotion_pending`. A rollback doesn't wait for promotion.

**To approve one,** `GET /api/v1/approvals` lists what you may see, with each intent and its
challenge, and whether you may approve (`can_approve`) or cancel it (`can_cancel`). `POST
/api/v1/approvals/{id}` takes the passkey's assertion, fresh each time, as `{"assertion": {...}}`. It must be by the caller's own key in `[approvers]`, for exactly
that intent. Approving queues a deploy under a new number, which carries the assertion to the
host. Everything that bears on it is looked at again then. What may pass by itself leaves the
request open, and you can try again: `promotion_pending` if the release isn't healthy for long
enough where it is promoted from any more, `release_not_verified` if the watcher has put it on
hold or hasn't looked at it under this configuration, `host_not_ready` and `deployment_busy`.

**To cancel one,** `POST /api/v1/approvals/{id}/cancel` is for whoever asked, and for anyone
with `approve` or `rollback` on that deployment. A deployment has one open request at a time,
so this is how to get one nobody will sign out of the way. A rollback by someone with `rollback`
does it by itself: it takes the open request's place, which ends as `cancelled` with a reason
naming the rollback. **Revoking a token doesn't touch a request it opened:** that stays open,
and an approver can still sign it, until someone cancels it or it expires. If you revoke a
token because it was stolen, look at `GET /api/v1/approvals` and cancel what it asked for.

A request goes `stale` when the host reports another running digest, `409 request_stale` to
anyone who tries it, and `expired` after 24 hours by the controller's clock, ended by the
watcher's next tick, so that one nobody signs doesn't keep the next one out. None of `stale`,
`expired` and `cancelled` comes back: ask again, which makes a new intent to sign. An approved
request is never queued twice either. If the host then refuses or defers its deploy, the
deployment is free again, and retrying takes a new request, a new assertion and a new deploy
number.

**Each credential has a budget for state changes,** so that one gone wrong can't fill the audit
log or crowd out the agents' writes: 120 at once, refilling at one a second. Each session has its
own, and a principal's tokens share one, so a stolen cookie can exhaust only itself: not the
person's other sessions, their tokens, or signing in, and signing out is never refused by a budget.
So if a session is being used up, the person can still end it. Reads don't count, and neither use
comes near it in normal work. Over it, a call gets `429 rate_limited` with `Retry-After`, and
writes nothing. The count of those goes in an `access_throttled` audit row, with how many were
`dropped`, at the next call within the budget or within one watcher interval, whichever is
first, and when the controller stops. It names the principal and whether by `token`, `session` or
`sign_in`, and no particular token, since it can be another of the principal's that comes next: to
find which, look at the rows around it. The count is kept in memory, so a crash loses one not yet
written.

The budget is what bounds a credential gone wrong, not a promise of a small log: one write
transaction a second, with rows of one to two KiB from a hostile caller and two rows a call for
a rollback that supersedes a request. That is **some 80 to 170 MB of audit log a day for each
credential** until it is revoked. A person's sessions come to at most sixteen times that, as a
principal keeps sixteen, **plus 120 state changes for each sign-in spent,** since each new session
starts with a whole budget. A principal has ten sign-ins at once, with one more every five minutes:
some 288 a day for each run of the controller, or about 35,000 more state changes, in the hands of
someone holding that key. A restart gives the sign-ins back, as it does every budget, so each restart
adds up to ten more. `access_throttled` and a jump in `request_refused`, `approval_refused` or
`request_cancelled` rows are worth an alert.

**Only a passkey that verifies and may sign in spends a sign-in,** so a stolen cookie, a stranger, or
a key that is barred can't. But the budget is the principal's, so someone holding the same key can use
it up and keep the owner from signing in for as long as they go on. Sessions already open aren't
affected. Over it, a sign-in gets `429 rate_limited` with a `Retry-After` of the seconds until the
next one, up to 300. If that's happening, the key has to go: for an approver, put a new key in the
file; for anyone else, have them register again from a new invite.

**A state change with a session and a bad `Origin`** is refused before it costs anything: it spends
no budget, and writes no row of its own. `SameSite=Strict` doesn't stop a page on a sibling
subdomain from sending the cookie, as that is the same site, so this must be free. They are counted,
and written as one `access_refused` row each watcher interval, with how many `attempts`, when the
first was and from where. A jump in those means someone is sending a person's cookie from another
origin, and it may be their browser doing so at a page's bidding.

**A request nothing can read** (`request_unreadable`, 500), from a hand-edited or damaged
database, costs only itself. The controller's log names its row, it is left out of `GET
/api/v1/approvals`, and it can't be approved or cancelled by id. It still ends by itself, and a
rollback can still take its place, and reports from hosts are recorded whatever it holds.

## Passkeys and signing in

The pages are `/passkeys/register`, `/sign-in` and `/approvals`. They are served by the
controller, and need the configuration's `[approval]`: with none, registering and signing in
answer `503 approvals_not_configured`.

### HTTPS and the RP ID

**WebAuthn only works in a secure context,** and the session cookie is `Secure`, so people reach the
controller over `https`, though it serves plain HTTP itself. Something in front of it has to
terminate TLS. Either of these fits:

- **A tailnet name, with `tailscale serve`** forwarding to the controller's `--listen` port. The
  name is the machine's, such as `landfall.example-tailnet.ts.net`, and is reachable only on the
  tailnet, which suits a controller that nothing outside needs.
- **A TLS-terminating reverse proxy** of your own, with a certificate for a name you own.

Whichever it is, **it must leave `Origin` as the browser sent it,** or every state change is refused
with `bad_origin`, and it should be listed in [`trusted_proxies`](configuration.md#server) if it
appends to `X-Forwarded-For` (see [the limits](#limits-for-what-anyone-can-send) for what
happens if it isn't). Check for your proxy that it does both.

`[approval]` then holds what the browser's address bar shows, and that hostname alone:

```toml
[approval]
origin = "https://landfall.example-tailnet.ts.net"
rp_id = "landfall.example-tailnet.ts.net"
```

**A passkey belongs to its RP ID,** so moving the controller to another name takes a new passkey
from everyone and a new line in the file for each approver, since a browser won't offer the old one
there and hosts wouldn't accept it. Pick the name you mean to keep. `origin` and `rp_id` are in the
file hosts hash too, so changing them means every host has the new file before it gets more work.
[The configuration](configuration.md#approval) has the exact rules.

**What has and hasn't been tried.** The ceremonies have run in Chrome with its virtual
authenticator, over a throwaway certificate on `https://localhost` with the test's own TLS
terminator, and with a software authenticator through the real routes end to end. **They have not
run through `tailscale serve` or any production proxy, or on a real device: no phone, no synced
passkey, no hardware key.** Safari's rules on when a ceremony may start and how a password manager's
extension behaves are both unknown here, so try a registration and a sign-in before you rely on
them, and keep the way back in [Losing a passkey](#losing-a-passkey) in mind.

### From nothing to a first deploy

1. Start with a file that has `[approval]` and no deployments, as a deployment needs an approver,
   who needs a key. Run `serve` with it.
2. `landfall-server passkey-invite --principal operator --config fleet.toml --db controller.db`, and
   open the link it prints.
3. Create the passkey. The page shows a line for `[approvers]`. Copy it into the file, and add the
   deployment, with `operator` in `rule.approvers`, and the grants:

   ```toml
   [approvers]
   operator = { credential_id = "...", public_key = "..." }

   [[grant]]
   principal = "operator"
   deployments = ["app/prod"]
   can = ["view", "request", "approve", "rollback"]
   ```

4. Have it reviewed, comparing the fingerprint with the one the page showed, and put the same file
   on the controller and on every host. Restart `serve`.
5. [Enrol the host](#enrolling-a-host) and start its agent. The watcher looks at releases when it
   starts and every five minutes after that, and records the release as `manual`. Nothing starts.
6. Ask for the release: `landfall-server token create --principal operator ...` gives a token, which
   goes with `POST /api/v1/deployments/app/prod/requests`. No page has a button for asking yet.
7. Sign in at `/sign-in`, open `/approvals`, check what it shows, and approve with your passkey. A
   token can't do this step. The host checks what you signed for itself, and runs it.

Later releases go by the rule. What takes an approval waits as `needs_approval` or `manual`, and
steps 6 and 7 are how it goes on. A lower version is [a manual
rollback](#api-tokens-requests-and-approvals), and a release that rolled back is
[retried](#a-release-that-rolled-back-isnt-retried), the same way.

### Registering, and who signs in as whom

**To register,** open the link `passkey-invite` printed and create a passkey. The code is after
the `#`, so it reaches no access log, and the page takes it out of the address bar at once. A
wrong, used or expired code all get the same `403 invite_refused`. Only a registration that
succeeds spends the code, so a cancelled dialog costs nothing, and of any number at once one
succeeds. The page shows the credential id, public key and fingerprint, and a line to copy under
`[approvers]` by pull request. Hosts trust a key only from that file. The controller keeps its own
copy, for signing in. No attestation is checked: what makes a key trusted is that someone reviews
it. Compare the fingerprint in the pull request with the one the person saw. **Accepted residual
risk (design 6.3):** a compromised controller could show its own key during registration.

Registering again replaces the person's stored key and ends their sessions. The passkey must be
discoverable, as signing in names nobody, so **a security key that can't hold a discoverable
credential can't be used.** Registering again on the same authenticator replaces its credential
for this controller: if the old one is in the configuration, update that too.

**Whose key opens a session:**

| The credential is | Signs in as | By |
|---|---|---|
| An `[approvers]` entry's | that approver, registered here or not | the file's key |
| Stored here, for a principal with grants and no `[approvers]` entry | that principal | the stored key |
| Stored here, for someone with a different `[approvers]` key | refused | |
| Stored here, for a principal the file doesn't name | refused | |
| Anything else | refused | |

So a key that is registered and not yet reviewed can only be copied off the page, if its owner
is or will be an approver. **An invite is only as trusted as its link:** a leaked one for someone
with grants and no approver's key does open a session, with what those grants allow, which is why
it lasts an hour and why every registration is in the audit log. It never gets `approve`, which
takes a key in `[approvers]`.

**A session** is 32 random bytes, kept only as a SHA-256, in a `__Host-landfall-session` cookie
(`HttpOnly; Secure; SameSite=Strict; Path=/`, no `Domain`), for 12 hours. Each sign-in makes a new
one, and any the browser came with ends. It has no power of its own: every use goes by the
configuration's grants, and it stops working once the file no longer names the principal. Sixteen
at most are kept for a principal, the oldest ending first. `POST /sign-out` ends one on the server.
**Approving always takes a fresh assertion,** so a stolen cookie can't approve anything.

**What a session outlives.** Whether a key may sign in is decided when it signs in, so a session
goes on after that changes. If someone with a stored key is added to `[approvers]` with another key,
a session from the stored key lives up to 12 hours more. It can do what their grants say, and still
can't approve, since `approve` takes the file's key. The stored key also wakes up by itself: if its
owner is later named in the file with no `[approvers]` entry, or taken out of `[approvers]` but left
with a grant, it signs in again. If that isn't what you want, end it by registering.

**To end someone's sessions:** have them register again from a new invite, which replaces the stored
key and ends every session of theirs. To do it without them, take them out of the file: their
sessions stop working when the controller next loads it. There is no command for one session.

Every failed sign-in gets the same `403 sign_in_refused`, whether the credential is unknown, the
signature bad, or the key one that may not sign in, and nothing before that names anyone. Each
challenge lasts five minutes and works once, and a sign-in's can't finish a registration.

### Limits, for what anyone can send

Every `POST` here wants the exact `Origin`, or
`403 bad_origin`. Each `begin`, and each `finish` that turns out bad, comes from a bucket per source:
30 at once, refilling at two a second, apart from the agents' so that a flood leaves them their
nonces. Over it is `429 rate_limited`. A `finish` with a live challenge and a good answer costs
nothing and can't be refused for this, so a tap once made isn't wasted by someone else's flood.
Sign-in challenges are in memory, 65,536 at most, each holding its place for its five minutes: a
full table answers `503 ceremonies_busy` and keeps every challenge it has, so nobody's can be pushed
out. Beginning writes nothing to the database. Neither limit touches anyone's budget, a session
already signed in, or an approval.

**Behind a proxy, set `[server] trusted_proxies`** ([configuration](configuration.md#server)).
Without it the source is the connection's peer, so all clients are one source, and anyone sending
two `begin`s a second can keep everyone from beginning a sign-in for as long as they go on. When
sessions have expired, nobody can then approve. With it, each client has its own bucket, and it
takes many addresses to do that. Limit these paths at the proxy too if it faces the internet.

### In the audit log

`passkey_registered`, `signed_in` and `signed_out`, each with its change.
Failures are counts, since anyone who knows a credential id could cause them. One row each watcher
interval for each principal, kind and reason, and when the controller stops, each with how many
`attempts`, the `reason`, `first_seen`, up to eight `sources` and how many attempts came `from_others`:

- **`sign_in_barred_key`: treat this as an alert.** A signature verified by a key registered here
  that may not sign in, so someone holds that key: a leaked invite, or an old device. Nothing a
  sender does afterwards changes this row.
- `sign_in_refused`: a signature that didn't verify on a known credential. A credential id may be
  public, so this says little about who sent it.
- `registration_refused`: a good invite's code with a ceremony that didn't check out.

Each also goes to the capped log as it happens, with who it came from. A crash loses a count not yet
written. A failure naming nobody goes only to the capped log.

### What a lying controller page can and can't do

A person can't read a challenge. It is the hash of an intent, so a passkey signs what the page
hands it, and the page comes from the controller. If the controller is compromised, then:

**It can** show you one release and have you sign another, on any deployment whose `rule.approvers`
lists you. That includes a lower version, so a tap can be turned into a rollback to an old release,
and an old release may have bugs a newer one fixed. It also includes a release on this host's
[record of failures](#a-release-that-rolled-back-isnt-retried), which an approval retries. It can do
the same with a tap meant for signing in. It can then hold what you signed and deliver it later,
since a host has no clock it trusts, for as long as the digest it names is running. It can show its
own key at registration in place of yours, which is why a key is reviewed and the fingerprint
compared. And it can say anything it likes in its own pages and its own audit log, including leaving
your tap out or writing one that never happened.

**It can't** run anything without a tap, as hosts check a signature by the key in their own file:

- **Sign for you.** An approval made up with another key, or with another credential, is refused.
- **Use your tap on anything but what it signed.** Carried to another release, the challenge doesn't
  match, and it is refused. It covers the deployment, the tag, the commit, the digest, what must be
  running, and a nonce.
- **Install what doesn't verify.** The host verifies the release for itself, and a digest or commit
  other than the one signed is refused. With `origin.signed_tags` on that means a maintainer-signed
  release. With it off, it means whatever that workflow built for a tag.
- **Use a tap twice,** or after the host has moved on. Only the digest it names, and only once,
  however the database is restored and whatever number it comes under.
- **Run what a rule refuses,** which is the version already running or a pre-release the rule
  doesn't take.
- **Burn your approval by asking wrongly.** A refusal spends no nonce. Only a good approval is
  spent, just before the deploy starts, [but for two failures of the
  disk](#an-approval-is-verified-on-the-host).

**A sign-in tap is `webauthn.get` too,** the same kind as an approval. So a compromised controller
could put a request's intent hash in a sign-in ceremony, and a person signing in would have approved
it without knowing. It is within the residual risk of design 6.3: the ceremony runs on the
controller's page, which can already show one thing and have another signed. The host still only
runs a release that verifies for that deployment, which is maintainer-signed if `origin.signed_tags`
is on, from the digest it is running. The page can't prove what it asks you to sign. Computing the
hash on your own machine is the stronger path, and is planned as `landfall approve`, which doesn't
exist yet.

**How you'd know.** Each of these refusals leaves the service alone and goes in the host's journal
as `controller_work_refused` at priority 2, which is the record the controller can't change, so
alert on that, and then [read it](#reading-a-refusal-at-priority-2), as some have honest causes. The
controller's `deploy_refused` audit row has the reason too, as long as it is honest. What the page
can't be caught by is a good signature over something you didn't mean: compare
`approval_about_to_be_spent` in the host's journal, which names the approver and the release, with
what you approved. `crates/agent/tests/e2e/approvals/` shows the refusals, with the controller's
database written to directly.

### Losing a passkey

**Nothing stops.** The service keeps running, automatic deploys and automatic rollbacks take no
passkey, and a session already open goes on. What waits is whatever takes an approval by that key.
If another approver is listed for a deployment, they can sign in the meantime. `[approvers]` holds
one key for a name, so a second device means a second name, listed in the same `rule.approvers` and
with an `approve` grant of its own, since the file doesn't ask for one and the controller won't let
that name approve without it. Have one before you need it. Nothing in the controller can stand in
for the file, so with no approver left it takes someone who can change the file on every host.

**For an approver:**

1. On the controller, `landfall-server passkey-invite --principal <name> ...`, and register a new
   passkey from its link. That needs no sign-in. It replaces the stored key and ends that person's
   sessions. The new key can't sign in yet, and trying gets `sign_in_barred_key` in the log:
   expected, this once.
2. Replace the person's line under `[approvers]` by pull request, comparing the fingerprint.
3. Put the file on every host and the controller, and restart them all, as each reads it once. A
   host with the old file gets no work until it has the new one, and the release needs the watcher's
   next look under the new file before it can be asked for.
4. From then on the old key is nobody. An approval it signed that hasn't reached the host yet is
   refused there at priority 2, which is expected this once: ask again and sign with the new key.

**For someone with grants and no key in `[approvers]`:** only step 1. The stored key is all there
was.

**If it may have been stolen and not lost,** do the above at once, and read back from when it went:
the controller's `signed_in` and `request_approved` rows, and `approval_about_to_be_spent` in each
host's journal. A thief with only the passkey can sign in and approve what's asked, with that
person's grants. Until each host restarts with the new file, it still accepts that key's signature.

**These steps can leave the thief a session.** Step 1 ends the sessions that exist, but until the
file changes the old key can still open a new one, as the file's key decides. That session outlives
the restart on the new file. It keeps the person's grants, so it can ask, roll back and cancel, and
it can't approve, which takes a fresh assertion by the key now in the file. It ends after its 12
hours, or when the person registers again, which is one more key and one more change to the file. So
make the file change quickly after step 1.

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
  `Auto`, or an approval this host verifies itself comes with it. A first deploy, a
  downgrade, or a step that needs an approval is refused without one. The version already
  running, or a pre-release the rule doesn't opt in to, is refused with one too.
- The release verifies, with this host's own trust root, and to the digest and the
  commit the controller named.

What isn't so is answered in one of two ways, and nothing runs either way:

- **`refused`, for good:** the rule says no, an approval isn't good, a verification result
  failed, or the release is on this host's record of failures. It is journalled as
  `controller_work_refused`, and the controller doesn't ask again. For a request the rule,
  an approval or verification refuses that is priority 2, critical: **treat it as an
  alert**, since it is how a lying controller shows. An honest controller decides by the same
  rule and mostly doesn't ask, but it can get here in a few ways, so
  [read it](#reading-a-refusal-at-priority-2) before you decide what it means.
- **`deferred`, not now:** an unfinished deploy, drift, state or evidence that can't be
  read, a clock behind the release, or a wait for verification that has reached its bound.
  All of these pass. It is journalled as `controller_work_deferred`, at priority 3, error,
  or 4, warning, for a clock or a wait, and the host's next poll is backed off. The
  controller records the release as `deferred`, and asks again under a new number after a
  wait of one look, five minutes, doubling each time it is told so, up to six hours.
  There is no last try. A newer release doesn't wait for it, older ones do, and the host
  judges each try as it would any other.

What it can do: withhold work, ask again, carry an approval a person gave, and see what the
host reports. It can also make the host deploy a release that is allowed by all of the above sooner than
promotion rules on the controller would, which are controller-enforced only. A deployment
with `origin.signed_tags = false` has less to go on: a release is then whatever the
configured workflow built for a tag, so someone who can push a tag and run that workflow
needs no controller to ship one.

What it holds is less than it might seem: the agents' public keys, the configuration, and
a GitHub token with no scopes. It never connects to a host, and no key it holds opens one.
Its audit log is its own account of events, and [the limit of that](#keeping-the-audit-head-elsewhere)
applies. The host's journal is the record the controller can't change.

### An approval is verified on the host

A first deploy, a downgrade, a step the rule leaves to `approve` or to nobody, and a retry
of a release that failed here each run only on a person's approval. The controller carries
it and can't make one. The host checks all of this itself, and an approval that fails any of
it is `refused` at priority 2, with the reason in full in the host's journal, up to 255
characters of whatever origin or type the assertion claimed. **Read it there:** the report
carries 4,096 characters of it, and the controller keeps 1,024 on the deploy and in the
`deploy_refused` audit row, escaped.

- Its deployment, tag, commit and digest are those of the work, and the commit and digest
  are what the release verifies to here.
- Its expected running digest is what the host's own `deployed.json` says: nothing on record
  matches only an approval for a first deploy. It is compared again under the deployment's
  lock, just before the deploy starts, and that lock is held from there on. A `recover`
  holding the lock makes the work wait, with nothing spent.
- The credential is that of an approver in this deployment's `rule.approvers`, in this
  host's file. Another deployment's approver is nobody here.
- The assertion is signed by that key over this intent, with the configured origin and RP ID,
  and with user presence and verification. Each field off the wire is capped before it is
  decoded.
- Its nonce isn't in the [nonce log](#the-nonce-log).

An approval attached to a deploy the rule makes automatic is ignored and isn't spent, even
if its assertion is garbled: the assertion's fields are only read when the approval is. Its
`intent` is another matter. It is parsed with the rest of the work, so an intent that doesn't
parse, a bad nonce say, fails the whole answer, whatever the rule says of the deploy. The
host reads that as `controller_unavailable` at priority 4, warning, and retries with its
backoff, and nothing runs. An approval never overrides the version already running or a
pre-release. If that automatic deploy fails and rolls back, the same unspent approval is accepted
as the manual retry of the failed release, and is spent then, so an `approval_about_to_be_spent`
line can come some time after the tap, with no request in between.

**An approval works once, whichever way the deploy ends.** It is spent after everything
above has passed, and before the deploy touches a file or Docker. A deploy that then fails
or is interrupted has used it, and a crash between the two leaves it spent with the service
as it was: the controller delivers the work again, the host refuses it as already spent, and
it takes a new approval.

**Refused or deferred on the way there, an approval is not spent,** so someone without the
passkey can't use it up by asking wrongly. There are two exceptions, both at the moment of
spending, and both fail safe, since nothing runs: writing the nonce running past its
60-second deadline on a hung disk, which defers, and an error from syncing it to disk, which
refuses. The nonce may be on disk or not after either. If it is, the approval is spent, and
it takes a new one.

**An approval has no expiry, as the host has no clock it trusts.** One that was never spent,
held back by a controller say, stays good indefinitely. It works if it is delivered later,
as long as what it names as running is running then, and that includes a digest that has
gone and come back. What it can install is still only the one release it names, verified here.

#### Reading a refusal at priority 2

Nothing ran. Nothing was spent either, unless the reason says the nonce was spent already, or that
the nonce log can't say, where [a failed sync](#an-approval-is-verified-on-the-host) may have left
it on disk. The reason is in the host's journal, `journalctl -u landfall-agent.service`.

**A lying controller can bring about most of these reasons too,** so a row only clears a refusal if
its check holds, and each check is something the controller can't make so.

| Reason | Honest cause | The check |
|---|---|---|
| `it is for a host running <A>, and this host has <B> on record` | The host moved while an approval was queued, which can't be cancelled yet ([#30](https://github.com/pecheriere/landfall/issues/30)). | [What moved it](#what-moved-the-host), below. |
| That, `is the version already running`, or `was already spent on this host` | The controller was [restored from a backup](#backing-up-and-restoring) holding that approval. | You restored it, just before this. |
| `no approver in this host's configuration has credential` | The approver's key was [replaced](#losing-a-passkey) while the approval was on its way. | You changed the file just before this, and the credential is the old one. Any other is an alert. |
| `credential <id> is <name>'s, who is no approver of this deployment` | That person was taken out of `rule.approvers` while the approval was on its way. | You changed the file just before this, and that is who you took out. |
| `clientDataJSON origin: expected <new>, found <old>` | `[approval]` changed while the approval was on its way. | You changed the file just before this, and `<old>` is what it was. |
| `no approval came with it` | An automatic deploy was queued, and the rule or what runs changed so that it no longer is. | You changed that just before this. A controller making up work looks just like this, so without that it is an alert. |
| `this host's nonce log can't say` | [The log](#the-nonce-log) is damaged, full, or has the wrong owner or mode. | A `nonce_log_unusable` line, and the file itself, which the controller can't reach. |
| `was already spent on this host` | A crash just as the approval was spent. | [Telling a crash from a replay](#telling-a-crash-from-a-replay). |
| `verification: release run: the release was attested by <N> workflow runs` | A second run for that tag came after the watcher recorded the release, as it doesn't look again at one that isn't automatic ([#30](https://github.com/pecheriere/landfall/issues/30)). | The repository's runs for that tag show a second one, which by GitHub's times started more than five minutes, one look of the watcher, after the first finished, and the rule doesn't make this move automatic, as an automatic one is looked at again. Otherwise it is an alert. A lying controller can't start a run, though it can deliver a tag someone else re-ran: **check who started the second run.** |
| `verification: platform: the image has no <platform> platform` | The release isn't built for this host's architecture, which the watcher doesn't look at, having no platform of its own. | The list the reason gives leaves this host's out, and `landfall verify --platform` says the same. |

**Every other `verification:` reason isn't explained by this table:** a tag signature, an
attestation's identity or the digest rule says the release is not what the file allows, whatever a
repository's runs look like.

##### What moved the host

`deployed.json` moves only by a deploy or a rollback of the agent's own, `recover`'s included, so
`<B>` should have `deploy_step` and `deploy_finished` lines. A `docker compose` by hand doesn't move
it, and shows as [drift](#drift). Those lines look the same whoever asked for them, so go by **the
unit they are under:**

- **`journalctl -u "landfall-agent-recover@$(systemd-escape app/prod).service"`:** someone ran
  `recover` on the host, which the controller has no way to start. **This clears it only if
  `recover` ran between your tap and this refusal,** by the host's journal time and your own memory
  of the tap, as the audit log's times are the controller's, the agent was down in between or the
  tap was moments before, and you can find out who ran it. Otherwise the approval was held, as the
  agent delivers at its next poll. A `recover` before your tap can't explain it either, since the
  intent would then have named `<B>`. Each of those is an alert.
- **`journalctl -u landfall-agent.service`:** the controller delivered it, and **nothing here clears
  that: treat it as an alert.** The controller chooses when to deliver and serves the page, so it
  sees when you open it and can time a deploy to any moment around your tap, or hold an approval for
  weeks. We know of almost no honest way: it would take an agent stopped within seconds of finishing
  that deploy, before its next poll said what runs, with the request asked for and signed while it
  was down, and its stop would show in the host's own journal.
- **You can't find it:** assume the worst, and then check whether the state directory was rebuilt or
  restored, which moves the record with no line, whether the journal is volatile or was vacuumed,
  and whether someone ran `recover` at a shell, whose lines went to that terminal and whose report
  is under `<deployment>/reports/`.

**What to do:** if a check holds and you still want the release, ask again, which makes a new intent
for what runs now. That doesn't help two kinds. For `attested by` and `platform`, verification gives
the same answer each time, and each try costs a ceremony and another critical alert: that release
can't be deployed there, and it takes a new release. For `this host's nonce log can't say`, put
[the log](#the-nonce-log) right first, or the next one is refused too.

**A reason that isn't listed, or a check that doesn't hold, is an alert to investigate.** It isn't
proof of a lying controller, as this list may not be whole, but nothing here clears it. `the
signature does not verify` and `clientDataJSON challenge` have no honest route we know of.

#### Telling a crash from a replay

Every delivery of a spent approval is refused with `was already spent on this host, and this
delivery changed nothing on the service`, naming the nonce. The host can't tell why it came
again, and you can, from its journal, by searching for that nonce.

The journal says `approval_about_to_be_spent` just before the host tries to spend a nonce,
naming the approver, the deployment and the release. The line doesn't prove it was spent: it
also appears with nothing spent, when the log turned out to be unusable, something held its lock
or another writer got there first. So if a `nonce_log_unusable` line follows it, or the nonce isn't in the log, read
it as an attempt. Otherwise, going by what follows it:

- **A crash before the deploy started:** this tag has no `deploy_step` lines after it, and the
  agent restarted. Honest: the controller redelivered work the host had claimed. It takes a new
  approval.
- **A deploy that ran and was then recovered or rolled back, redelivered:** the tag has
  `deploy_step` lines, its `deploy_finished` isn't a success, or a `recover` ended it, and the
  agent restarted around then. This can be honest too: a controller that lost track of how the
  deploy ended delivers it again. The agent's restart, in the host's journal, is what counts. The
  controller's restart and what it says about that deploy count for little, as a lying one can
  restart itself and say what it likes. If you still want the release, it takes a new approval.
- **A replay:** the tag has `deploy_step` lines and its `deploy_finished` succeeded, the report was
  delivered (`report_delivered`, by the deploy's number), and the controller wasn't [restored from
  a backup](#backing-up-and-restoring), yet the approval has come again under a later number. Treat
  that as an alert. It gets nothing from it, as the approval is spent.
- **No such line at all, for a nonce in the log:** the log was changed by something other
  than the agent, or the journal has lost it. Treat it as an alert.

### The nonce log

`approval-nonces.log` in the state directory has one line per spent nonce, 64 lowercase
hex digits and a newline, for the whole host. A line is appended and synced to disk before
the deploy starts. Only an approval that has verified is written, so what grows it takes a
person with a passkey. It is full at 65,000,000 bytes, a million approvals.

**A log that can't be used refuses every approval, and automatic deploys go on.** That is one
that is torn, holds anything but those lines, is full, is a symlink or anything else but a
regular file, belongs to another user, or is writable by group or others. The journal says
`nonce_log_unusable` at priority 2 when the agent starts and at each approval refused for it,
naming the file, and its `error` says which. Nothing repairs it for you:

- **A torn last line** is what a crash in the middle of an append leaves, and the file's
  size isn't a multiple of 65 bytes. The deploy it was for never started. Remove only that
  partial last line, and leave the whole lines alone. A write that merely fails, on a full
  disk say, takes its partial line back by itself; this is only for when that failed too.
- **Full** is a log doing its job for a long time, not damage. To go on, move the oldest
  lines to an archive, keeping them. See below for what that gives up. Keep the mode 0600,
  and stop the agent while you do it, so that nothing appends to the file in between.
- **A wrong owner or mode, or a symlink or other file in its place:** put right what it is.
  Nothing written by the agent gets to be any of these, so find out what did it.
- **Any other line that isn't a nonce** means something other than the agent has written
  there. Find out what, and restore the file from a backup if you have one.

**A lock held on the log makes the work wait.** Nothing but the daemon locks it, so this is a
process you ran as the agent's user or root. After a second of trying, nothing is spent, the
journal says `work_waiting` naming the file, and the work is tried again at the next poll, so it
goes on once the lock is let go. This has no bound, and meanwhile the claim holds up the host's
other deployments, so find what holds it. While it is held to read, each poll verifies the release
again and writes `approval_about_to_be_spent` again, at the backoff, so don't count those lines as
taps when reading for a replay.

**Taking a line out of the log reopens replay for that nonce, so only archive when you accept
that.** The agent doesn't read an archive, and the controller that delivered every approval
has seen them all, so assume a compromised one still holds each of them. What still bounds it:
an approval only works while the digest it names as running is the one on record, so it can
only ever take the deployment from that same running digest to the one signed release it names.
Older lines are less likely to name a digest that is running, which is why they are the ones to
move, but that is a likelihood and no more: a rollback to a long-lived digest, A to B and back
to A, can reopen an old approval that named A. Removing the whole file forgets every approval
this way. The agent reads the file afresh for each approval, so none of this needs a restart.

### A release that rolled back isn't retried

**A release that rolled back on this host isn't retried automatically; a newer release
is.** Retrying the same one takes [an approval](#an-approval-is-verified-on-the-host), even
when its rule would otherwise make it automatic, and a deploy of it that succeeds takes it
off the record. Both ends know. The controller records `rule_decision` `refused` with `it already rolled
back on its host`, and doesn't queue it again. The host goes by its own record,
`<deployment>/failed-releases.json`, the tag and digest of the newest 1,024 releases that
failed here, written before the report is sent; and after that by the engine's reports
under `<deployment>/reports/`, in case a `recover` the daemon didn't see ended one, unless
a report says the release has deployed since. The record is what counts, so removing old
reports doesn't forget a failure.

**Evidence that can't be read holds up the deploy.** If the record or any of the engine's
reports can't be read, it could be about the release at hand, or the next one, so no
deploy of that deployment goes ahead, with an approval or without: each is deferred, and an
approval isn't spent. The journal says
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
