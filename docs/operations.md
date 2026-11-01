# Operating the agent

`landfall-agent` runs on every host that deploys a service. This guide covers
what a host needs and what to do when a deploy goes wrong. The design is in
[`design/landfall.md`](design/landfall.md), section 7, and the configuration
file in [`configuration.md`](configuration.md).

The agent does not yet have a long-running command: it will get one with the
controller loop. Today it has `status` and `recover`, and the deploy engine runs
as a library.

## Requirements

- **Linux 5.8 or later.** Copying a symlink into a backup sets its owner and
  times through an `O_PATH` descriptor, and `utimensat(2)` takes `AT_EMPTY_PATH`
  since Linux 5.8 (`fchownat(2)` has taken it since 2.6.39; both per their man
  pages). On an older kernel a backup that holds a symlink fails. With
  `stop = true` the service has stopped by then, and the rollback restarts it on
  the previous version; the data is not touched.
- **Docker with the compose plugin**, reached through the `docker` client on the
  agent's `PATH`.
- **A synchronised clock (NTP).** Origin verification compares the transparency
  log's time with the host's: a clock running behind refuses a fresh release.
  Log windows and backup names also go by the host's clock.

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

- Run `docker compose` from the directory's real path, with `compose.yaml` in it.
  The agent finds a service's container by the working directory compose labels it
  with, and through a symlink that label is the symlink's path, so `status` would
  report such a container as not running.

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
failed rollback is priority 2, critical.

## HTTP checks

An `http` check connects from the host to the container's address on the named
Docker network. On Linux a host reaches its bridge networks unless a firewall
forbids it, which is worth trying once with `curl` from the host: the check has
no way to tell a firewall from a service that is down. Docker on a Mac has no such
route, so these checks only work on Linux.

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
- **The newest 3 backups are kept** per deployment. **Reports are not pruned
  yet** ([#14](https://github.com/pecheriere/landfall/issues/14)): they are small
  JSON files under `<state dir>/<deployment>/reports/`, where the deployment's
  `/` becomes `__` (`/var/lib/landfall-agent/app__prod/reports/`), one per deploy,
  and removing old ones by hand is safe.

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
{"deployment":"app/prod","dir":"/srv/compose/app","deployed":{"deploy_id":"...","tag":"v1.2.3","version":"1.2.3","digest":"sha256:...","commit":"...","deployed_at":"2026-11-01T10:00:00Z"},"in_progress":false,"override_file":"pinned","running_image":"\"ghcr.io/example/app@sha256:...\"","drift":false,"error":null}
```

- `deployed` is what the agent last recorded, or `null`.
- `in_progress` means a deploy started and did not finish; see below.
- `override_file` is `missing`, `placeholder`, `pinned`, or `unrecognised` when the
  file isn't one the agent wrote for this service. A missing one is a state to
  report, not a failure: it is what a host looks like before its first deploy.
- `running_image` is the running container's word, so it is quoted and truncated
  as any text from a container is, and `null` if none is running.
- `drift` is true when a running container's image is not the one the override
  file pins, or the file is `unrecognised`, whatever `.env` makes of the project.
  With nothing pinned, or nothing running, it is false. During a deploy a
  difference is expected, and `in_progress` says so.
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

It takes the same rollback path as a failed deploy: the previous override, the
backup if one was completed, start, verify, checks. If the deploy had in fact
finished and only the clean-up was left, it finishes that instead. A deployment
with `rollback_failed` in its report also stays blocked until `recover` succeeds.
It prints the report as JSON on stdout.

| Exit | Meaning |
|---|---|
| 0 | the previous version is back, or there is none and the service is stopped, or the deploy had finished |
| 1 | the rollback failed; deploys stay blocked. Fix the cause and run it again |
| 2 | it could not run: usage, configuration, state, another process holding the lock, or nothing to recover |
