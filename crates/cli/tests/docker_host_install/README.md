# `host install` against a real `sshd`

These tests run the real `run_with` over the real `ssh`, into a throwaway container running real
systemd, `sshd`, `sudo`, `useradd`, `install` and `runuser`, with the real agent and controller.
They are `#[ignore]`d and named `docker_`, so they don't run in the normal suite. CI runs them in
the `host-install` job. Run them by hand after changing `crates/cli/src/host/`.

## What they need

Docker, `ssh`, `ssh-keygen`, and `nc` for one line of a config. No root, and no network beyond
what building takes.

```sh
docker buildx build --target binaries --provenance=false --sbom=false \
  --output type=local,dest=<scratch dir>/dist .
docker build -t landfall-test-sshd crates/cli/tests/docker_host_install
LANDFALL_TEST_DIST=<scratch dir>/dist cargo test -p landfall-cli --locked -- --ignored docker_
```

Rebuild `dist` after changing the agent or the controller: the script and the CLI's own code come
from the test's build, and these two from `dist`. They take about 80 s on a 10-core Mac, of which
70 s is one test waiting out `ControlPersist`. A test that's killed outright leaves its container:
`docker rm -f -v $(docker ps -aq --filter label=landfall-test-sshd)`.

## The container

```sh
docker run -d --cap-add SYS_ADMIN --security-opt apparmor=unconfined --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock -p 127.0.0.1::22 landfall-test-sshd
```

It has **no host mounts and no `--network host`,** and its port is published on `127.0.0.1` only.
Binaries go in with `docker cp`. Each test has its own, removed when the test ends, and its own
throwaway key and `ssh_config`, with `IdentityAgent none`, so nothing reaches your agent or keys.

**`--privileged` isn't needed.** Each flag, and what happens without it:

| Flag | Why |
|---|---|
| `--cap-add SYS_ADMIN` | systemd's own mounts, and the unit's `ProtectSystem`, `PrivateTmp` and `ReadWritePaths`. `docker_the_unit_runs_the_agent_in_its_sandbox` checks they took effect. |
| The image's `mount -o remount,rw /sys/fs/cgroup` | Docker mounts cgroups read-only unless `--privileged`, and systemd exits at once with them so. |
| `--security-opt apparmor=unconfined` | Docker's default profile refuses those mounts on a host with AppArmor. It isn't active on Docker Desktop, so that part is from what it does on a runner. |
| `--cgroupns=private` | So that this systemd sees a cgroup tree of its own to write to. |
| `--tmpfs /run`, `--tmpfs /run/lock` | Where systemd expects a tmpfs. |

`SYS_ADMIN` is a broad capability, and this isn't a sandbox for hostile code: it's what lets a test
of a root script not need all of `--privileged`.

## In the image

- **`dbus`,** as a login's `systemctl cat docker.service` needs the system bus, and `systemd` only
  recommends it. Without it the probe says "Docker from snap".
- **`useradd -g operator operator`,** as bookworm has that group already.
- **`operator`** has passwordless `sudo`, and **`needs-password`** doesn't.
- **`fake-docker.sh`** answers only `docker --version`, `docker version` and `docker compose version
  --short`, and fails anything else. **`docker.service`** is a `oneshot` stub, as the unit has
  `Requires=docker.service`.
- **`/srv/compose/app`** exists, and is the deployment's directory in `fleet.toml`.
- **Its host keys are baked in,** and aren't secret: it only ever listens on `127.0.0.1`.

## What they can't show

- **A real `sudo` password prompt.** `needs-password` is only tested without a terminal. The one
  test with a terminal, `docker_a_slow_answer_costs_one_more_connection`, has passwordless `sudo`.
- **Real Docker.** The agent starts with nothing to deploy, and `docker version` is answered by a
  script. The agent's real deploys are in `crates/agent/tests/docker_e2e`.
- **A real release.** `FixedSource` hands out `dist`'s agent. `GitHubReleases` and its checks are
  tested in `agent_release` and `live_` tests.
- **A hardware key, or an agent that asks to approve each connection.** The count of connections
  is real, what a person would be asked isn't. The key here has no passphrase.
- **Any distribution but Debian bookworm,** or systemd but 252, and any `sshd` but its 9.2.
- **The stdout of a real `ssh` master:** what `OpenSsh` gives one is tested with a fake `ssh` that
  looks at its streams, in `host::tests::ssh::streams`.
