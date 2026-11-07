# A throwaway host for the `docker_` tests of `host install`: real systemd, sshd, sudo and useradd,
# and a stand-in for Docker. Nothing in it is a secret: its host keys are in the image, and it only
# listens on 127.0.0.1 for the length of a test. README.md says why each thing is here.
FROM debian:bookworm-20261027-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

# `dbus` because a login's `systemctl cat docker.service` needs the system bus, without which the
# probe takes it for Docker from snap. `systemd` only recommends it, and this says no to those.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates dbus openssh-server sudo systemd systemd-sysv \
    && rm -rf /var/lib/apt/lists/*

# bookworm has a group called `operator`, so `useradd operator` alone fails with "group exists".
RUN useradd -m -s /bin/bash -g operator operator \
    && useradd -m -s /bin/bash needs-password \
    && echo 'needs-password:not-a-secret-only-a-test' | chpasswd \
    && usermod -p '*' operator \
    && echo 'operator ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/operator \
    && echo 'needs-password ALL=(ALL) ALL' > /etc/sudoers.d/needs-password \
    && chmod 0440 /etc/sudoers.d/operator /etc/sudoers.d/needs-password \
    && groupadd docker \
    && mkdir -p /srv/compose/app /usr/local/lib/landfall /var/lib/landfall-server \
    && printf 'PasswordAuthentication no\n' > /etc/ssh/sshd_config.d/landfall-test.conf

COPY fake-docker.sh /usr/local/bin/docker
COPY docker.service /etc/systemd/system/docker.service

# What a console or a real machine needs, and a container hasn't got.
RUN chmod 0755 /usr/local/bin/docker \
    && chmod 0644 /etc/systemd/system/docker.service \
    && systemctl enable docker.service ssh.service \
    && systemctl mask getty.target console-getty.service systemd-firstboot.service \
        systemd-udevd.service systemd-modules-load.service

STOPSIGNAL SIGRTMIN+3
# Docker mounts cgroups read-only unless `--privileged`, and systemd needs to write there. The
# harness gives this `SYS_ADMIN` for it, and for the unit's own mounts. README.md has the rest.
CMD ["sh", "-c", "mount -o remount,rw /sys/fs/cgroup && exec /sbin/init"]
