# The builder always runs on the build host's platform and cross-compiles a
# static musl binary for the requested target with zig as the C compiler and
# linker, so multi-platform builds need no emulation. The Rust version tracks
# rust-toolchain.toml (1.99). No `# syntax=` line: the Dockerfile frontend
# built into BuildKit covers everything used here, so no unpinned frontend
# image is pulled at build time.

# zig is upstream's own release, one directory with its LLVM, clang and lld in
# it, fixed by checksum for each platform a build can run on, so nothing from a
# package repository can change the compiler or linker. These hashes were checked
# against the release's minisign signatures. To bump it, take each file's hash
# from a new release's index.json at ziglang.org and verify its `.minisig`
# against the key published there.
ARG BUILDARCH

FROM scratch AS zig-arm64
ADD --checksum=sha256:958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f https://ziglang.org/download/0.15.2/zig-aarch64-linux-0.15.2.tar.xz /zig.tar.xz

FROM scratch AS zig-amd64
ADD --checksum=sha256:02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz /zig.tar.xz

FROM zig-${BUILDARCH} AS zig

FROM --platform=$BUILDPLATFORM rust:1.99.0-alpine3.23@sha256:42c2519fdf75d9e34cc61a1aaf34b1a684da9bfd65fe5daefef98d92a801b001 AS build

ARG TARGETARCH

COPY --from=zig /zig.tar.xz /zig.tar.xz

# What stays free is in plan 06's "Left mutable" list: musl-dev, for build scripts
# only, and the targets, which the digest-pinned toolchain's channel decides.
RUN apk add --no-cache musl-dev \
    && mkdir /opt/zig \
    && tar -xJf /zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /zig.tar.xz \
    && cargo install --locked --version 0.24.0 cargo-zigbuild \
    && rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl

ENV PATH="/opt/zig:$PATH"

# Static and position-independent, so that where the agent, which is
# root-equivalent, sits in memory differs on every run. rustc's own request for
# that doesn't reach zig's linker, and this does. In the environment because
# `.dockerignore` keeps a `.cargo/config.toml` out of the build, before both
# builds below so the dependency layer and the real one agree, and with
# `--target` it doesn't reach build scripts. check_binaries.py holds it.
ENV RUSTFLAGS="-C link-arg=-pie"

WORKDIR /src

# Dependencies build in their own layer, from the manifests and Cargo.lock
# only, so the build cache reuses it until Cargo.lock changes. Each crate gets
# an empty main.rs (lib.rs for the library crates; the server and the agent
# have both) for this step.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/
COPY crates/approval/Cargo.toml crates/approval/
COPY crates/origin/Cargo.toml crates/origin/
COPY crates/server/Cargo.toml crates/server/
COPY crates/agent/Cargo.toml crates/agent/
COPY crates/cli/Cargo.toml crates/cli/
RUN case "$TARGETARCH" in \
        arm64) echo aarch64-unknown-linux-musl ;; \
        amd64) echo x86_64-unknown-linux-musl ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac > /target-triple \
    && for crate in server agent cli; do \
        mkdir -p "crates/$crate/src" && echo 'fn main() {}' > "crates/$crate/src/main.rs"; \
    done \
    && for crate in core approval origin server agent cli; do \
        mkdir -p "crates/$crate/src" && : > "crates/$crate/src/lib.rs"; \
    done \
    && cargo zigbuild --release --locked -p landfall-server -p landfall-agent -p landfall-cli --target "$(cat /target-triple)"

COPY crates ./crates

# The placeholder builds are removed first, so the real sources always compile,
# whatever their timestamps. All three binaries come from one invocation, which
# shares the dependency layer. The final image is empty apart from what is
# installed in rootfs, and its HTTPS client refuses to start without a CA
# bundle, so the base image's bundle (fixed by its digest) goes in.
RUN target="$(cat /target-triple)" \
    && cargo clean --release --target "$target" -p landfall-server -p landfall-agent -p landfall-cli -p landfall-core -p landfall-approval -p landfall-origin \
    && cargo zigbuild --release --locked -p landfall-server -p landfall-agent -p landfall-cli --target "$target" \
    && install -D -m 0755 "target/$target/release/landfall-server" /out/rootfs/landfall-server \
    && install -D -m 0644 /etc/ssl/certs/ca-certificates.crt /out/rootfs/etc/ssl/certs/ca-certificates.crt \
    && for binary in landfall-server landfall-agent landfall; do \
        install -D -m 0755 "target/$target/release/$binary" "/out/binaries/$binary"; \
    done

# The static binaries, for `docker buildx build --target binaries --output
# type=local,dest=dist`. check_binaries.py checks them. This stage is skipped
# when the image is built, as the final stage doesn't need it.
FROM scratch AS binaries

COPY --from=build /out/binaries/ /

# The image holds the controller only. The host agent runs outside Docker (it
# must survive the deploys it performs) and the CLI runs wherever its user is.
FROM scratch

COPY --from=build /out/rootfs/ /

USER 65532:65532
ENTRYPOINT ["/landfall-server"]
