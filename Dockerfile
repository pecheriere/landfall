# The builder always runs on the build host's platform and cross-compiles a
# static musl binary for the requested target with zig as the C compiler and
# linker, so multi-platform builds need no emulation. The Rust version tracks
# rust-toolchain.toml (1.99). No `# syntax=` line: the Dockerfile frontend
# built into BuildKit covers everything used here, so no unpinned frontend
# image is pulled at build time.
FROM --platform=$BUILDPLATFORM rust:1.99.0-alpine3.23@sha256:42c2519fdf75d9e34cc61a1aaf34b1a684da9bfd65fe5daefef98d92a801b001 AS build

ARG TARGETARCH

# zig and the libraries that are its C compiler and linker are pinned to the
# versions in Alpine 3.23, so a repository update cannot change them under a
# digest-pinned base image. Alpine drops an old version when it publishes a new
# one, so one of these can make this line fail, and that is the point: bump the
# version on purpose. What stays free is in plan 06's "Left mutable" list: what
# those libraries load (libffi, xz-libs, libxml2), musl-dev, and the targets,
# which the digest-pinned toolchain's own channel manifest decides.
RUN apk add --no-cache musl-dev zig=0.15.2-r0 llvm20-libs=20.1.8-r0 clang20-libs=20.1.8-r1 lld20-libs=20.1.8-r1 \
    && cargo install --locked --version 0.24.0 cargo-zigbuild \
    && rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl

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
    && for crate in core approval origin server agent; do \
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
