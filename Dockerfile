# The builder always runs on the build host's platform and cross-compiles a
# static musl binary for the requested target with zig as the C compiler and
# linker, so multi-platform builds need no emulation. The Rust version tracks
# rust-toolchain.toml (1.99). No `# syntax=` line: the Dockerfile frontend
# built into BuildKit covers everything used here, so no unpinned frontend
# image is pulled at build time.
FROM --platform=$BUILDPLATFORM rust:1.99.0-alpine3.23@sha256:42c2519fdf75d9e34cc61a1aaf34b1a684da9bfd65fe5daefef98d92a801b001 AS build

ARG TARGETARCH

# zig is pinned to the version in Alpine 3.23 community, so a repository update
# cannot change the C compiler and linker under a digest-pinned base image.
RUN apk add --no-cache musl-dev zig=0.15.2-r0 \
    && cargo install --locked --version 0.24.0 cargo-zigbuild \
    && rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl

WORKDIR /src

# Dependencies build in their own layer, from the manifests and Cargo.lock
# only, so the build cache reuses it until Cargo.lock changes. Each crate gets
# an empty main.rs (lib.rs for the library crates) for this step.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/
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
    && for crate in core origin; do \
        mkdir -p "crates/$crate/src" && : > "crates/$crate/src/lib.rs"; \
    done \
    && cargo zigbuild --release --locked -p landfall-server --target "$(cat /target-triple)"

COPY crates ./crates

# The placeholder build of landfall-server is removed first, so the real
# sources always compile, whatever their timestamps.
RUN target="$(cat /target-triple)" \
    && cargo clean --release --target "$target" -p landfall-server -p landfall-core -p landfall-origin \
    && cargo zigbuild --release --locked -p landfall-server --target "$target" \
    && install -D -m 0755 "target/$target/release/landfall-server" /out/rootfs/landfall-server

# The image holds the controller only. The host agent runs outside Docker (it
# must survive the deploys it performs) and the CLI runs wherever its user is.
FROM scratch

COPY --from=build /out/rootfs/ /

USER 65532:65532
ENTRYPOINT ["/landfall-server"]
