# Dockerfile — packages the `pillar` binary (the `node run` entrypoint, see
# crates/pillar-cli/src/run.rs) for the containerized deployment consumed by
# flux's pillar-node-deploy task.
#
# Multi-stage: build the workspace with the pinned rust-toolchain in a full
# builder image, then copy just the resulting `pillar` binary into a slim
# runtime image so the shipped image carries no compiler/toolchain surface.

FROM rust:1.80-bookworm AS builder

WORKDIR /src

# Leverage layer caching: copy manifests first, then sources.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --release --locked -p pillar-cli --bin pillar

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/pillar --shell /usr/sbin/nologin pillar

COPY --from=builder /src/target/release/pillar /usr/local/bin/pillar

USER pillar
WORKDIR /var/lib/pillar

# Matches crates/pillar-cli/src/run.rs defaults; override via env/flags.
ENV PILLAR_DATA_DIR=/var/lib/pillar/data
ENV PILLAR_IDENTITY_KEY=/var/lib/pillar/data/identity.key
ENV PILLAR_LISTEN=/ip4/0.0.0.0/tcp/0

ENTRYPOINT ["/usr/local/bin/pillar", "node", "run"]
