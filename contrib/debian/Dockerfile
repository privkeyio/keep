# Builds the keep and keep-web Debian packages.
#
#   docker build -f contrib/debian/Dockerfile -o type=local,dest=./dist .
#
# The Rust stage mirrors Dockerfile.reproducible: same pinned base, same
# RUSTFLAGS, same SOURCE_DATE_EPOCH, same full-workspace build. That keeps the
# binaries inside the packages bit-identical to the keep-linux-x86_64 and
# keep-web-linux-x86_64 published in the same release, so one SHA256SUMS
# describes both and the packages inherit the reproducible-build guarantee.
# Keep this stage in step with Dockerfile.reproducible.
#
# Building on bookworm also holds the dependency floor low enough to install on
# Debian 12 and Ubuntu 22.04. A newer base silently raises it.

FROM rust:1.89.0-slim-bookworm AS rust-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libudev-dev \
    libgtk-3-dev \
    libxdo-dev \
    libclang-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Pinned rather than a build arg: Dockerfile.reproducible is always invoked
# without one, so it always compiles at epoch 0. Matching that literally is
# what keeps these binaries bit-identical to the published ones.
ENV SOURCE_DATE_EPOCH=0
ENV RUSTFLAGS="-C strip=symbols -C codegen-units=1"

COPY Cargo.toml Cargo.lock ./
COPY keep-core ./keep-core
COPY keep-cli ./keep-cli
COPY keep-nip46 ./keep-nip46
COPY keep-bitcoin ./keep-bitcoin
COPY keep-agent ./keep-agent
COPY keep-frost-net ./keep-frost-net
COPY keep-enclave ./keep-enclave
COPY keep-mobile ./keep-mobile
COPY keep-desktop ./keep-desktop
COPY keep-web ./keep-web

RUN cargo build --release --locked

# Build the admin SPA. --ignore-scripts keeps dependency lifecycle hooks out of
# the release pipeline: this bundle is what an operator reads when deciding
# whether to approve a signature.
FROM node:20-bookworm-slim AS ui-builder
WORKDIR /ui
COPY keep-web/ui/ ./
RUN npm ci --ignore-scripts && npm run build

FROM debian:bookworm-slim AS packager
RUN apt-get update && apt-get install -y --no-install-recommends \
    dpkg-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Package mtimes and the changelog date, distinct from the compile-time epoch
# above. Left unset it falls back to the current time; dpkg-deb would clamp
# every mtime to 1970 if this were defaulted to 0.
ARG SOURCE_DATE_EPOCH
COPY Cargo.toml LICENSE ./
COPY contrib/ ./contrib/
COPY --from=rust-builder /build/target/release/keep /build/target/release/keep-web /bin-in/
COPY --from=ui-builder /ui/dist /ui-in/
RUN contrib/debian/build-deb.sh /bin-in /ui-in /out

FROM scratch AS export
COPY --from=packager /out/* /
