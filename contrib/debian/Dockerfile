# Builds the keep and keep-web Debian packages.
#
#   docker build -f contrib/debian/Dockerfile -o type=local,dest=./dist .
#
# Everything is built on bookworm so the packages carry a libc6 floor that
# still installs on Debian 12 and Ubuntu 22.04. Building on a newer
# distribution silently raises that floor and the packages stop installing on
# older ones.

FROM rust:1.89-bookworm AS rust-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libudev-dev \
    libclang-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
ENV RUSTFLAGS="-C strip=symbols"
RUN cargo build --release --locked -p keep-cli -p keep-web

FROM node:20-bookworm-slim AS ui-builder
WORKDIR /ui
COPY keep-web/ui/ ./
RUN npm ci && npm run build

FROM debian:bookworm-slim AS packager
RUN apt-get update && apt-get install -y --no-install-recommends \
    dpkg-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml LICENSE ./
COPY contrib/ ./contrib/
COPY --from=rust-builder /build/target/release/keep /build/target/release/keep-web /bin-in/
COPY --from=ui-builder /ui/dist /ui-in/
RUN contrib/debian/build-deb.sh /bin-in /ui-in /out

FROM scratch AS export
COPY --from=packager /out/* /
