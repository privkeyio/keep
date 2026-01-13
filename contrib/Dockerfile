FROM rust:1.83-bookworm AS builder

RUN apt-get update && apt-get install -y libudev-dev

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/keep /usr/local/bin/keep

RUN useradd -r -s /bin/false keep && \
    mkdir -p /data && \
    chown keep:keep /data
USER keep

ENTRYPOINT ["keep"]
