# Reproducible Builds

Reproducible builds allow anyone to verify that a binary was built from a specific source commit.

## Requirements

- Docker
- just (optional, for convenience commands)

## Build Environment

| Component | Version |
|-----------|---------|
| Rust | 1.85.0 |
| Base Image | rust:1.85.0-slim-bookworm |
| Build Flags | `-C strip=symbols -C codegen-units=1` |

## Building

```bash
# Using just
just build-reproducible

# Or directly with Docker
docker build -f Dockerfile.reproducible -o type=local,dest=./dist .
```

The binary will be output to `dist/keep`.

## Verification

### Verify two builds match

```bash
just verify-reproducible
```

### Verify against expected hash

```bash
just verify-sha <expected_sha256_hash>
```

### Manual verification

```bash
docker build -f Dockerfile.reproducible -o type=local,dest=./dist .
sha256sum dist/keep
```

## Release Hashes

Expected hashes for official releases will be published in release notes.

## Technical Details

Reproducibility is achieved through:

1. **Pinned Rust version** via `rust-toolchain.toml` and Docker image tag
2. **Locked dependencies** via `Cargo.lock` and `--locked` flag
3. **Stripped symbols** removing non-deterministic debug info
4. **Single codegen unit** ensuring consistent compilation order
5. **Fixed SOURCE_DATE_EPOCH** for deterministic embedded timestamps

## CI Verification

Every PR and push to main runs the reproducibility check, building twice and comparing hashes.
