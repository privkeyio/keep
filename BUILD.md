# Building Keep

## Prerequisites

### Rust Toolchain

Rust 1.83 or later required. Install via [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libudev-dev libssl-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc pkg-config systemd-devel openssl-devel
```

**macOS:**
```bash
xcode-select --install
```

**Minimum System Requirements:**
- 2GB RAM
- 1GB disk space
- x86_64 or aarch64 architecture

---

## Standard Build

### Development Build

```bash
cargo build
./target/debug/keep --help
```

### Release Build

```bash
cargo build --release
./target/release/keep --help
```

### Install to PATH

```bash
cargo install --path keep-cli
```

---

## Feature Flags

### keep-cli

| Feature | Description | Build Command |
|---------|-------------|---------------|
| `warden` | Policy enforcement via Warden API | `cargo build --release --features warden` |

```bash
cargo build --release --features warden
```

---

## Component Builds

### Python Bindings (keep-agent-py)

Requires Python 3.9+ and maturin.

```bash
cd keep-agent-py
pip install maturin
maturin build --release
pip install target/wheels/keep_agent-*.whl
```

**Development install:**
```bash
maturin develop
```

### TypeScript/Node.js Bindings (keep-agent-ts)

Requires Node.js 18+ and npm.

```bash
cd keep-agent-ts
npm install
npm run build
```

**Debug build:**
```bash
npm run build:debug
```

### Enclave Build

See [keep-enclave/build/README.md](keep-enclave/build/README.md) for full instructions.

**Quick start with Enclaver:**
```bash
docker build -f keep-enclave/build/Dockerfile.local -t keep-enclave:local .
enclaver build -f keep-enclave/enclaver.yaml
```

**Full production build (requires Nitro SDK):**
```bash
cd keep-enclave/build
./build-enclave.sh
```

Outputs `keep-enclave.eif` and `pcrs.json`.

---

## Cross-Compilation

### Linux ARM64

```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

Requires cross-compilation toolchain:
```bash
sudo apt-get install gcc-aarch64-linux-gnu
```

### macOS ARM64 (from x86_64)

```bash
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

---

## Docker Build

Build the CLI in Docker:

```bash
docker build -t keep-build -f - . <<'EOF'
FROM rust:1.83-bookworm
RUN apt-get update && apt-get install -y libudev-dev
WORKDIR /app
COPY . .
RUN cargo build --release
EOF

docker run --rm -v $(pwd)/artifacts:/out keep-build cp /app/target/release/keep /out/
```

---

## Running Tests

```bash
cargo test
```

With logging:
```bash
RUST_LOG=debug cargo test -- --nocapture
```

Single crate:
```bash
cargo test -p keep-core
```

---

## Code Quality

```bash
cargo fmt -- --check
cargo clippy -- -D warnings
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `libudev-dev not found` | Install system dependencies (see Prerequisites) |
| `failed to run custom build command for serialport` | Install `libudev-dev` (Linux) |
| `GLIBC_X.XX not found` | Build on older glibc system or use musl target |
| `error[E0463]: can't find crate` | Run `cargo clean` and rebuild |
| Python build fails | Ensure maturin and Python dev headers installed |
| Node.js build fails | Ensure Node 18+ and run `npm install` first |

### MUSL Static Build (Linux)

For maximum portability:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

---

## CI/CD

The project uses GitHub Actions. See [.github/workflows/ci.yml](.github/workflows/ci.yml).

CI runs:
1. `cargo fmt -- --check`
2. `cargo clippy -- -D warnings`
3. `cargo build --release`
4. `cargo test`
