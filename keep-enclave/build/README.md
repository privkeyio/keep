# Enclave Build

## Local Testing (No AWS Required)

Test the enclave logic locally before deploying to AWS:

```bash
# Build local Docker image
docker build -f keep-enclave/build/Dockerfile.local -t keep-enclave:local .

# Run (will fail on vsock - expected outside enclave)
docker run --rm keep-enclave:local
```

## Using Enclaver (Recommended)

[Enclaver](https://github.com/edgebitio/enclaver) simplifies enclave builds:

```bash
# Install enclaver
curl -sL https://github.com/edgebitio/enclaver/releases/latest/download/enclaver-linux-x86_64.tar.gz | tar xz
sudo mv enclaver /usr/local/bin/

# Build local image first
docker build -f keep-enclave/build/Dockerfile.local -t keep-enclave:local .

# Build enclave with enclaver
enclaver build -f keep-enclave/enclaver.yaml

# Deploy on AWS Nitro instance
enclaver run keep-enclave:enclave
```

## Full AWS Build (with KMS)

For production builds with KMS integration, you need AWS SDK binaries.

### Required Binaries

| Binary | Source | Description |
|--------|--------|-------------|
| `kmstool_enclave_cli` | [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c) | KMS integration for attestation-based decryption |
| `libnsm.so` | [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c) | Nitro Secure Module library |

### Build from Source

```bash
git clone https://github.com/aws/aws-nitro-enclaves-sdk-c.git
cd aws-nitro-enclaves-sdk-c
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cp bin/kmstool-enclave-cli ../../keep-enclave/build/kmstool_enclave_cli
cp lib/libnsm.so ../../keep-enclave/build/libnsm.so

# Then update checksums.sha256 with the new hashes
```

Both the build script and Docker build verify checksums. This ensures:
- Binaries are from a known source
- No tampering occurred during download
- Reproducible builds across environments

## Build Enclave

```bash
./build-enclave.sh
```

This:
1. Builds the Rust enclave binary
2. Creates a Docker image with all dependencies
3. Converts to EIF format for Nitro
4. Outputs PCR values for KMS policy

## Output

- `keep-enclave.eif` - Enclave Image File
- `pcrs.json` - PCR0/1/2 values for KMS key policy
