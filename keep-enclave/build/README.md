# Enclave Build

## Required Binaries

Before building, download these binaries from the AWS Nitro Enclaves SDK:

| Binary | Source | Description |
|--------|--------|-------------|
| `kmstool_enclave_cli` | [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c/releases) | KMS integration for attestation-based decryption |
| `libnsm.so` | [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c/releases) | Nitro Secure Module library |

### Download from Official Release

```bash
cd keep-enclave/build

# Download v0.4.2 binaries (x86_64)
curl -LO https://github.com/aws/aws-nitro-enclaves-sdk-c/releases/download/v0.4.2/kmstool_enclave_cli
curl -LO https://github.com/aws/aws-nitro-enclaves-sdk-c/releases/download/v0.4.2/libnsm.so
chmod +x kmstool_enclave_cli

# Generate checksums
sha256sum kmstool_enclave_cli libnsm.so
```

### Update Checksums (Required)

The build will fail until you update `checksums.sha256` with real hashes:

```bash
# Get the hashes
sha256sum kmstool_enclave_cli libnsm.so

# Edit checksums.sha256 - replace the placeholder zeros with actual hashes
# Format: <64-char-sha256-hash>  /app/kmstool_enclave_cli
#         <64-char-sha256-hash>  /usr/lib64/libnsm.so
```

### Build from Source (Alternative)

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
