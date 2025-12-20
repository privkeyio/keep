#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$SCRIPT_DIR"

echo "=== Building Keep Enclave ==="
echo "Project root: $PROJECT_ROOT"
echo "Build dir: $BUILD_DIR"

if ! command -v nitro-cli &> /dev/null; then
    echo "Error: nitro-cli not found. Install aws-nitro-enclaves-cli."
    exit 1
fi

if [ ! -f "$BUILD_DIR/kmstool_enclave_cli" ]; then
    echo "Error: kmstool_enclave_cli not found in $BUILD_DIR"
    echo "Download from: https://github.com/aws/aws-nitro-enclaves-sdk-c/releases"
    exit 1
fi

if [ ! -f "$BUILD_DIR/libnsm.so" ]; then
    echo "Error: libnsm.so not found in $BUILD_DIR"
    echo "Download from: https://github.com/aws/aws-nitro-enclaves-sdk-c/releases"
    exit 1
fi

if grep -q "^0\{64\}" "$BUILD_DIR/checksums.sha256"; then
    echo "Error: checksums.sha256 contains placeholder values"
    echo "Update with real checksums:"
    echo "  cd $BUILD_DIR"
    echo "  sha256sum kmstool_enclave_cli libnsm.so"
    echo "Then update checksums.sha256 with the output hashes"
    exit 1
fi

echo "Verifying binary checksums..."
cd "$BUILD_DIR"
if ! sha256sum -c checksums.sha256 --ignore-missing 2>/dev/null; then
    echo "Error: Binary checksum verification failed"
    echo "Expected checksums from checksums.sha256:"
    grep -v "^#" checksums.sha256
    echo ""
    echo "Actual checksums:"
    sha256sum kmstool_enclave_cli libnsm.so
    exit 1
fi
echo "Checksums verified ✓"
cd "$PROJECT_ROOT"

echo "Building Docker image..."
docker build \
    -f "$BUILD_DIR/Dockerfile.enclave" \
    -t keep-enclave:latest \
    "$PROJECT_ROOT"

echo "Building EIF..."
nitro-cli build-enclave \
    --docker-uri keep-enclave:latest \
    --output-file "$BUILD_DIR/keep-enclave.eif"

echo "Extracting PCRs..."
PCR_OUTPUT=$(nitro-cli describe-eif --eif-path "$BUILD_DIR/keep-enclave.eif")

PCR0=$(echo "$PCR_OUTPUT" | jq -r '.Measurements.PCR0')
PCR1=$(echo "$PCR_OUTPUT" | jq -r '.Measurements.PCR1')
PCR2=$(echo "$PCR_OUTPUT" | jq -r '.Measurements.PCR2')

cat > "$BUILD_DIR/pcrs.json" << EOF
{
  "PCR0": "$PCR0",
  "PCR1": "$PCR1",
  "PCR2": "$PCR2"
}
EOF

echo ""
echo "=== Build Complete ==="
echo "EIF: $BUILD_DIR/keep-enclave.eif"
echo "PCRs saved to: $BUILD_DIR/pcrs.json"
echo ""
echo "PCR0 (Image): $PCR0"
echo "PCR1 (Kernel): $PCR1"
echo "PCR2 (Application): $PCR2"
echo ""
echo "Update your KMS key policy with PCR0 value."
