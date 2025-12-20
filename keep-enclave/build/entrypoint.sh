#!/bin/bash
set -e

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting keep-enclave"

ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set dev lo up 2>/dev/null || true

log "Starting vsock proxy for KMS (port 8000)"
socat VSOCK-LISTEN:8000,fork TCP:127.0.0.1:8000 &

log "Starting vsock proxy for credentials (port 8003)"
socat VSOCK-LISTEN:8003,fork TCP:127.0.0.1:8003 &

sleep 1

log "Starting keep-enclave binary"
exec /app/keep-enclave
