# keep-web

Headless co-signer daemon for Keep. It unlocks a vault at boot, optionally joins a FROST
group as an always-on co-signer, and exposes a small authenticated HTTP API (plus a Svelte
admin UI) for managing shares, watching the signing log, and approving requests.

This is the process packaged by [keep-startos](https://github.com/start9-community/keep-startos),
but it runs anywhere you can set a few environment variables (Docker, systemd, a VM).

## Running

```bash
# Build
cargo build --release -p keep-web

# Minimum: a vault path and an unlock password. Pinning the API token is
# recommended so the credential lives outside the vault directory, which is
# what filesystem backups and volume snapshots capture.
KEEP_PATH=/data \
KEEP_PASSWORD_FILE=/run/secrets/keep-password \
KEEP_WEB_AUTH_TOKEN_FILE=/run/secrets/keep-web-token \
# Deliberately widened from the 127.0.0.1 default: required in a container.
KEEP_WEB_LISTEN=0.0.0.0:8080 \
./target/release/keep-web
```

If the vault at `KEEP_PATH` does not exist, it is created with the supplied password on
first boot. If `KEEP_WEB_AUTH_TOKEN[_FILE]` is unset, a random token is generated once and
persisted to `$KEEP_PATH/auth_token` (mode `0600`); it is never written to the log, because
it authorizes share export.

## Configuration

All configuration is via environment variables. Any `*_FILE` variant reads the value from
the given file path instead (use this for secrets).

| Variable | Default | Description |
|----------|---------|-------------|
| `KEEP_PATH` | `/data` | Vault directory. Created on first boot if absent |
| `KEEP_PASSWORD` / `KEEP_PASSWORD_FILE` | (required) | Vault unlock password for headless start |
| `KEEP_WEB_AUTH_TOKEN` / `_FILE` | persisted to `$KEEP_PATH/auth_token` | Bearer token gating every `/api/*` route |
| `KEEP_WEB_LISTEN` | `127.0.0.1:8080` | Listen address. Containers must set `0.0.0.0:8080` explicitly |
| `KEEP_WEB_UI_DIR` | `ui/dist` | Path to the built admin UI assets |
| `KEEP_BUNKER_RELAY` | `KEEP_RELAY` then `wss://bucket.coracle.social` | Relay(s) for the NIP-46 bunker |
| `KEEP_RELAY` | `wss://bucket.coracle.social` | Fallback relay |
| `KEEP_FROST_GROUP` | (none) | npub of the FROST group to co-sign for |
| `KEEP_FROST_RELAY` | (none) | Relay(s) for FROST coordination |
| `KEEP_FROST_AUTO_APPROVE` | `false` | Auto-approve co-signing requests when `true` |
| `KEEP_ALLOW_SINGLE_KEY` | `false` | Allow serving a non-threshold single key |
| `KEEP_SINGLE_KEY_ACK` | (none) | Must be `i-understand` to actually enable single-key serving |

## Authentication

Every `/api/*` route except `/api/health` and the WebSocket upgrade requires a
`Authorization: Bearer <token>` header matching `KEEP_WEB_AUTH_TOKEN`, or the token
persisted at `$KEEP_PATH/auth_token` when that is unset. The WebSocket gates
itself on a single-use ticket minted via the authed `/api/ws-ticket`, so the durable token
never appears in a URL or proxy access log.

## HTTP API

Authenticated (`Bearer` token):

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/bunker` | Bunker connection details |
| GET | `/api/shares` | List FROST shares |
| POST | `/api/shares/import` | Import a share |
| POST | `/api/shares/export` | Export an encrypted share backup |
| POST | `/api/shares/delete` | Delete a share |
| POST | `/api/shares/rename` | Rename a share |
| POST | `/api/active-group` | Switch the active FROST group |
| GET | `/api/signing-log` | FROST coordination / signing log |
| GET | `/api/peers` | Live peer status |
| GET/POST | `/api/killswitch` | Read / toggle the co-signing kill switch |
| POST | `/api/approvals/{id}` | Resolve a pending approval request |
| POST | `/api/ws-ticket` | Mint a single-use WebSocket ticket |

Unauthenticated:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Liveness probe (for StartOS/Docker) |
| GET | `/api/events` | WebSocket upgrade for real-time events (ticket-gated) |

Requests and responses are JSON; keep-core errors map to standard HTTP status codes.
