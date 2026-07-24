# Contrib

Supplementary files for deploying and configuring Keep.

## Contents

```
contrib/
├── keep.env.example
├── Dockerfile
├── docker-compose.yml
├── debian/
│   ├── Dockerfile
│   ├── build-deb.sh
│   ├── keep-web.service
│   ├── keep-web.env
│   └── keep-web.{postinst,prerm,postrm}
├── systemd/
│   ├── keep-serve.service
│   └── keep-frost-serve@.service
├── nginx/
│   └── keep.conf
└── completions/
    ├── keep.bash
    ├── keep.zsh
    └── keep.fish
```

## Debian Packages

Two packages are published with each release: `keep` (the command line
interface) and `keep-web` (the always-on FROST co-signer and web admin,
running as a systemd service). They install on Debian 12+ and Ubuntu 22.04+.

Verify the download against the `SHA256SUMS` published with the release before
installing. dpkg runs maintainer scripts as root, so a swapped package is root
on the host, not merely a bad binary:

```bash
sha256sum --check --ignore-missing SHA256SUMS
sudo apt install ./keep_<version>_amd64.deb ./keep-web_<version>_amd64.deb
```

`keep-web` is installed disabled, because it cannot start until it has a vault
password and a FROST group:

```bash
# 1. Vault password. Create the file with its mode already restricted, then
#    write into it: writing first would leave the password briefly world
#    readable.
sudo install -m 600 -o keep-web -g keep-web /dev/null /etc/keep-web/password
sudo tee /etc/keep-web/password >/dev/null   # type the password, then Ctrl-D

# 2. Set KEEP_FROST_GROUP and review the relays
sudo editor /etc/keep-web/keep-web.env

# 3. Start it
sudo systemctl enable --now keep-web
```

The admin interface binds to `127.0.0.1:8080` and is not reachable from the
network on purpose, since it controls signing and can export the share. To use
it from another machine, forward the port over SSH:

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<host>
```

Then browse to `http://127.0.0.1:8080` and sign in with the token from
`/etc/keep-web/auth-token` (`sudo cat` it). For a permanent deployment, front
it with the reverse proxy in `nginx/keep.conf` or an onion service rather than
widening `KEEP_WEB_LISTEN`. The vault lives in `/var/lib/keep-web`.

The bearer token guarding the admin API is generated on install at
`/etc/keep-web/auth-token`. This token gates share export, so treat it as key
material. Left unset, the daemon would persist its own token inside the vault
directory instead; the package pins it under `/etc/keep-web` so the credential
is not swept up by filesystem backups and volume snapshots of the vault.

Only `/var/lib/keep-web` survives a purge. It holds the encrypted share and
deleting it would be irrecoverable, so it is kept along with the `keep-web`
account that owns it. The password and token under `/etc/keep-web` are
removed, which leaves the vault as inert ciphertext rather than a usable share
on a host you believe is decommissioned. Keep your vault password in your own
password manager: it is not recoverable from what remains.

To build the packages locally:

```bash
docker build -f contrib/debian/Dockerfile -o type=local,dest=./dist .
```

## Systemd Setup

```bash
sudo cp contrib/systemd/*.service /etc/systemd/system/
sudo useradd -r -s /bin/false keep
sudo mkdir -p /var/lib/keep /etc/keep
sudo chown keep:keep /var/lib/keep
sudo cp contrib/keep.env.example /etc/keep/keep.env
sudo systemctl daemon-reload
sudo systemctl enable --now keep-serve
```

For FROST network signer (template service):
```bash
sudo systemctl enable --now keep-frost-serve@npub1abc123.service
```

## Shell Completions

**Bash:**
```bash
sudo cp contrib/completions/keep.bash /etc/bash_completion.d/keep
```

**Zsh:**
```bash
sudo cp contrib/completions/keep.zsh /usr/local/share/zsh/site-functions/_keep
```

**Fish:**
```bash
cp contrib/completions/keep.fish ~/.config/fish/completions/
```

## Docker

```bash
cd contrib
cp keep.env.example keep.env
docker compose up -d
```
