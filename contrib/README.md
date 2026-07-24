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

```bash
sudo apt install ./keep_0.7.5_amd64.deb ./keep-web_0.7.5_amd64.deb
```

`keep-web` is installed disabled, because it cannot start until it has a vault
password and a FROST group:

```bash
# 1. Vault password, kept out of the environment and off the process list
sudo install -m 640 -o root -g keep-web /dev/null /etc/keep-web/password
sudo tee /etc/keep-web/password >/dev/null   # type the password, then Ctrl-D

# 2. Set KEEP_FROST_GROUP and review the relays
sudo editor /etc/keep-web/keep-web.env

# 3. Start it
sudo systemctl enable --now keep-web
```

The admin interface binds to `127.0.0.1:8080` by default. Front it with the
reverse proxy in `nginx/keep.conf` or an onion service rather than exposing it
directly. The vault lives in `/var/lib/keep-web`.

Purging the package leaves `/var/lib/keep-web` and `/etc/keep-web/password` in
place on purpose: they are the FROST share and the only key to it. Remove them
by hand once the share is retired.

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
