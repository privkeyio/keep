# Contrib

Supplementary files for deploying and configuring Keep.

## Contents

```
contrib/
├── keep.env.example
├── Dockerfile
├── docker-compose.yml
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
