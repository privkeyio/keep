#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# Every workspace member must be copied into the release Dockerfiles, or the
# release and Debian builds fail on a tag while pull request CI stays green.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
dirs=$(cargo metadata --no-deps --format-version 1 --manifest-path "$root/Cargo.toml" |
    jq -r --arg root "$root/" '.workspace_members as $m | .packages[] | select(.id as $id | $m | index($id)) | .manifest_path | ltrimstr($root) | split("/")[0]' |
    sort -u)
[ -n "$dirs" ] || { echo "no workspace members found" >&2; exit 1; }

status=0
for dockerfile in Dockerfile.reproducible contrib/debian/Dockerfile; do
    for dir in $dirs; do
        if ! grep -qx "COPY $dir ./$dir" "$root/$dockerfile"; then
            echo "$dockerfile does not copy workspace member directory $dir" >&2
            status=1
        fi
    done
done
[ "$status" -eq 0 ] && echo "release Dockerfiles copy every workspace member"
exit "$status"
