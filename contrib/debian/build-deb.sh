#!/bin/sh
# Build Debian packages for the keep CLI and the keep-web daemon from
# prebuilt binaries.
#
#   contrib/debian/build-deb.sh <bin-dir> <ui-dir> <out-dir>
#
# <bin-dir>  holds `keep` and `keep-web` built for the host architecture
# <ui-dir>   holds the built admin SPA (keep-web/ui/dist)
# <out-dir>  receives the .deb files
#
# Build this in the oldest distribution you intend to support: the packages
# pick up a libc6 floor from the glibc they were linked against.
set -eu

BIN_DIR=${1:?usage: build-deb.sh <bin-dir> <ui-dir> <out-dir>}
UI_DIR=${2:?usage: build-deb.sh <bin-dir> <ui-dir> <out-dir>}
OUT_DIR=${3:?usage: build-deb.sh <bin-dir> <ui-dir> <out-dir>}

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

VERSION=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml")
[ -n "$VERSION" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }
ARCH=$(dpkg --print-architecture)
MAINTAINER="PrivKey LLC <security@privkey.io>"
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    DATE=$(date -R -u -d "@$SOURCE_DATE_EPOCH")
    MANDATE=$(date -u +%Y-%m-%d -d "@$SOURCE_DATE_EPOCH")
else
    DATE=$(date -R -u)
    MANDATE=$(date -u +%Y-%m-%d)
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT_DIR"

# dpkg-shlibdeps derives the real libc6/libgcc-s1 floor instead of guessing.
shlibdeps() {
    _sd=$WORK/shlibdeps
    rm -rf "$_sd"
    mkdir -p "$_sd/debian"
    printf 'Source: keep\nPackage: %s\nArchitecture: %s\n' "$1" "$ARCH" > "$_sd/debian/control"
    cp "$2" "$_sd/"
    ( cd "$_sd" && dpkg-shlibdeps -O --ignore-missing-info "./$(basename "$2")" 2>/dev/null ) \
        | sed 's/^shlibs:Depends=//'
}

install_man() {
    install -d -m 0755 "$(dirname "$2")"
    sed -e "s/@VERSION@/$VERSION/g" -e "s/@DATE@/$MANDATE/g" "$1" | gzip -9n > "$2.gz"
    chmod 0644 "$2.gz"
}

write_common() {
    _tree=$1 _pkg=$2
    install -d -m 0755 "$_tree/usr/share/doc/$_pkg"

    {
        printf 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n'
        printf 'Upstream-Name: keep\n'
        printf 'Source: https://github.com/privkeyio/keep\n\n'
        printf 'Files: *\n'
        printf 'Copyright: 2026 PrivKey LLC\n'
        printf 'License: MIT\n'
        sed 's/^$/./; s/^/ /' "$ROOT/LICENSE"
    } > "$_tree/usr/share/doc/$_pkg/copyright"

    {
        printf '%s (%s) stable; urgency=medium\n\n' "$_pkg" "$VERSION"
        printf '  * Upstream release %s.\n\n' "$VERSION"
        printf ' -- %s  %s\n' "$MAINTAINER" "$DATE"
    # Native package (version carries no Debian revision), so Policy wants
    # changelog.gz rather than changelog.Debian.gz.
    } | gzip -9n > "$_tree/usr/share/doc/$_pkg/changelog.gz"
}

finish() {
    _tree=$1 _pkg=$2
    ( cd "$_tree" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
        | LC_ALL=C sort -z | xargs -0 md5sum > DEBIAN/md5sums )
    sed -i "s|^Installed-Size:.*|Installed-Size: $(du -k -s --exclude=DEBIAN "$_tree" | cut -f1)|" \
        "$_tree/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$_tree" "$OUT_DIR/${_pkg}_${VERSION}_${ARCH}.deb" >/dev/null
    echo "built $OUT_DIR/${_pkg}_${VERSION}_${ARCH}.deb"
}

# ---------------------------------------------------------------- keep (CLI)

T=$WORK/keep
install -D -m 0755 "$BIN_DIR/keep" "$T/usr/bin/keep"
install -D -m 0644 "$ROOT/contrib/completions/keep.bash" \
    "$T/usr/share/bash-completion/completions/keep"
install -D -m 0644 "$ROOT/contrib/completions/keep.zsh" \
    "$T/usr/share/zsh/vendor-completions/_keep"
install -D -m 0644 "$ROOT/contrib/completions/keep.fish" \
    "$T/usr/share/fish/vendor_completions.d/keep.fish"
install_man "$HERE/keep.1" "$T/usr/share/man/man1/keep.1"
write_common "$T" keep

install -d -m 0755 "$T/DEBIAN"
cat > "$T/DEBIAN/control" <<EOF
Package: keep
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Section: utils
Priority: optional
Homepage: https://github.com/privkeyio/keep
Installed-Size: 0
Depends: $(shlibdeps keep "$BIN_DIR/keep")
Description: Self-custodial key manager for Nostr and Bitcoin
 Keep stores Nostr and Bitcoin keys in an encrypted vault and signs with them
 without ever exposing the key material to the requesting application. It
 supports FROST threshold signatures, so a key can be split across several
 devices with no single device holding the whole secret.
 .
 This package provides the keep command line interface and its shell
 completions.
EOF
finish "$T" keep

# ------------------------------------------------------------ keep-web daemon

T=$WORK/keep-web
install -D -m 0755 "$BIN_DIR/keep-web" "$T/usr/bin/keep-web"
install -d -m 0755 "$T/usr/share/keep-web"
cp -r "$UI_DIR" "$T/usr/share/keep-web/ui"
find "$T/usr/share/keep-web/ui" -type d -exec chmod 0755 {} +
find "$T/usr/share/keep-web/ui" -type f -exec chmod 0644 {} +
install -D -m 0644 "$HERE/keep-web.env" "$T/etc/keep-web/keep-web.env"
install -D -m 0644 "$HERE/keep-web.service" \
    "$T/usr/lib/systemd/system/keep-web.service"
install_man "$HERE/keep-web.8" "$T/usr/share/man/man8/keep-web.8"
write_common "$T" keep-web

install -d -m 0755 "$T/DEBIAN"
for s in postinst prerm postrm; do
    install -m 0755 "$HERE/keep-web.$s" "$T/DEBIAN/$s"
done
echo /etc/keep-web/keep-web.env > "$T/DEBIAN/conffiles"
cat > "$T/DEBIAN/control" <<EOF
Package: keep-web
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Section: utils
Priority: optional
Homepage: https://github.com/privkeyio/keep
Installed-Size: 0
Depends: $(shlibdeps keep-web "$BIN_DIR/keep-web"), adduser, init-system-helpers (>= 1.52)
Recommends: keep
Description: Always-on FROST co-signer and web admin for Keep
 keep-web runs as a system service holding one share of a Keep FROST
 threshold key. It coordinates signatures with the other shareholders over
 Nostr relays, so a signature needs a quorum of devices and no single machine
 can sign on its own. It also answers NIP-46 bunker requests and serves a web
 admin interface for approving signing requests.
 .
 The service ships disabled: it needs a vault password in
 /etc/keep-web/password and a FROST group in /etc/keep-web/keep-web.env
 before it will start.
EOF
finish "$T" keep-web
