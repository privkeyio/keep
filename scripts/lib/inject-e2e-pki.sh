#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# Makes the throwaway CA the gateway e2e's own build of the inject worker
# trusts (built with RUSTFLAGS='--cfg keep_e2e_roots' and KEEP_E2E_CA_DER
# naming ca.der), and the certificate its test server presents for
# echo.keep.test and evil.keep.test. The CA's key is deleted once the
# certificate is signed.
#
#   scripts/lib/inject-e2e-pki.sh <empty directory>

set -euo pipefail
dir=${1:?usage: inject-e2e-pki.sh <directory>}
mkdir -p "$dir"
cd "$dir"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -sha256 -days 30 -subj "/CN=keep gateway e2e CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -out ca.pem
openssl x509 -in ca.pem -outform der -out ca.der
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
openssl req -new -key leaf.key -subj "/CN=echo.keep.test" -out leaf.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:echo.keep.test,DNS:evil.keep.test\n' >leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -sha256 \
    -extfile leaf.ext -out leaf.pem 2>/dev/null
rm -f ca.key ca.srl leaf.csr leaf.ext
