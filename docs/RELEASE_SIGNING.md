# Threshold Release Signing with Keep

Keep can act as a general-purpose threshold signer for software releases. A
project generates a FROST-Ed25519 group, distributes the `n` shares to its
maintainers, and signs release artifacts with `keep sign`. Producing a signature
requires a threshold `t` of those maintainers to cooperate, so no single person
holds the signing key. The output is minisign-compatible, so downstream users
verify with the stock [`minisign`](https://jedisct1.github.io/minisign/) tool or
with `keep verify`.

This is a Keep capability you can adopt for your own project. Keep's own GitHub
releases are not signed this way; they ship binaries and a `SHA256SUMS` manifest.

## Establishing a signing group

Done once. Generate the group, distribute the shares, and publish the public
key:

```sh
keep frost generate --ed25519 --threshold <t> --shares <n> \
  --name release-signing --pubkey-out release-signing.pub
```

Export each share to its holder with `keep frost export` (bech32 / QR), then
publish `release-signing.pub` somewhere users can find it (in your repository,
on your site, and/or attached to each release).

## Signing a release

Sign the checksum manifest rather than every artifact; the manifest covers them
all.

```sh
# Generate a checksum manifest for the release artifacts.
sha256sum keep-* > SHA256SUMS

# Threshold-sign the manifest (writes SHA256SUMS.minisig).
keep sign SHA256SUMS --group <group-npub-or-hex> -t "release v1.2.3"
```

`--group` accepts an `npub1...` string or a 64-char hex group pubkey. The
current minisign signing path is local-threshold: the `t` shares must be present
on the signing machine. See "Distributed signing" below.

Attach `SHA256SUMS`, `SHA256SUMS.minisig`, and `release-signing.pub` to the
release.

## Verifying a release

Users need the artifact, `SHA256SUMS`, `SHA256SUMS.minisig`, and the project
public key.

```sh
# 1. Confirm the downloaded files match the manifest.
sha256sum --check SHA256SUMS

# 2. Verify the manifest signature against the project public key.
minisign -V -p release-signing.pub -m SHA256SUMS
```

`minisign -V` prints `Signature and comment signature verified` on success. The
`SHA256SUMS.minisig` file must sit next to `SHA256SUMS`.

With Keep installed, verify without minisign:

```sh
keep verify SHA256SUMS SHA256SUMS.minisig --group release-signing.pub
```

`--group` accepts the public-key file, a hex group pubkey, or an `npub1...`
string.

## GitHub Actions example

Signing should not run in CI: putting the threshold of shares into CI secrets
recreates the single point of failure threshold signing exists to remove. Build
and publish in CI, then sign offline and upload the signature.

```yaml
# In your release job, after generating SHA256SUMS:
- name: Attach signing public key
  run: cp release-signing.pub artifacts/
- uses: softprops/action-gh-release@v3
  with:
    files: artifacts/*
```

After the release publishes, a maintainer signs and uploads the signature:

```sh
gh release download <tag> --pattern SHA256SUMS
keep sign SHA256SUMS --group <group-npub-or-hex> -t "release <tag>"
minisign -V -p release-signing.pub -m SHA256SUMS
gh release upload <tag> SHA256SUMS.minisig
```

Optionally, a non-blocking workflow triggered on `release: [published, edited]`
can run `minisign -V` to surface the signature status as a check once the
`.minisig` is uploaded.

## Distributed signing

The minisign signing path currently reconstructs the threshold from shares held
on one machine. Fully distributed signing, where no machine ever holds `t`
shares and signers cooperate over Nostr, reuses Keep's existing FROST network
coordination but is not yet wired to the minisign output format. Tracked in
[#500](https://github.com/privkeyio/keep/issues/500).
