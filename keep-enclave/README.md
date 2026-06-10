# keep-enclave

AWS Nitro Enclave signer for Keep. Private keys are generated and used inside a
hardware-isolated enclave and never leave its memory; the host verifies the enclave via
Nitro attestation (certificate chain to the AWS root, PCR measurement pinning, and a
nonce challenge) before trusting it.

The crate is split into `host/` (runs on the EC2 parent instance) and `enclave/` (runs
inside the enclave), with a reproducible enclave build (see `Dockerfile.reproducible` at
the repo root) so the running image can be independently verified against its PCRs.

For deployment, KMS setup, and attestation details, see
[`docs/ENCLAVE.md`](../docs/ENCLAVE.md). For the CLI, see
[`docs/USAGE.md` › AWS Nitro Enclaves](../docs/USAGE.md#aws-nitro-enclaves).
