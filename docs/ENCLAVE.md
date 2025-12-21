# Keep Enclave Deployment Guide

Deploy Keep's TEE-based signing infrastructure on AWS Nitro Enclaves.

## Overview

Keep uses AWS Nitro Enclaves to provide hardware-isolated signing for Nostr and Bitcoin. Keys never leave the enclave memory, and KMS policies enforce that only verified enclave code can decrypt stored keys.

**Architecture:**
```
┌─────────────────────────────────────────────────────────┐
│                    AWS Nitro Enclave                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │              keep-enclave binary                   │  │
│  │  • Private keys (memory only)                     │  │
│  │  • Policy engine (amount limits, rate limits)     │  │
│  │  • FROST threshold signing                        │  │
│  │  • PSBT sighash computation                       │  │
│  └───────────────────────────────────────────────────┘  │
│                          ▲                              │
│                          │ vsock                        │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │                   Host (EC2)                       │  │
│  │  • Routes requests to enclave                     │  │
│  │  • Verifies attestation                           │  │
│  │  • Never sees private keys                        │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │                    AWS KMS                         │  │
│  │  Key Policy: Decrypt only if PCR0/1/2 match       │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites

**First**, download the required AWS Nitro SDK binaries by following [keep-enclave/build/README.md](../keep-enclave/build/README.md). The enclave build will fail without these.

## Automated Deployment (CDK)

For automated infrastructure provisioning:

```bash
cd deploy/cdk
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export CDK_DEPLOY_ACCOUNT=<your-account-id>
export CDK_DEPLOY_REGION=us-east-1
export CDK_PREFIX=prod  # or dev

cdk bootstrap
cdk deploy
```

This provisions VPC, auto-scaling group, NLB, KMS key, and ECR. After deployment, update the KMS key policy with PCR values from the build output.

## Manual Deployment

### Prerequisites

### AWS Account Setup

1. **IAM User with Admin Access**
   ```bash
   aws configure sso
   # or for existing profile:
   aws sso login --profile YourProfile
   ```

2. **SSH Key Pair**
   ```bash
   # Create new key pair
   aws ec2 create-key-pair --key-name keep-enclave --query 'KeyMaterial' --output text > ~/.ssh/keep-enclave.pem
   chmod 400 ~/.ssh/keep-enclave.pem
   ```

### Launch EC2 Instance

Launch a Nitro-capable instance with enclave support enabled:

```bash
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --count 1 \
  --instance-type m5.xlarge \
  --enclave-options 'Enabled=true' \
  --key-name keep-enclave \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":20}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=keep-enclave}]'
```

**Supported Instance Types:**
- `m5.xlarge`, `m5.2xlarge` (Intel)
- `m6i.xlarge`, `m6i.2xlarge` (Intel)
- `c5.xlarge`, `c5.2xlarge` (Intel)
- `r5.xlarge`, `r5.2xlarge` (Intel)

### Instance Setup

SSH into your instance and install required packages:

```bash
ssh -i ~/.ssh/keep-enclave.pem ec2-user@<INSTANCE_IP>
```

```bash
# Install Nitro CLI
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo yum install docker socat jq -y

# Add user to required groups
sudo usermod -aG ne ec2-user
sudo usermod -aG docker ec2-user

# Configure enclave resources
sudo tee /etc/nitro_enclaves/allocator.yaml << EOF
memory_mib: 512
cpu_count: 2
EOF

# Enable services
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now docker

# Logout and login to apply group changes
exit
```

Verify installation:
```bash
nitro-cli --version
docker --version
```

## Build Enclave

### Download Dependencies

The enclave requires `kmstool_enclave_cli` and `libnsm.so` from the AWS Nitro SDK.

See [keep-enclave/build/README.md](../keep-enclave/build/README.md) for:
- Download instructions
- Checksum verification
- Building from source

### Build EIF

```bash
cd keep-enclave/build
./build-enclave.sh
```

Output:
```
=== Build Complete ===
EIF: keep-enclave/build/keep-enclave.eif
PCRs saved to: keep-enclave/build/pcrs.json

PCR0 (Image): abc123...
PCR1 (Kernel): def456...
PCR2 (Application): ghi789...
```

**Record the PCR values** - you'll need them for the KMS key policy.

### Copy to EC2

```bash
scp -i ~/.ssh/keep-enclave.pem \
  keep-enclave/build/keep-enclave.eif \
  ec2-user@<INSTANCE_IP>:~/
```

## KMS Setup

### Create KMS Key

```bash
aws kms create-key \
  --description "Keep Enclave Master Key" \
  --tags TagKey=Project,TagValue=keep

# Note the KeyId from output
export KMS_KEY_ID=<key-id-from-output>

# Create alias
aws kms create-alias \
  --alias-name alias/keep-enclave \
  --target-key-id $KMS_KEY_ID
```

### Apply PCR-Restricted Policy

Edit `keep-enclave/build/kms-policy.json` and replace placeholders:
- `<EC2_INSTANCE_ROLE_ARN>` - IAM role attached to EC2 instance
- `<REGION>` - AWS region (e.g., `us-east-1`)
- `<ACCOUNT_ID>` - Your AWS account ID
- `<KMS_KEY_ID>` - Key ID from above
- `<PCR0_VALUE>`, `<PCR1_VALUE>`, `<PCR2_VALUE>` - From build output
- `<KMS_ADMIN_ROLE_ARN>` - Role for key administration

Apply the policy:
```bash
aws kms put-key-policy \
  --key-id $KMS_KEY_ID \
  --policy-name default \
  --policy file://kms-policy.json
```

## Run Enclave

### Start Enclave

```bash
nitro-cli run-enclave \
  --eif-path ~/keep-enclave.eif \
  --memory 512 \
  --cpu-count 2
```

For debugging (PCR0 becomes all zeros):
```bash
nitro-cli run-enclave \
  --eif-path ~/keep-enclave.eif \
  --memory 512 \
  --cpu-count 2 \
  --debug-mode
```

### Verify Running

```bash
nitro-cli describe-enclaves
```

Output:
```json
{
  "EnclaveName": "keep-enclave",
  "EnclaveID": "i-abc123-enc-def456",
  "ProcessID": 12345,
  "EnclaveCID": 16,
  "NumberOfCPUs": 2,
  "CPUIDs": [1, 3],
  "MemoryMiB": 512,
  "State": "RUNNING",
  "Flags": "NONE"
}
```

Note the `EnclaveCID` (typically 16).

### View Debug Logs

```bash
nitro-cli console --enclave-id <enclave-id>
```

### Stop Enclave

```bash
nitro-cli terminate-enclave --all
```

## CLI Commands

### Verify Attestation

```bash
keep enclave verify --cid 16
```

Verifies:
- Certificate chain to AWS Nitro root CA
- PCR values match expected
- Attestation document is valid

### Generate Key in Enclave

```bash
keep enclave generate-key --name mykey --cid 16
```

Returns the public key (npub). Private key exists only in enclave memory.

### Import Key from Vault

```bash
keep enclave import-key --name enclavekey --from-vault vaultkey --cid 16
```

Encrypts the key with KMS envelope encryption and imports to enclave.

### Sign Message

```bash
keep enclave sign --key mykey --message <hex> --cid 16
```

### Sign PSBT

```bash
keep enclave sign-psbt --key mykey --psbt unsigned.psbt --network testnet --cid 16
```

The enclave:
1. Parses the PSBT
2. Computes sighash internally
3. Checks policy (amount limits, address allowlists)
4. Signs if policy allows

### Set Policy

Policies are set via the API and enforced inside the enclave:

```rust
PolicyConfig {
    policies: vec![
        Policy {
            name: "spending_limit",
            rules: vec![
                PolicyRule::MaxAmountSats(1_000_000),  // 0.01 BTC
                PolicyRule::MaxPerHour(10),
            ],
            action: PolicyAction::Deny,
        }
    ]
}
```

## Local Development

For testing without AWS Nitro hardware:

```bash
# Mock enclave (keys stored in /tmp/keep-mock-enclave.redb)
keep enclave status --local
keep enclave generate-key --name test --local
keep enclave sign --key test --message <hex> --local
```

**Warning:** `--local` mode is NOT secure. Keys are stored unencrypted. For development only.

### QEMU Nitro Emulation

QEMU 8.0+ supports a `nitro-enclave` machine type for local testing without AWS:

```bash
qemu-system-x86_64 -M nitro-enclave,vsock=parent \
  -kernel keep-enclave.eif \
  -m 512 -nographic --enable-kvm -cpu host
```

This lets you test vsock communication and boot flow locally. Limitations:
- No real attestation (PCRs are mock values)
- No KMS integration
- Requires Linux with KVM support

## Troubleshooting

### Enclave Won't Start

| Error | Cause | Solution |
|-------|-------|----------|
| `Enclave boot failed` | Insufficient memory | Increase `--memory` |
| `No enclave support` | Instance type | Use Nitro-capable instance |
| `Resource busy` | Enclave already running | `nitro-cli terminate-enclave --all` |

### KMS Decrypt Failed

| Error | Cause | Solution |
|-------|-------|----------|
| `AccessDeniedException` | PCR mismatch | Rebuild enclave, update KMS policy |
| `InvalidCiphertextException` | Wrong key | Check KMS key ID |
| `KMSInternalException` | AWS issue | Retry |

For debug mode, set PCR0 to all zeros in KMS policy:
```
"kms:RecipientAttestation:PCR0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
```

### Vsock Connection Failed

```bash
# Check enclave is running
nitro-cli describe-enclaves

# Check CID matches (default 16)
keep enclave verify --cid 16
```

### View Enclave Logs

```bash
# Get enclave ID
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# View console output
nitro-cli console --enclave-id $ENCLAVE_ID
```

## Security Considerations

1. **PCR Values Change on Rebuild** - Any code change produces new PCRs. Update KMS policy after each build.

2. **Debug Mode** - Sets PCR0 to zeros. Never use in production.

3. **Key Persistence** - Keys in enclave memory are lost on restart. Use KMS envelope encryption for persistence.

4. **Instance Role** - EC2 instance role needs `kms:Decrypt` permission, but KMS policy restricts to enclave-only.

5. **Network Isolation** - Enclaves have no network access. All communication via vsock to parent.

## Testing Checklist

Before production deployment:

- [ ] Enclave starts without `--debug-mode`
- [ ] Attestation verification passes
- [ ] KMS decrypt works (with real PCRs, not zeros)
- [ ] Key generation works
- [ ] Signing works
- [ ] Policy enforcement works
- [ ] Rate limiting works
- [ ] Key survives enclave restart (via KMS)
- [ ] Wrong PCRs fail KMS decrypt (security test)
