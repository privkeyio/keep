# Keep Enclave Deployment

Deploy Keep on AWS Nitro Enclaves for hardware-isolated signing.

## Architecture

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

Keys live only in enclave memory. KMS decrypts only if PCRs match.

## Prerequisites

- AWS account with EC2, KMS, IAM permissions
- AWS CLI configured
- Docker installed
- Nitro SDK binaries — see [keep-enclave/build/README.md](../keep-enclave/build/README.md)

## Deployment Options

| Method | Best for | Complexity |
|--------|----------|------------|
| **[Enclaver](#using-enclaver)** | Quick setup, simpler operations | Low |
| **[CDK (automated)](#automated-deployment-cdk)** | Production with full AWS integration | Medium |
| **[Manual](#manual-deployment)** | Learning, debugging, custom setups | Higher |

---

## Using Enclaver

[Enclaver](https://github.com/edgebitio/enclaver) simplifies enclave builds:

```bash
curl -sL https://github.com/edgebitio/enclaver/releases/latest/download/enclaver-linux-x86_64.tar.gz | tar xz
sudo mv enclaver /usr/local/bin/

docker build -f keep-enclave/build/Dockerfile.local -t keep-enclave:local .
enclaver build -f keep-enclave/enclaver.yaml
```

Deploy to EC2 (use [CDK](#automated-deployment-cdk) or [Manual](#manual-deployment) to provision an instance first):

```bash
docker save keep-enclave:enclave | gzip > keep-enclave.tar.gz
scp -i ~/.ssh/keep-enclave.pem keep-enclave.tar.gz ec2-user@<IP>:~/

# On EC2
docker load < keep-enclave.tar.gz
enclaver run keep-enclave:enclave
```

Still need [KMS setup](#kms-setup) for key persistence.

---

## Automated Deployment (CDK)

Create ECR repository and push enclave image first:

```bash
aws ecr create-repository --repository-name keep-enclave
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker build -f keep-enclave/build/Dockerfile.enclave -t keep-enclave:v1.0.0 .
docker tag keep-enclave:v1.0.0 <account>.dkr.ecr.us-east-1.amazonaws.com/keep-enclave:v1.0.0
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/keep-enclave:v1.0.0
```

Deploy infrastructure:

```bash
cd deploy/cdk
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
CDK_DEPLOY_ACCOUNT=<account> CDK_DEPLOY_REGION=us-east-1 cdk deploy -c image_tag=v1.0.0
```

Provisions VPC, ASG, NLB, KMS. Update KMS policy with PCRs after build.

## Manual Deployment

### IAM Role

```bash
aws iam create-role --role-name keep-enclave-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam create-instance-profile --instance-profile-name keep-enclave-profile
aws iam add-role-to-instance-profile --instance-profile-name keep-enclave-profile --role-name keep-enclave-role
export EC2_ROLE_ARN=$(aws iam get-role --role-name keep-enclave-role --query 'Role.Arn' --output text)
```

### SSH Key

```bash
aws ec2 create-key-pair --key-name keep-enclave --query 'KeyMaterial' --output text > ~/.ssh/keep-enclave.pem
chmod 400 ~/.ssh/keep-enclave.pem
```

### Launch EC2

```bash
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --count 1 \
  --instance-type m5.xlarge \
  --enclave-options 'Enabled=true' \
  --key-name keep-enclave \
  --iam-instance-profile Name=keep-enclave-profile \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":20}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=keep-enclave}]'
```

Note: AMI `ami-0c02fb55956c7d316` is for us-east-1. Find your region's Amazon Linux 2 AMI via `aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2 --query 'Parameter.Value' --output text`.

Supported: `m5.xlarge`, `m6i.xlarge`, `c5.xlarge`, `r5.xlarge` (and 2xlarge variants).

### Instance Setup

```bash
ssh -i ~/.ssh/keep-enclave.pem ec2-user@<INSTANCE_IP>

sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel docker -y
sudo usermod -aG ne,docker ec2-user
sudo tee /etc/nitro_enclaves/allocator.yaml <<< $'memory_mib: 512\ncpu_count: 2'
sudo systemctl enable --now nitro-enclaves-allocator docker
exit  # Re-login to apply groups
```

## Build Enclave

See [keep-enclave/build/README.md](../keep-enclave/build/README.md). Produces `keep-enclave.eif` and `pcrs.json`.

PCRs (Platform Configuration Registers) are hashes of the enclave code. They change on rebuild. KMS uses them to restrict decryption to your exact code.

```bash
scp -i ~/.ssh/keep-enclave.pem keep-enclave/build/keep-enclave.eif ec2-user@<IP>:~/
```

## KMS Setup

```bash
aws kms create-key --description "Keep Enclave" --tags TagKey=Project,TagValue=keep
export KMS_KEY_ID=<key-id-from-output>
aws kms create-alias --alias-name alias/keep-enclave --target-key-id $KMS_KEY_ID
```

Edit `keep-enclave/build/kms-policy.json`, replace all placeholders:
- `<EC2_INSTANCE_ROLE_ARN>`: Role ARN from IAM setup (use `echo $EC2_ROLE_ARN`)
- `<KMS_ADMIN_ROLE_ARN>`: Your IAM user/role ARN for key administration
- `<REGION>`: AWS region (e.g., `us-east-1`)
- `<ACCOUNT_ID>`: Your AWS account ID
- `<KMS_KEY_ID>`: Key ID from above
- `<PCR0_VALUE>`, `<PCR1_VALUE>`, `<PCR2_VALUE>`: From `pcrs.json` after build

```bash
aws kms put-key-policy --key-id $KMS_KEY_ID --policy-name default \
  --policy file://keep-enclave/build/kms-policy.json
```

## Run Enclave

```bash
nitro-cli run-enclave --eif-path ~/keep-enclave.eif --memory 512 --cpu-count 2
nitro-cli describe-enclaves  # Note EnclaveCID (usually 16)
```

Debug mode (PCR0 = zeros, insecure):
```bash
nitro-cli run-enclave --eif-path ~/keep-enclave.eif --memory 512 --cpu-count 2 --debug-mode
nitro-cli console --enclave-id <id>  # View logs
```

Stop: `nitro-cli terminate-enclave --all`

## CLI Commands

```bash
keep enclave verify --cid 16                                    # Verify attestation
keep enclave generate-key --name mykey --cid 16                 # Generate key in enclave
keep enclave import-key --name enclavekey --from-vault vaultkey --cid 16
keep enclave sign --key mykey --message <hex> --cid 16
keep enclave sign-psbt --key mykey --psbt tx.psbt --network testnet --cid 16
```

Policy example (enforced inside enclave):

```rust
PolicyRule::MaxAmountSats(1_000_000)  // 0.01 BTC limit
PolicyRule::MaxPerHour(10)            // Rate limit
```

## Local Development

Mock mode (no security, dev only):
```bash
keep enclave generate-key --name test --local
keep enclave sign --key test --message <hex> --local
```

QEMU emulation (vsock testing, no real attestation):
```bash
qemu-system-x86_64 -M nitro-enclave,vsock=parent -kernel keep-enclave.eif -m 512 -nographic --enable-kvm
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| `Enclave boot failed` | Increase `--memory` |
| `No enclave support` | Use Nitro-capable instance |
| `Resource busy` | `nitro-cli terminate-enclave --all` |
| `AccessDeniedException` | PCR mismatch—rebuild, update KMS policy |
| Vsock failed | Check `nitro-cli describe-enclaves`, verify CID |

Debug mode KMS: set PCR0 to 96 zeros in policy.

## Security Notes

- PCRs change on rebuild—update KMS policy each time
- Debug mode sets PCR0=0, bypasses attestation—never in prod
- Keys lost on restart unless persisted via KMS envelope encryption
- Host can't decrypt—KMS policy restricts to enclave with matching PCRs
- No network in enclave—host proxies KMS

## Checklist

- [ ] Runs without `--debug-mode`
- [ ] Attestation passes
- [ ] KMS works with real PCRs
- [ ] Signing works
- [ ] Policy enforced
- [ ] Keys survive restart
- [ ] Wrong PCRs fail decrypt
