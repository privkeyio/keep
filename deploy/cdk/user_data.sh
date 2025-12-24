Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
bootcmd:
  - [ amazon-linux-extras, install, aws-nitro-enclaves-cli ]
packages:
  - aws-nitro-enclaves-cli-devel
  - jq
  - socat

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1
set -x
set +e

usermod -aG docker ec2-user
usermod -aG ne ec2-user

ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
sed -r "s/^(\s*memory_mib\s*:\s*).*/\1 4096/" -i "$ALLOCATOR_YAML"
sed -r "s/^(\s*cpu_count\s*:\s*).*/\1 2/" -i "$ALLOCATOR_YAML"

cat > /etc/nitro_enclaves/vsock-proxy.yaml <<EOF
allowlist:
- {address: kms.${__REGION__}.amazonaws.com, port: 443}
EOF

systemctl enable --now docker
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now nitro-enclaves-vsock-proxy.service

cd /home/ec2-user
mkdir -p app

cat > app/bootstrap.sh <<'SCRIPT'
#!/bin/bash
set -ex

token=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
account_id=$(curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.accountId')
region=$(curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/region)

aws ecr get-login-password --region $region | docker login --username AWS --password-stdin $account_id.dkr.ecr.$region.amazonaws.com
docker pull ${__ENCLAVE_IMAGE_URI__}

nitro-cli build-enclave --docker-uri ${__ENCLAVE_IMAGE_URI__} --output-file /home/ec2-user/app/keep-enclave.eif
SCRIPT
chmod +x app/bootstrap.sh

cat > app/run-enclave.py <<'SCRIPT'
#!/usr/bin/env python3
import json
import subprocess
import time

def describe_enclaves():
    proc = subprocess.run(["/bin/nitro-cli", "describe-enclaves"], capture_output=True)
    return json.loads(proc.stdout.decode()) if proc.returncode == 0 else []

def run_enclave():
    subprocess.run([
        "/bin/nitro-cli", "run-enclave",
        "--cpu-count", "2",
        "--memory", "3072",
        "--eif-path", "/home/ec2-user/app/keep-enclave.eif",
        "--enclave-cid", "16"
    ])

def main():
    run_enclave()
    while True:
        enclaves = describe_enclaves()
        if not enclaves or enclaves[0].get("State") != "RUNNING":
            run_enclave()
        time.sleep(10)

if __name__ == "__main__":
    main()
SCRIPT
chmod +x app/run-enclave.py

chown -R ec2-user:ec2-user app

cat > /etc/systemd/system/keep-enclave.service <<EOF
[Unit]
Description=Keep Nitro Enclave
After=network-online.target nitro-enclaves-allocator.service
Requires=nitro-enclaves-allocator.service

[Service]
Type=simple
ExecStartPre=/home/ec2-user/app/bootstrap.sh
ExecStart=/home/ec2-user/app/run-enclave.py
Restart=always
User=ec2-user

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/keep-vsock-proxy.service <<EOF
[Unit]
Description=TCP to vsock proxy for Keep Enclave
After=keep-enclave.service
Requires=keep-enclave.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:443,fork,reuseaddr VSOCK-CONNECT:16:5000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now keep-enclave.service
systemctl enable --now keep-vsock-proxy.service
--//--
