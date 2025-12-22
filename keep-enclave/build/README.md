# Enclave Build

Builds `keep-enclave.eif` (enclave image) and `pcrs.json` (hashes for KMS policy).

## Local Testing

```bash
docker build -f keep-enclave/build/Dockerfile.local -t keep-enclave:local .
docker run --rm keep-enclave:local  # Will fail on vsock—expected
```

## Enclaver (Recommended)

```bash
curl -sL https://github.com/edgebitio/enclaver/releases/latest/download/enclaver-linux-x86_64.tar.gz | tar xz
sudo mv enclaver /usr/local/bin/

docker build -f keep-enclave/build/Dockerfile.local -t keep-enclave:local .
enclaver build -f keep-enclave/enclaver.yaml
```

Deploy to EC2:

```bash
docker save keep-enclave:enclave | gzip > keep-enclave.tar.gz
scp -i ~/.ssh/keep-enclave.pem keep-enclave.tar.gz ec2-user@<IP>:~/

# On EC2
docker load < keep-enclave.tar.gz
enclaver run keep-enclave:enclave
```

## Full Build (with KMS)

Requires `kmstool_enclave_cli` and `libnsm.so` from [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c):

```bash
git clone https://github.com/aws/aws-nitro-enclaves-sdk-c.git
cd aws-nitro-enclaves-sdk-c && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
cp bin/kmstool-enclave-cli ../../keep-enclave/build/kmstool_enclave_cli
cp lib/libnsm.so ../../keep-enclave/build/
cd ../../keep-enclave/build/
echo "$(sha256sum kmstool_enclave_cli | cut -d' ' -f1)  /app/kmstool_enclave_cli" > checksums.sha256
echo "$(sha256sum libnsm.so | cut -d' ' -f1)  /usr/lib64/libnsm.so" >> checksums.sha256
```

Then build:

```bash
./build-enclave.sh
```

Outputs `keep-enclave.eif` and `pcrs.json`. Deploy via [docs/ENCLAVE.md](../../docs/ENCLAVE.md).
