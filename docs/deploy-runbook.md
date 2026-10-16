# Deploy runbook: iroh.arkavo.net

This covers deploying the release that serves creator catalogs ([creator-catalogs.md](creator-catalogs.md)) at `iroh.arkavo.net`. The host is an Amazon Linux 2023 arm64 `t4g.medium` launched from the `tdf-iroh-s3` launch template. Iroh listens on UDP 11204. The node terminates TLS itself on 443 with an ACM-exported certificate (`[http.tls]`, kept current by `cert-sync`; see the README), and its plain listener on 8090 is loopback-only.

## 1. Build the arm64 Linux binary

The binary must run on AL2023, which ships glibc 2.34. A binary built against a newer glibc, such as one from a Debian bookworm `rust` image (2.36), will not start. Build inside `amazonlinux:2023`. Colima on Apple Silicon is aarch64, so this is a native arm64 build with no emulation.

```bash
cd tdf-iroh-s3
docker --context colima run --rm -v "$PWD":/src -w /src amazonlinux:2023 bash -c '
  set -euo pipefail
  dnf install -y -q gcc gcc-c++ make cmake perl clang tar gzip
  curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain stable
  . "$HOME/.cargo/env"
  cargo build --release --locked --target-dir /src/target/al2023
  objdump -T target/al2023/release/tdf-iroh-s3 | grep -o "GLIBC_[0-9.]*" | sort -Vu | tail -1
'
```

The last line prints the newest glibc symbol the binary needs. It must be `GLIBC_2.34` or older. An AL2023 arm64 EC2 instance can run the same commands without Docker.

## 2. Publish the binary and bake the AMI

Packer pulls the binary from `s3://arkavo-report/packer/tdf-iroh-s3.gz` (`binary_s3_uri` in `packer/ami.pkr.hcl`), using the instance profile `packer-s3-read`.

```bash
gzip -9c target/al2023/release/tdf-iroh-s3 > /tmp/tdf-iroh-s3.gz
aws s3 cp /tmp/tdf-iroh-s3.gz s3://arkavo-report/packer/tdf-iroh-s3.gz

cd packer
packer init .
packer build ami.pkr.hcl
```

You can roll the release out in either of two ways.

- **New instance from the AMI.** Point the launch template at the new AMI, add the configuration below to its user-data, and launch. `bootstrap.sh` writes user-data to `/etc/tdf-iroh-s3/config.toml` only when that file does not exist. Then move the `iroh.arkavo.net` CNAME to the new instance and stop the old one.
- **In place.** Copy the binary to the running instance and restart the service:

  ```bash
  scp /tmp/tdf-iroh-s3.gz ec2-user@<instance>:/tmp/
  ssh ec2-user@<instance> 'gunzip -f /tmp/tdf-iroh-s3.gz &&
    sudo install -m 755 /tmp/tdf-iroh-s3 /usr/local/bin/tdf-iroh-s3 &&
    sudo systemctl restart tdf-iroh-s3'
  ```

  Edit `/etc/tdf-iroh-s3/config.toml` on the instance before the restart. SSH accepts only the allowlisted address in the security group.

  `systemctl stop` and `restart` send SIGTERM, which the node handles by shutting down cleanly. To confirm that the last stop was clean:

  ```bash
  ssh ec2-user@<instance> 'sudo journalctl -u tdf-iroh-s3 | grep -E "SIGTERM received|Done\." | tail -2'
  # ... SIGTERM received, shutting down...
  # ... Done.
  ```

  The first restart onto this release stops a binary without SIGTERM handling, so nothing matches until the restart after that.

Either way the NodeId stays the same. It comes from the SSM parameter `[iroh] secret_key_param` (default `/tdf-iroh-s3/node-secret-key`), not from the instance.

- The iOS viewer compiles the endpoint ID and addresses into its release configuration.
- Never delete or rotate that parameter without shipping a viewer release first.

## 3. Configuration additions

Add these settings to `/etc/tdf-iroh-s3/config.toml`, or to the user-data for a new instance:

```toml
[iroh]
bind_port = 11204
# Reported by GET /node as directAddresses; the node cannot see its own
# public IP. Use an address that survives a stop and start (an elastic IP).
# Leave it out rather than list one that changes: publishers then reach the
# node through its relay.
public_addresses = ["<public ip>:11204"]

[validation]
# Larger pushes are refused. The default is 4 GiB (the largest payloadSize
# a catalog may name).
max_blob_bytes = 4294967295

[http]
enabled = true
bind_port = 8090   # loopback-only while [http.tls] is set
cose_keys_url = "https://identity.arkavo.net/.well-known/cose-keys"
expected_issuer = "https://identity.arkavo.net"
```

**Memory.** Ingest holds the whole blob in memory: it reads the blob from the iroh store, validates it, and uploads it to S3. A `t4g.medium` has 4 GiB of RAM, so a blob near the 4 GiB default will exhaust memory before it is refused for any other reason.

- On this instance type, set `max_blob_bytes = 2147483648` (2 GiB), or move to an instance with more memory. `GET /node` reports the limit as `maxBlobBytes`, and Creator refuses a larger recording before uploading it.
- The node refuses a blob over the limit before reading it, so a lower limit is safe.

Keep the rest of the config as it is: `[s3]`, `[publishing]` (gated by default) and `[catalog]`.

## 4. TLS for iroh.arkavo.net

Nothing changes here: the node keeps terminating TLS with the ACM-exported certificate that `cert-sync` installs (`[http.tls]`, README). The security group needs TCP 443 and UDP 11204 open; keep 8090 closed.

The iOS viewer pins the **leaf certificate's SubjectPublicKeyInfo** (SHA-256, lowercase hex), on top of normal system trust. Compute the pin it must carry:

```bash
echo | openssl s_client -connect iroh.arkavo.net:443 -servername iroh.arkavo.net 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
# SHA2-256(stdin)= <64 lowercase hex>   <- the pin
```

**The pin changes when the key does.** ACM manages the key, and a renewal can come with a new one; then every installed viewer stops reaching the HTTPS routes until it gets an app update. Check the pin after each renewal. Before the iOS release ships pins, decide how renewals keep a pinned key (for example, a viewer release with the next key's pin ahead of each renewal, or a key the team controls). The certificate in use in October 2026 expires on 2027-05-01.

## 5. IAM

The instance role already has access to `<prefix>blobs/*`, `manifests/*`, `catalog-index/*`, `tags/*` and `moderation/*`. Creator catalogs add read and write access to `catalog-documents/*`:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::<bucket>/<prefix>catalog-documents/*"
},
{
  "Effect": "Allow",
  "Action": "s3:ListBucket",
  "Resource": "arn:aws:s3:::<bucket>"
}
```

The role needs `s3:ListBucket` on the bucket itself, without a prefix condition. Without it, S3 answers a request for a missing key with 403 instead of 404. The node then reports `GET /blobs/{hash}` and `GET /catalog-documents/{hash}` for unknown hashes as 502 `storage unavailable` instead of 404.

`GET /blobs/{hash}` is an S3 `HeadObject` on `blobs/<hash>`, which the existing `s3:GetObject` on `blobs/*` covers.

## 6. Read the NodeId

The NodeId (endpoint ID) is a 64-character lowercase hex string. Two places report it:

```bash
curl -s https://iroh.arkavo.net/node
# {"endpointId":"<64 hex>","relayUrl":"https://...","directAddresses":[...],"maxBlobBytes":<bytes>}

ssh ec2-user@<instance> 'sudo journalctl -u tdf-iroh-s3 | grep "Node ID:" | tail -1'
```

The endpoint ID must match the one in the iOS release configuration.

## 7. Post-deploy smoke checks

```bash
curl -fsS https://iroh.arkavo.net/healthz
# ok

curl -fsS https://iroh.arkavo.net/node
# endpointId as above; directAddresses as configured; relayUrl a URL or null; maxBlobBytes

curl -sS https://iroh.arkavo.net/blobs/0000000000000000000000000000000000000000000000000000000000000000
# {"error":"blob not found"}  (a 502 here means the IAM ListBucket grant is missing)

curl -sS https://iroh.arkavo.net/blobs/<hash of a published TDF>
# {"hash":"<hash>","size":<bytes>}
```

Then compute the pin as in section 4 and compare it with the iOS release configuration.

Run an end-to-end push and fetch from outside the VPC with the test CLI. On a gated node, the token needs the publishing entitlement.

```bash
cargo run --release --bin tdf-iroh-s3-test -- publish \
  -n <endpointId> --addr <public ip>:11204 \
  --url https://iroh.arkavo.net --token-file token.txt -d recording.tdf
cargo run --release --bin tdf-iroh-s3-test -- fetch \
  -n <endpointId> --addr <public ip>:11204 --hash <hash> -o /tmp/check.tdf
```
