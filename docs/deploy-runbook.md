# Deploy runbook: iroh.arkavo.net

This covers deploying the node that serves creator catalogs ([creator-catalogs.md](creator-catalogs.md)) at `iroh.arkavo.net`. The host is an Amazon Linux 2023 arm64 `t4g.medium` with the elastic IP `3.91.18.97`. Iroh listens on UDP 11204, and the HTTP API listens on `127.0.0.1:8090` behind TLS.

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

- **New instance from the AMI.** Launch it with the config below as user-data. `bootstrap.sh` writes user-data to `/etc/tdf-iroh-s3/config.toml` only when that file does not exist. Then move the elastic IP `3.91.18.97` to the new instance.
- **In place.** Copy the binary to the running instance and restart the service:

  ```bash
  scp /tmp/tdf-iroh-s3.gz ec2-user@3.91.18.97:/tmp/
  ssh ec2-user@3.91.18.97 'gunzip -f /tmp/tdf-iroh-s3.gz &&
    sudo install -m 755 /tmp/tdf-iroh-s3 /usr/local/bin/tdf-iroh-s3 &&
    sudo systemctl restart tdf-iroh-s3'
  ```

  Edit `/etc/tdf-iroh-s3/config.toml` on the instance before the restart.

Either way the NodeId stays the same. It comes from the SSM parameter `[iroh] secret_key_param` (default `/tdf-iroh-s3/node-secret-key`), not from the instance.

- The iOS viewer compiles the endpoint ID and addresses into its release configuration.
- Never delete or rotate that parameter without shipping a viewer release first.

## 3. Configuration additions

Add these settings to `/etc/tdf-iroh-s3/config.toml`, or to the user-data for a new instance:

```toml
[iroh]
bind_port = 11204
# Reported by GET /node as directAddresses. The node cannot see its
# elastic IP itself.
public_addresses = ["3.91.18.97:11204"]

[validation]
# Larger pushes are refused. The default is 4 GiB (the largest payloadSize
# a catalog may name).
max_blob_bytes = 4294967296

[http]
enabled = true
bind_address = "127.0.0.1"   # only the TLS proxy on this host reaches the API
bind_port = 8090
cose_keys_url = "https://identity.arkavo.net/.well-known/cose-keys"
expected_issuer = "https://identity.arkavo.net"
```

**Memory.** Ingest holds the whole blob in memory: it reads the blob from the iroh store, validates it, and uploads it to S3. A `t4g.medium` has 4 GiB of RAM, so a blob near the 4 GiB default will exhaust memory before it is refused for any other reason.

- On this instance type, set `max_blob_bytes = 2147483648` (2 GiB), or move to an instance with more memory.
- The node refuses a blob over the limit before reading it, so a lower limit is safe.

Keep the rest of the config as it is: `[s3]`, `[publishing]` (gated by default) and `[catalog]`.

## 4. TLS for iroh.arkavo.net

The iOS viewer pins the **leaf certificate's SubjectPublicKeyInfo** (SHA-256, lowercase hex), on top of normal system trust. A renewal must keep the same private key. Otherwise every installed viewer stops connecting until it gets an app update.

### Open the ports

The security group opens only TCP 22 and UDP 11204. Add TCP 80, for the ACME HTTP-01 challenge and the HTTPS redirect, and TCP 443. Keep 8090 closed.

```bash
SG=<security group id of the instance>
for port in 80 443; do
  aws ec2 authorize-security-group-ingress --group-id "$SG" \
    --ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}]"
done
```

`iroh.arkavo.net` must resolve to `3.91.18.97`.

### nginx and certbot

AL2023 has no certbot package. Install certbot into a virtualenv, as certbot's own instructions describe:

```bash
sudo dnf install -y nginx python3 augeas-libs
sudo python3 -m venv /opt/certbot
sudo /opt/certbot/bin/pip install --upgrade pip certbot certbot-nginx
sudo ln -sf /opt/certbot/bin/certbot /usr/bin/certbot

sudo tee /etc/nginx/conf.d/iroh.arkavo.net.conf >/dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name iroh.arkavo.net;

    client_max_body_size 1m;   # catalogs are at most 256 KiB; the node answers 413

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
sudo systemctl enable --now nginx
```

Issue the certificate with an ECDSA P-256 key, and set `--reuse-key` so that every renewal keeps that key:

```bash
sudo certbot --nginx -d iroh.arkavo.net \
  --key-type ecdsa --elliptic-curve secp256r1 --reuse-key \
  --redirect --agree-tos -m <ops email>

# Renewals reuse the key while this says True:
sudo grep reuse_key /etc/letsencrypt/renewal/iroh.arkavo.net.conf
```

A certbot installed with pip does not add a renewal timer, and AL2023 has no cron, so add a systemd timer:

```bash
sudo tee /etc/systemd/system/certbot-renew.service >/dev/null <<'EOF'
[Unit]
Description=Renew Let's Encrypt certificates

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
EOF
sudo tee /etc/systemd/system/certbot-renew.timer >/dev/null <<'EOF'
[Unit]
Description=Renew Let's Encrypt certificates twice a day

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now certbot-renew.timer
sudo certbot renew --dry-run
```

Never pass `--new-key` to certbot, and never delete `/etc/letsencrypt` on this host. Either one replaces the pinned key.

### Compute the pin

Compute the pin from the live endpoint:

```bash
openssl s_client -connect iroh.arkavo.net:443 -servername iroh.arkavo.net </dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
# SHA2-256(stdin)= <64 lowercase hex>   <- the pin
```

The same value comes from the key on the host:

```bash
sudo openssl pkey -in /etc/letsencrypt/live/iroh.arkavo.net/privkey.pem -pubout -outform der \
  | openssl dgst -sha256
```

Run the first command again after the first renewal. The value must not change.

### Backup pin

Ship two pins in the iOS release configuration: the live key, and a backup key that is generated now and kept offline. If the live key is ever lost or compromised, the backup lets the server move to a new key without breaking installed viewers.

```bash
# Offline, on a trusted machine. Store iroh-backup.key in the secrets vault, not on the host.
openssl ecparam -name prime256v1 -genkey -noout -out iroh-backup.key
openssl pkey -in iroh-backup.key -pubout -outform der | openssl dgst -sha256   # backup pin
```

To switch to the backup key:

1. Request a certificate for it with a CSR.
2. Install the certificate in nginx.
3. Ship a viewer release that pins the new key and a fresh backup.

```bash
openssl req -new -key iroh-backup.key -subj "/CN=iroh.arkavo.net" \
  -addext "subjectAltName=DNS:iroh.arkavo.net" -out iroh-backup.csr
sudo certbot certonly --nginx --csr iroh-backup.csr \
  --cert-path /etc/nginx/iroh-backup-cert.pem --fullchain-path /etc/nginx/iroh-backup-fullchain.pem
# Point ssl_certificate / ssl_certificate_key in the nginx server block at the
# new fullchain and at iroh-backup.key, then: sudo systemctl reload nginx
```

certbot does not renew certificates issued from a CSR. Repeat the `certonly --csr` command before the certificate expires, which is every 90 days, until a viewer release moves the pins.

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
# {"endpointId":"<64 hex>","relayUrl":"https://...","directAddresses":["3.91.18.97:11204"]}

ssh ec2-user@3.91.18.97 'sudo journalctl -u tdf-iroh-s3 | grep "Node ID:" | tail -1'
```

The endpoint ID must match the one in the iOS release configuration.

## 7. Post-deploy smoke checks

```bash
curl -fsS https://iroh.arkavo.net/healthz
# ok

curl -fsS https://iroh.arkavo.net/node
# endpointId as above; directAddresses ["3.91.18.97:11204"]; relayUrl a URL or null

curl -sS https://iroh.arkavo.net/blobs/0000000000000000000000000000000000000000000000000000000000000000
# {"error":"blob not found"}  (a 502 here means the IAM ListBucket grant is missing)

curl -sS https://iroh.arkavo.net/blobs/<hash of a published TDF>
# {"hash":"<hash>","size":<bytes>}

curl -sS http://iroh.arkavo.net/healthz -o /dev/null -w '%{http_code}\n'
# 301 (redirect to https)
```

Then compute the pin as in section 4 and compare it with the iOS release configuration.

Run an end-to-end push and fetch from outside the VPC with the test CLI. On a gated node, the token needs the publishing entitlement.

```bash
cargo run --release --bin tdf-iroh-s3-test -- publish \
  -n <endpointId> --addr 3.91.18.97:11204 \
  --url https://iroh.arkavo.net --token-file token.txt -d recording.tdf
cargo run --release --bin tdf-iroh-s3-test -- fetch \
  -n <endpointId> --addr 3.91.18.97:11204 --hash <hash> -o /tmp/check.tdf
```
