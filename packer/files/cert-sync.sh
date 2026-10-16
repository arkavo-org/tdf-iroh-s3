#!/bin/bash
# Export the node's exportable ACM certificate into the PEM files the HTTPS
# listener reads ([http.tls] cert_path / key_path). The node reloads them when
# they change, so this runs on a timer and rewrites only when ACM has renewed.
set -euo pipefail

CONFIG_PATH="/etc/tdf-iroh-s3/config.toml"
SERVICE_USER="tdf-iroh-s3"

# Value of `key = "..."` inside the [http.tls] table of the config.
tls_value() {
    awk -v key="$1" '
        /^\s*\[/ { in_tls = ($0 ~ /^\s*\[http\.tls\]\s*$/); next }
        in_tls && $0 ~ "^\\s*" key "\\s*=" {
            sub(/^[^=]*=\s*"/, ""); sub(/".*$/, ""); print; exit
        }' "$CONFIG_PATH"
}

[ -f "$CONFIG_PATH" ] || { echo "No config at $CONFIG_PATH yet"; exit 0; }

CERT_ARN=$(tls_value acm_certificate_arn)
CERT_PATH=$(tls_value cert_path)
KEY_PATH=$(tls_value key_path)
if [ -z "$CERT_ARN" ]; then
    echo "[http.tls] acm_certificate_arn not set; nothing to sync"
    exit 0
fi
: "${CERT_PATH:?[http.tls] cert_path is required}"
: "${KEY_PATH:?[http.tls] key_path is required}"

# The ARN carries the region: arn:aws:acm:<region>:<account>:certificate/<id>
REGION=$(echo "$CERT_ARN" | cut -d: -f4)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

# ACM returns the key encrypted under a passphrase we choose; a fresh random
# one per run never leaves this directory.
openssl rand -base64 32 | tr -d '\n' > "$WORK/pass"

aws acm export-certificate \
    --region "$REGION" \
    --certificate-arn "$CERT_ARN" \
    --passphrase "fileb://$WORK/pass" \
    --output json > "$WORK/export.json"

python3 - "$WORK" <<'PY'
import json, sys, os
work = sys.argv[1]
e = json.load(open(os.path.join(work, "export.json")))
chain = e["Certificate"].strip() + "\n" + e.get("CertificateChain", "").strip() + "\n"
open(os.path.join(work, "fullchain.pem"), "w").write(chain)
open(os.path.join(work, "key.enc.pem"), "w").write(e["PrivateKey"])
PY

openssl pkey -in "$WORK/key.enc.pem" -passin "file:$WORK/pass" -out "$WORK/privkey.pem"

if [ -f "$CERT_PATH" ] && cmp -s "$WORK/fullchain.pem" "$CERT_PATH"; then
    echo "Certificate unchanged ($(openssl x509 -in "$CERT_PATH" -noout -enddate))"
    exit 0
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")"
# Key first, then chain: the node reloads when either changes and a pair it
# cannot load keeps the old certificate in service until the next check.
install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 600 "$WORK/privkey.pem" "$KEY_PATH.tmp"
mv -f "$KEY_PATH.tmp" "$KEY_PATH"
install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 644 "$WORK/fullchain.pem" "$CERT_PATH.tmp"
mv -f "$CERT_PATH.tmp" "$CERT_PATH"

echo "Certificate updated ($(openssl x509 -in "$CERT_PATH" -noout -subject -enddate | tr '\n' ' '))"
