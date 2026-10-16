#!/bin/bash
set -euo pipefail

install -m 755 /tmp/tdf-iroh-s3 /usr/local/bin/tdf-iroh-s3
install -m 755 /tmp/bootstrap.sh /usr/local/bin/tdf-iroh-s3-bootstrap
install -m 644 /tmp/tdf-iroh-s3.service /etc/systemd/system/tdf-iroh-s3.service
install -m 755 /tmp/cert-sync.sh /usr/local/bin/tdf-iroh-s3-cert-sync
install -m 644 /tmp/tdf-iroh-s3-cert-sync.service /etc/systemd/system/tdf-iroh-s3-cert-sync.service
install -m 644 /tmp/tdf-iroh-s3-cert-sync.timer /etc/systemd/system/tdf-iroh-s3-cert-sync.timer

# Create data directory for FsStore
install -d -o tdf-iroh-s3 -g tdf-iroh-s3 -m 750 /var/lib/tdf-iroh-s3/data

systemctl daemon-reload
systemctl enable tdf-iroh-s3.service
systemctl enable tdf-iroh-s3-cert-sync.timer
