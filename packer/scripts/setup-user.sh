#!/bin/bash
set -euo pipefail

useradd --system --no-create-home --shell /sbin/nologin tdf-iroh-s3

mkdir -p /etc/tdf-iroh-s3
mkdir -p /var/lib/tdf-iroh-s3

chown tdf-iroh-s3:tdf-iroh-s3 /var/lib/tdf-iroh-s3
# The service user must OWN /etc/tdf-iroh-s3: bootstrap.sh runs as this user
# (systemd ExecStartPre, no '+' prefix) and creates config.toml here from
# instance user-data. A root-owned 750 dir left the group without write, so
# bootstrap failed with "Permission denied" and the node never started. 750
# keeps the dir private to the service user.
chown tdf-iroh-s3:tdf-iroh-s3 /etc/tdf-iroh-s3
chmod 750 /etc/tdf-iroh-s3
chmod 750 /var/lib/tdf-iroh-s3
