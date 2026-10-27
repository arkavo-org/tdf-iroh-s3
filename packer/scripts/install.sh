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

# CloudWatch agent: ships the node's and cert-sync's journal (systemd's
# exit and restart lines included) to CloudWatch Logs, so logs outlive the
# instance. Reading the journal needs agent 1.300070.0 or later.
dnf install -y amazon-cloudwatch-agent
agent_version=$(rpm -q --qf '%{VERSION}' amazon-cloudwatch-agent)
if [ "$(printf '%s\n' 1.300070.0 "$agent_version" | sort -V | head -n1)" != 1.300070.0 ]; then
  echo "amazon-cloudwatch-agent $agent_version cannot read the journal (needs 1.300070.0)" >&2
  exit 1
fi
install -m 644 /tmp/amazon-cloudwatch-agent.json /opt/aws/amazon-cloudwatch-agent/etc/tdf-iroh-s3.json
# Translate (and so validate) the config now without starting the agent:
# it starts at boot, with the instance's role rather than the build's.
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/tdf-iroh-s3.json

systemctl daemon-reload
systemctl enable tdf-iroh-s3.service
systemctl enable tdf-iroh-s3-cert-sync.service tdf-iroh-s3-cert-sync.timer
systemctl enable amazon-cloudwatch-agent.service
