#!/usr/bin/env bash
# Przygotowanie pod agenta (bez kodu — C1)
set -euo pipefail
sudo useradd --system --home /var/lib/soho-guard --shell /usr/sbin/nologin soho-agent
sudo install -d -o soho-agent -g soho-agent -m 750 /var/lib/soho-guard/{r1,r2} /etc/soho-guard
sudo install -d /opt/soho-guard
sudo python3 -m venv /opt/soho-guard/venv
sudo /opt/soho-guard/venv/bin/pip install librouteros pyyaml netmiko
