#!/usr/bin/env bash
# Instalacja RITA v5.1.2 (wymaga Docker Engine + Compose v2)
set -euo pipefail
mkdir -p ~/rita-install && cd ~/rita-install
wget https://github.com/activecm/rita/releases/download/v5.1.2/rita-v5.1.2.tar.gz
echo "c77d99842877439dac5b460b4b17d081f21e32eab40263dfade32ccc81afaec0  rita-v5.1.2.tar.gz" | sha256sum -c
tar -xzf rita-v5.1.2.tar.gz
sudo ./rita-v5.1.2-installer/install_rita.sh
