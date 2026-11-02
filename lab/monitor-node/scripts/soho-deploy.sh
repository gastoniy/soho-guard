#!/usr/bin/env bash
# /usr/local/sbin/soho-deploy.sh <tag> — wdrożenie soho-guard z taga do /opt/soho-guard/app
# Czynność operatora (root), kanał utrzymaniowy. Kod tylko do odczytu dla soho-agent.
# Wycofanie: ponowne uruchomienie z poprzednim tagiem (przełącza dowiązanie app).
set -euo pipefail
TAG=${1:?użycie: soho-deploy.sh <tag>}
REPO=${SOHO_REPO:-https://github.com/gastoniy/soho-guard.git}
REL=/opt/soho-guard/releases/$TAG
if [ ! -d "$REL" ]; then
  git clone --quiet --depth 1 --branch "$TAG" "$REPO" "$REL.tmp"
  git -C "$REL.tmp" verify-tag "$TAG" 2>/dev/null || echo "UWAGA: tag $TAG niepodpisany (ADR-002 zakłada tagi podpisane)"
  rm -rf "$REL.tmp/.git"
  mv "$REL.tmp" "$REL"
fi
/opt/soho-guard/venv/bin/pip install --quiet -r "$REL/requirements.txt"
/opt/soho-guard/venv/bin/pip freeze > "$REL/requirements.lock"
chown -R root:root "$REL" && chmod -R go-w "$REL"
ln -sfn "$REL" /opt/soho-guard/app
echo "wdrożono $TAG -> $(readlink -f /opt/soho-guard/app)"
