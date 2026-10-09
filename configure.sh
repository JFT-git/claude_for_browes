#!/bin/sh
# Configure the extension + server templates for a given gateway domain.
# Usage: ./configure.sh claude.example.com
set -e

HOST="$1"
if [ -z "$HOST" ]; then
  echo "Usage: ./configure.sh <gateway-host>   e.g. ./configure.sh claude.example.com"
  exit 1
fi

# Domain part for excludedInitiatorDomains (e.g. example.com from claude.example.com)
DOMAIN=$(echo "$HOST" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')

echo "Configuring for gateway host: $HOST (domain: $DOMAIN)"

# Extension files
for f in extension/manifest.chrome.json extension/manifest.firefox.json extension/rules.json extension/background.js; do
  if [ -f "$f" ]; then
    sed -i.bak "s/__GATEWAY_HOST__/$HOST/g; s/__GATEWAY_DOMAIN__/$DOMAIN/g" "$f" && rm "$f.bak"
    echo "  configured $f"
  fi
done

# Build per-browser packages (extension/dist/chrome, extension/dist/firefox)
if command -v zip >/dev/null 2>&1; then
  ./extension/build.sh
else
  echo "  (zip not found — run extension/build.sh after installing it)"
fi

# Server Caddyfile
if [ -f server/Caddyfile.template ]; then
  sed "s/__DOMAIN__/$HOST/g" server/Caddyfile.template > server/Caddyfile
  echo "  generated server/Caddyfile (remember to set __BASIC_AUTH_USER__ and __BASIC_AUTH_HASH__)"
fi

# Server compose: set PUBLIC_HOST so the gateway rewrites URLs to your domain
if [ -f server/compose.yaml ]; then
  sed -i.bak "s|PUBLIC_HOST: \${PUBLIC_HOST:-[^}]*}|PUBLIC_HOST: \${PUBLIC_HOST:-$HOST}|" server/compose.yaml && rm server/compose.yaml.bak
  echo "  set PUBLIC_HOST=$HOST in server/compose.yaml"
fi

echo ""
echo "Done. Next steps:"
echo "  1. Server: edit server/Caddyfile — set basic_auth user + hash (caddy hash-password)"
echo "  2. Server: see docs/DEPLOY-SERVER.md"
echo "  3. Client: load extension/dist/chrome (Chrome) or extension/dist/firefox (Firefox), set credentials in Options"
echo "     see docs/SETUP-CLIENT.md"
