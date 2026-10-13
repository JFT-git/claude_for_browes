#!/bin/sh
# Configure the SERVER for a given gateway domain.
# The browser extension no longer needs a domain — the user enters it in Options
# (one build for all domains). This script only:
#   * generates server/Caddyfile from the template
#   * sets PUBLIC_HOST in server/compose.yaml
#   * builds the (domain-independent) extension packages
# Usage: ./configure.sh claude.example.com
set -e

HOST="$1"
if [ -z "$HOST" ]; then
  echo "Usage: ./configure.sh <gateway-host>   e.g. ./configure.sh claude.example.com"
  exit 1
fi

echo "Configuring server for gateway host: $HOST"

# Build the extension (domain-independent: host is entered by the user in Options)
if command -v zip >/dev/null 2>&1; then
  ./extension/build.sh
else
  echo "  (zip not found — run extension/build.sh after installing it)"
fi

# Server Caddyfile
if [ -f server/Caddyfile.template ]; then
  sed "s/__DOMAIN__/$HOST/g" server/Caddyfile.template > server/Caddyfile
  echo "  generated server/Caddyfile (install.sh will set the basic_auth user + hash)"
fi

# Server compose: set PUBLIC_HOST so the gateway rewrites URLs to your domain
if [ -f server/compose.yaml ]; then
  sed -i.bak "s|PUBLIC_HOST: \${PUBLIC_HOST:-[^}]*}|PUBLIC_HOST: \${PUBLIC_HOST:-$HOST}|" server/compose.yaml && rm server/compose.yaml.bak
  echo "  set PUBLIC_HOST=$HOST in server/compose.yaml"
fi

echo ""
echo "Done. Next steps:"
echo "  1. Server: run ./install.sh (interactive) or docs/DEPLOY-SERVER.md"
echo "  2. Client: load extension/dist/chrome (Chrome) or extension/dist/firefox (Firefox),"
echo "     enter your gateway host + credentials in Options — see docs/SETUP-CLIENT.md"
