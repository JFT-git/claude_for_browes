#!/bin/sh
# Add a user to the gateway: generates a basic_auth credential and a cookie slot.
# Run on the server from the project dir (where Caddyfile lives).
# Usage: ./add-user.sh <username> <password>
set -e

USER="$1"
PASS="$2"

if [ -z "$USER" ] || [ -z "$PASS" ]; then
  echo "Usage: ./add-user.sh <username> <password>"
  exit 1
fi

# sanitize username (must match gateway's sanitizeUser: a-zA-Z0-9._-)
if ! echo "$USER" | grep -qE '^[a-zA-Z0-9._-]+$'; then
  echo "Error: username may only contain letters, digits, dot, dash, underscore"
  exit 1
fi

if [ ! -f Caddyfile ]; then
  echo "Error: Caddyfile not found in current directory. Run from the project dir."
  exit 1
fi

# generate bcrypt hash
HASH=$(docker run --rm caddy:2 caddy hash-password --plaintext "$PASS" 2>/dev/null | tail -1)
if [ -z "$HASH" ]; then
  echo "Error: failed to generate hash (is docker running?)"
  exit 1
fi

# insert the user into the basic_auth block (before the closing brace of basic_auth)
# uses a marker comment if present, else appends inside basic_auth
if grep -q "# one line per user" Caddyfile; then
  sed -i.bak "s|# one line per user:.*|&\n            $USER $HASH|" Caddyfile && rm Caddyfile.bak
else
  # fallback: insert after "basic_auth {"
  sed -i.bak "/basic_auth {/a\\            $USER $HASH" Caddyfile && rm Caddyfile.bak
fi

# create the cookie slot dir entry (empty file the gateway will fill on first login)
mkdir -p gateway/cookies
[ -f "gateway/cookies/$USER.json" ] || echo '{"cookies":[]}' > "gateway/cookies/$USER.json"
chmod 600 "gateway/cookies/$USER.json" 2>/dev/null || true

# reload caddy
docker compose restart caddy >/dev/null 2>&1 || docker restart claude-browser-caddy-1 >/dev/null 2>&1 || true

echo "Added user: $USER"
echo "  basic_auth: $USER / $PASS"
echo "  cookie slot: gateway/cookies/$USER.json"
echo ""
echo "Next: the user logs in once via https://<domain>/ (magic-link) — the gateway"
echo "captures their session cookies automatically. See docs/SETUP-CLIENT.md."
