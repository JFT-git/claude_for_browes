#!/bin/sh
# Add a user (or reset an existing user's password).
# Run on the server from the project dir (where Caddyfile lives).
# Usage: ./add-user.sh <username> [password]
#   no password given -> a strong random one is generated and printed ONCE.
set -e

USER="$1"
PASS="$2"

if [ -z "$USER" ]; then
  echo "Usage: ./add-user.sh <username> [password]"
  exit 1
fi
if ! echo "$USER" | grep -qE '^[a-zA-Z0-9._-]+$' || [ "${#USER}" -gt 64 ]; then
  echo "Error: username may only contain letters, digits, dot, dash, underscore (max 64)"
  exit 1
fi
[ -f Caddyfile ] || { echo "Error: Caddyfile not found in current directory. Run from the project dir."; exit 1; }

GENERATED=0
if [ -z "$PASS" ]; then
  PASS=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
  GENERATED=1
fi
if [ "${#PASS}" -lt 12 ]; then
  echo "Error: password must be at least 12 characters (or omit it to generate one)"
  exit 1
fi

HASH=$(docker run --rm caddy:2 caddy hash-password --plaintext "$PASS" 2>/dev/null | tail -1)
[ -n "$HASH" ] || { echo "Error: failed to generate hash (is docker running?)"; exit 1; }

# drop an existing line for this user, then insert the new one after the marker
# (awk + ENVIRON: no shell/sed escaping problems with the '$' characters in bcrypt hashes)
U="$USER" H="$HASH" awk '
  $1 == ENVIRON["U"] && $2 ~ /^\$2/ { next }
  { print }
  /# one line per user/ { printf "            %s %s\n", ENVIRON["U"], ENVIRON["H"] }
' Caddyfile > Caddyfile.new
grep -q "^ *$USER " Caddyfile.new || { rm -f Caddyfile.new; echo "Error: marker '# one line per user' not found in Caddyfile"; exit 1; }
mv Caddyfile.new Caddyfile

mkdir -p gateway/cookies
[ -f "gateway/cookies/$USER.json" ] || echo '{"cookies":[]}' > "gateway/cookies/$USER.json"
chmod 600 "gateway/cookies/$USER.json" 2>/dev/null || true

docker compose restart caddy >/dev/null 2>&1 || true

echo "User ready: $USER"
if [ "$GENERATED" = "1" ]; then
  echo "  password (shown once): $PASS"
else
  echo "  password: (the one you provided)"
fi
echo "  cookie slot: gateway/cookies/$USER.json"
echo ""
echo "Send the user: extension download page https://<domain>/__ext/ , their login and password."
echo "They sign in to Claude through the gateway (or import a session) — see docs/SETUP-CLIENT.md."
