#!/bin/sh
# Remove a user: drops the basic_auth line and moves the cookie file to gateway/cookies/.removed/
# Usage: ./remove-user.sh <username>
set -e
USER="$1"
[ -n "$USER" ] || { echo "Usage: ./remove-user.sh <username>"; exit 1; }
echo "$USER" | grep -qE '^[a-zA-Z0-9._-]+$' || { echo "Error: invalid username"; exit 1; }
[ -f Caddyfile ] || { echo "Error: run from the project dir (Caddyfile not found)"; exit 1; }
grep -qE "^ *$USER +\\\$2" Caddyfile || { echo "User '$USER' not found in Caddyfile"; exit 1; }
U="$USER" awk '$1 == ENVIRON["U"] && $2 ~ /^\$2/ { next } { print }' Caddyfile > Caddyfile.new && mv Caddyfile.new Caddyfile
mkdir -p gateway/cookies/.removed
[ -f "gateway/cookies/$USER.json" ] && mv "gateway/cookies/$USER.json" "gateway/cookies/.removed/$USER.$(date +%s).json"
docker compose restart caddy >/dev/null 2>&1 || true
echo "Removed user: $USER (cookie file archived in gateway/cookies/.removed/)"
