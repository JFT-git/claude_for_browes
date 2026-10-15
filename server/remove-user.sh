#!/bin/sh
# Removal restarts gateway too, revoking all minted CONNECT tokens immediately.
set -eu
. "$(dirname "$0")/install-lib.sh"
USERNAME=${1:-}
valid_user "$USERNAME" || { echo 'Error: invalid username (1–64 ASCII letters, digits, dot, dash, underscore; excluding . and ..).' >&2; exit 1; }
[ -f Caddyfile ] || { echo 'Error: run from deployment directory (Caddyfile missing).' >&2; exit 1; }
FOUND=$(caddy_users Caddyfile | awk -v u="$USERNAME" '$1==u {print "yes"}')
[ "$FOUND" = yes ] || { printf 'User %s not found.\n' "$USERNAME" >&2; exit 1; }
CANDIDATE=$(mktemp "$(pwd)/.Caddyfile.XXXXXX")
trap 'rm -f "$CANDIDATE"' EXIT HUP INT TERM
U="$USERNAME" awk '
  /^[[:space:]]*basic_auth([[:space:]]|\{)/ {auth=1}
  auth && /^[[:space:]]*}/ {auth=0}
  auth && $1==ENVIRON["U"] && $2 ~ /^\$2/ {next}
  {print}' Caddyfile > "$CANDIDATE"
validate_caddy "$CANDIDATE" "$(env_get .env CONNECT_HOST)" "$(env_get .env FRONTDOOR_IP)"
chmod 600 "$CANDIDATE"
mv "$CANDIDATE" Caddyfile
umask 077
mkdir -p gateway/cookies/.removed
chmod 700 gateway/cookies gateway/cookies/.removed
if [ -f "gateway/cookies/$USERNAME.json" ]; then
  mv "gateway/cookies/$USERNAME.json" "gateway/cookies/.removed/$USERNAME.$(date +%s).json"
fi
restart_failed=0
docker compose restart caddy || restart_failed=1
docker compose restart gateway || restart_failed=1
[ "$restart_failed" = 0 ] || { echo 'Error: restart failed; ensure both Caddy and gateway restart to revoke credentials and tokens.' >&2; exit 1; }
printf 'Removed user: %s. All users must reconnect: gateway restart revoked all CONNECT tokens.\n' "$USERNAME"
