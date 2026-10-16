#!/bin/sh
# Remove a user. Run from the deployment directory.
#   ./remove-user.sh [--json] USER
# Caddy reloads gracefully and the gateway ends only this user's tunnels,
# WebSockets and cookies in memory; other users stay connected. The cookie jar
# is deleted, not archived: an archived jar is still a live Claude session.
set -eu
. "$(dirname "$0")/install-lib.sh"
JSON=0
if [ "${1:-}" = --json ]; then JSON=1; shift; fi
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
install_caddyfile "$CANDIDATE"
failed=0
reload_caddy || failed=1
# Without the operator API (older gateway) a restart revokes every token.
gateway_admin POST "/users/$USERNAME/revoke?forget=1" >/dev/null 2>&1 || docker compose restart gateway >&2 || failed=1
JAR="gateway/cookies/$USERNAME.json"
if [ -f "$JAR" ]; then
  if command -v shred >/dev/null 2>&1; then shred -u "$JAR"; else rm -f "$JAR"; fi
fi
[ "$failed" = 0 ] || { echo 'Error: Caddy reload or token revocation failed; restart Caddy and the gateway to revoke the credentials.' >&2; exit 1; }
if [ "$JSON" = 1 ]; then printf '{"user":"%s","removed":true}\n' "$USERNAME"; else printf 'Removed user: %s. Their sessions and cookie jar are gone; other users stay connected.\n' "$USERNAME"; fi
