#!/bin/sh
# Add a user or reset a password. Run from the deployment directory.
#   ./add-user.sh [--json] USER [PASSWORD]
# --json prints {"user":…,"password":…,"reset":…} for server/admin.sh.
# Neither the Caddy reload nor a reset restarts the gateway, so other users stay
# connected. A reset ends the user's tunnels and WebSockets; their Claude
# session survives only while the gateway still holds the old jar key in memory.
set -eu
. "$(dirname "$0")/install-lib.sh"
JSON=0
if [ "${1:-}" = --json ]; then JSON=1; shift; fi
USERNAME=${1:-}
PASSWORD=${2:-}
valid_user "$USERNAME" || { echo 'Error: username needs 1–64 ASCII letters, digits, dots, dashes or underscores; . and .. are invalid.' >&2; exit 1; }
[ -f Caddyfile ] || { echo 'Error: run from the deployment directory (Caddyfile missing).' >&2; exit 1; }
GENERATED=0
if [ -z "$PASSWORD" ]; then PASSWORD=$(openssl rand -hex 12); GENERATED=1; fi
[ "${#PASSWORD}" -ge 12 ] || { echo 'Error: password must be at least 12 characters.' >&2; exit 1; }
RESET=false
caddy_users Caddyfile | awk -v u="$USERNAME" '$1==u {found=1} END {exit !found}' && RESET=true
HASH=$(hash_password "$PASSWORD")
CANDIDATE=$(mktemp "$(pwd)/.Caddyfile.XXXXXX")
trap 'rm -f "$CANDIDATE"' EXIT HUP INT TERM
U="$USERNAME" H="$HASH" awk '
  /^[[:space:]]*basic_auth([[:space:]]|\{)/ {auth=1; print; print "            " ENVIRON["U"] " " ENVIRON["H"]; inserted=1;next}
  auth && /^[[:space:]]*}/ {auth=0}
  auth && $1 == ENVIRON["U"] && $2 ~ /^\$2/ {next}
  {print}
  END {if (!inserted) exit 1}' Caddyfile > "$CANDIDATE"
validate_caddy "$CANDIDATE" "$(env_get .env CONNECT_HOST)" "$(env_get .env FRONTDOOR_IP)"
install_caddyfile "$CANDIDATE"
umask 077
mkdir -p gateway/cookies
chmod 700 gateway/cookies
[ -f "gateway/cookies/$USERNAME.json" ] || printf '%s\n' '{"cookies":[]}' > "gateway/cookies/$USERNAME.json"
chmod 600 "gateway/cookies/$USERNAME.json"
reload_caddy
# Whoever knew the old password loses tunnels, WebSockets and WebSocket cookies.
if [ "$RESET" = true ]; then gateway_admin POST "/users/$USERNAME/revoke" >/dev/null 2>&1 || true; fi
if [ "$JSON" = 1 ]; then
  printf '{"user":"%s","password":"%s","reset":%s}\n' "$USERNAME" "$PASSWORD" "$RESET"
  exit 0
fi
if [ "$RESET" = true ]; then printf 'Password changed: %s\n' "$USERNAME"; else printf 'User ready: %s\n' "$USERNAME"; fi
if [ "$GENERATED" = 1 ]; then printf 'Password (shown once): %s\n' "$PASSWORD"; fi
