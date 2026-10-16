#!/bin/sh
# Operator entry point for the local dashboard (dashboard/dashboard.js) and the
# console. Output never contains cookie values, password hashes or request paths.
#
#   ./admin.sh status [MINUTES]   gateway, front door, containers, host, users
#   ./admin.sh watch [SECONDS]    status every SECONDS (default 5), forever
#   ./admin.sh add USER           new user; prints {"user":…,"password":…} once
#   ./admin.sh reset USER         new password for an existing user (same output)
#   ./admin.sh remove USER        removes the user, their live access and cookie jar
#   ./admin.sh unban IP
#
# Status output is a sequence of "@@section" lines followed by their data and
# ends with "@@end". A dedicated SSH key can be limited to these commands:
#   restrict,command="/root/claude-browser/admin.sh --ssh" ssh-ed25519 AAAA… dashboard
set -eu
cd "$(dirname "$0")"
. ./install-lib.sh

if [ "${1:-}" = --ssh ]; then
  # Forced command: the request comes only from SSH_ORIGINAL_COMMAND, split into
  # words without glob expansion; every word is validated below.
  set -f
  # shellcheck disable=SC2086
  set -- ${SSH_ORIGINAL_COMMAND:-}
  set +f
  case "${1:-}" in admin.sh|*/admin.sh) shift;; esac
fi

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
number() { case "$1" in ''|*[!0-9]*) return 1;; esac; [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]; }
user_exists() { caddy_users Caddyfile | awk -v u="$1" '$1==u {found=1} END {exit !found}'; }

status() {
  echo '@@gateway'
  if gateway_json=$(gateway_admin GET "/status?history=$1" 2>/dev/null); then printf '%s\n' "$gateway_json"
  else echo '{"error":"gateway_unreachable"}'; fi
  echo '@@frontdoor'
  # One interval line every 30 s when FRONTDOOR_DIAGNOSTICS=1.
  docker compose logs --no-log-prefix --timestamps --since 75s frontdoor 2>/dev/null | grep '"frontdoor_diagnostics"' | tail -n 1 || true
  echo '@@containers'
  ids=$(docker compose ps -q 2>/dev/null || true)
  # shellcheck disable=SC2086
  [ -z "$ids" ] || docker stats --no-stream --format '{{json .}}' $ids 2>/dev/null || true
  echo '@@host'
  printf 'cpus %s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)"
  printf 'load %s\n' "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || true)"
  awk '/^MemTotal:/ {print "mem_total_kb " $2} /^MemAvailable:/ {print "mem_available_kb " $2}' /proc/meminfo 2>/dev/null || true
  df -Pk . 2>/dev/null | awk 'NR==2 {print "disk_total_kb " $2; print "disk_used_kb " $3}'
  printf 'uptime_sec %s\n' "$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)"
  echo '@@config'
  printf 'users %s\n' "$(caddy_users Caddyfile | awk '{printf "%s%s", sep, $1; sep=" "}')"
  printf 'admins %s\n' "$(env_get .env ADMIN_USERS | tr ',' ' ')"
  printf 'public_host %s\n' "$(env_get .env PUBLIC_HOST)"
  printf 'frontdoor_diagnostics %s\n' "$(env_get .env FRONTDOOR_DIAGNOSTICS)"
  printf 'legacy_key %s\n' "$( [ -n "$(env_get .env COOKIES_KEY)" ] && echo yes || echo no)"
  printf 'backups %s\n' "$(ls -1 backups/state-*.tar.gz.enc 2>/dev/null | wc -l | tr -d ' ')"
  printf 'backup_latest %s\n' "$(ls -1t backups/state-*.tar.gz.enc 2>/dev/null | head -n 1 | sed 's|.*/state-||; s|\.tar\.gz\.enc$||')"
  echo '@@end'
}

[ -f Caddyfile ] || die 'run from the deployment directory (Caddyfile missing)'
command=${1:-}
case "$command" in
  status)
    minutes=${2:-60}; number "$minutes" 1 1440 || die 'MINUTES must be 1–1440'
    status "$minutes";;
  watch)
    seconds=${2:-5}; number "$seconds" 2 300 || die 'SECONDS must be 2–300'
    # The first snapshot carries 24 hours of history, later ones the last minutes.
    status 1440
    while sleep "$seconds"; do status 3; done;;
  add)
    valid_user "${2:-}" || die 'invalid username'
    user_exists "$2" && die "user $2 already exists"
    ./add-user.sh --json "$2";;
  reset)
    valid_user "${2:-}" || die 'invalid username'
    user_exists "$2" || die "user $2 not found"
    ./add-user.sh --json "$2";;
  remove)
    valid_user "${2:-}" || die 'invalid username'
    ./remove-user.sh --json "$2";;
  unban)
    case "${2:-}" in ''|*[!0-9a-fA-F:.]*) die 'invalid IP';; esac
    [ "${#2}" -le 45 ] || die 'invalid IP'
    gateway_admin POST "/bans/$2/clear"; echo;;
  *)
    die 'usage: admin.sh status [MINUTES] | watch [SECONDS] | add USER | reset USER | remove USER | unban IP';;
esac
