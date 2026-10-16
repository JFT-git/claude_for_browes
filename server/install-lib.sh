#!/bin/sh
# Shared installer/user-management helpers. .env is data, never shell code.
valid_user() {
  [ -n "$1" ] && [ "${#1}" -le 64 ] && [ "$1" != . ] && [ "$1" != .. ] || return 1
  case "$1" in *[!a-zA-Z0-9._-]*) return 1;; esac
}
valid_domain() {
  case "$1" in ""|*[!a-zA-Z0-9.-]*) return 1;; esac
  [ "${#1}" -le 253 ] || return 1
  printf '%s\n' "$1" | awk -F. '
    NF < 2 { exit 1 }
    { for (i=1;i<=NF;i++) if (length($i)>63 || $i !~ /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/) exit 1 }
    $NF !~ /^[a-zA-Z][a-zA-Z]+$/ { exit 1 }'
}
valid_public_ipv4() {
  case "$1" in ""|*[!0-9.]*) return 1;; esac
  printf '%s\n' "$1" | awk -F. '
    NF!=4 {exit 1}
    {for(i=1;i<=4;i++) if ($i !~ /^[0-9]+$/ || length($i)>3 || $i+0>255 || (length($i)>1 && substr($i,1,1)=="0")) exit 1}
    $1==0 || $1==10 || $1==127 || $1>=224 || ($1==100 && $2>=64 && $2<=127) || ($1==169 && $2==254) || ($1==172 && $2>=16 && $2<=31) || ($1==192 && ($2==168 || $2==0)) || ($1==198 && ($2==18 || $2==19 || ($2==51 && $3==100))) || ($1==203 && $2==0 && $3==113) {exit 1}'
}
env_get() {
  [ -f "$1" ] || return 0
  awk -v key="$2" '
    {
      line=$0; sub(/\r$/, "", line); sub(/^[ \t]*(export[ \t]+)?/, "", line)
      if (line !~ "^" key "[ \t]*=") next
      if (seen++) {print "Duplicate dotenv setting: " key > "/dev/stderr"; bad=1; exit 1}
      sub("^" key "[ \t]*=[ \t]*", "", line)
      quote=substr(line,1,1)
      if (quote=="\047" || quote=="\042") {
        line=substr(line,2); stop=index(line,quote)
        if (!stop || substr(line,stop+1) !~ /^[ \t]*(#.*)?$/) {print "Unsupported dotenv value: " key > "/dev/stderr";bad=1;exit 1}
        value=substr(line,1,stop-1)
      } else {value=line;sub(/[ \t]+#.*/, "", value);sub(/[ \t]+$/, "", value)}
    }
    END {if (!bad) printf "%s",value}' "$1"
}
env_has() {
  [ -f "$1" ] && awk -v key="$2" '
    {line=$0;sub(/^[ \t]*(export[ \t]+)?/, "",line);if(line ~ "^" key "[ \t]*=") found=1}
    END {exit !found}' "$1"
}
# Only basic_auth entries are carried forward; routing always comes from the template.
caddy_users() {
  [ -f "$1" ] || return 0
  awk '
    /^[[:space:]]*basic_auth([[:space:]]|\{)/ {auth=1;next}
    auth && /^[[:space:]]*}/ {auth=0;next}
    auth && NF==2 && $2 ~ /^\$2[aby]\$/ {print $1 " " $2}' "$1"
}
render_caddy() {
  RENDER_HOST="$1" RENDER_USERS="$2" awk '
    {gsub(/__DOMAIN__/,ENVIRON["RENDER_HOST"])}
    /__BASIC_AUTH_USER__ __BASIC_AUTH_HASH__/ {
      while ((getline entry < ENVIRON["RENDER_USERS"])>0) print "            " entry
      close(ENVIRON["RENDER_USERS"]);next
    }
    {print}' "$3" > "$4"
}
# The password goes to Caddy on stdin, never on a command line that `ps` shows.
hash_password() {
  case "$1" in *"
"*) echo 'Error: password must not contain a newline.' >&2; return 1;; esac
  hash_output=$(printf '%s\n' "$1" | docker run --rm -i caddy:2.11.7 caddy hash-password 2>/dev/null) || { echo 'Error: password hashing failed.' >&2; return 1; }
  case "$hash_output" in *[!a-zA-Z0-9./\$]*) echo 'Error: invalid bcrypt hash returned.' >&2; return 1;; esac
  printf '%s\n' "$hash_output" | awk 'length($0)==60 && /^\$2[aby]\$[0-9][0-9]\$/ {valid=1} END {exit !valid}' || { echo 'Error: invalid bcrypt hash returned.' >&2; return 1; }
  printf '%s' "$hash_output"
}
validate_caddy() (
  umask 077
  validation_log=$(mktemp "${TMPDIR:-/tmp}/claude-caddy-validation.XXXXXX") || exit 1
  trap 'rm -f "$validation_log"' EXIT HUP INT TERM
  candidate_dir=$(cd "$(dirname "$1")" && pwd)
  if ! docker run --rm -e "CONNECT_HOST=$2" -e "FRONTDOOR_IP=${3:-172.30.240.2}" \
    -v "$candidate_dir/$(basename "$1"):/etc/caddy/Caddyfile:ro" \
    caddy:2.11.7 caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile > "$validation_log" 2>&1; then
    echo 'Error: Caddy candidate validation failed; configuration was not installed.' >&2
    exit 1
  fi
)
# Rewrite the Caddyfile in place: compose bind-mounts this exact file (inode),
# so a renamed replacement would stay invisible to a graceful reload.
install_caddyfile() (
  umask 077
  cp Caddyfile .Caddyfile.prev
  trap 'rm -f .Caddyfile.prev' EXIT HUP INT TERM
  if ! cat "$1" > Caddyfile || [ "$(cksum < "$1")" != "$(cksum < Caddyfile)" ]; then
    cat .Caddyfile.prev > Caddyfile
    echo 'Error: cannot write Caddyfile; previous version kept.' >&2
    exit 1
  fi
  chmod 600 Caddyfile
)
# Graceful reload over Caddy's private admin socket keeps every other user's
# connections open; a restart is the fallback (first run after an update).
reload_caddy() {
  docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    || docker compose restart caddy >&2
}
# The gateway's operator API listens on the container's loopback only.
gateway_admin() {
  docker compose exec -T gateway node -e '
    const [method, path] = process.argv.slice(1);
    fetch("http://127.0.0.1:" + (process.env.ADMIN_PORT || 8089) + path, { method, signal: AbortSignal.timeout(10000) })
      .then(async r => { process.stdout.write(await r.text()); if (!r.ok) process.exitCode = 1; })
      .catch(() => { process.exitCode = 2; });' "$1" "$2"
}
