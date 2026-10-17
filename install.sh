#!/usr/bin/env bash
# Interactive installation and safe upgrades. Run on the deployment server.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"
. ./server/install-lib.sh
ok() { printf '✔ %s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
ask() {
  local name="$1" prompt="$2" default="${3:-}" answer=''
  read -r -p "$prompt${default:+ [$default]}: " answer || true
  printf -v "$name" '%s' "${answer:-$default}"
}
ask_secret() { local name="$1" prompt="$2" answer=''; read -r -s -p "$prompt: " answer || true; echo; printf -v "$name" '%s' "$answer"; }
confirm() { local answer=''; read -r -p "$1 [Y/n]: " answer || true; case "${answer:-Y}" in [Yy]*) return 0;; *) return 1;; esac; }
for dependency in docker curl openssl zip awk; do command -v "$dependency" >/dev/null || die "$dependency is required"; done
docker compose version >/dev/null
docker info >/dev/null

# Select the destination before reading or generating any secrets.
ask DEPLOY_DIR 'Куда установить сервер' '/root/claude-browser'
[[ "$DEPLOY_DIR" = /* ]] || die 'Deployment directory must be an absolute path.'
# Cron commands are shell syntax; restrict paths to safe literal pathname characters.
[[ "$DEPLOY_DIR" =~ ^/[a-zA-Z0-9_./-]+$ ]] || die 'Deployment path may contain only ASCII letters, digits, /, ., _, -.'
[ ! -L "$DEPLOY_DIR/.env" ] || die 'Refusing a symlinked .env.'
ENV_FILE="$DEPLOY_DIR/.env"
COOKIES_KEY=$(env_get "$ENV_FILE" COOKIES_KEY)
if [ -z "$COOKIES_KEY" ] && [ -d "$DEPLOY_DIR/gateway/cookies" ]; then
  COOKIE_SCAN_STATUS=0
  # Consume the full scan: an early-closing grep -q can hide matches via SIGPIPE.
  COOKIE_SCAN=$(grep -r -lE --include='*.json' '"enc"[[:space:]]*:[[:space:]]*1([,}[:space:]]|$)' "$DEPLOY_DIR/gateway/cookies" 2>/dev/null) || COOKIE_SCAN_STATUS=$?
  [ "$COOKIE_SCAN_STATUS" -le 1 ] || die 'Cannot inspect existing cookie jars; no files were changed.'
  [ -z "$COOKIE_SCAN" ] || die 'Encrypted cookie jars exist but COOKIES_KEY is missing. Restore the original key; no files were changed.'
fi
if [ -n "$COOKIES_KEY" ]; then
  if [[ ! "$COOKIES_KEY" =~ ^[a-fA-F0-9]{64}$ ]]; then
    [[ "$COOKIES_KEY" =~ ^[A-Za-z0-9+/_-]{43}=?$ ]] || die 'Existing COOKIES_KEY is invalid; restore the original 32-byte key.'
    KEY_FOR_DECODE=$(printf '%s' "$COOKIES_KEY" | tr '_-' '/+')
    [ "${#KEY_FOR_DECODE}" = 44 ] || KEY_FOR_DECODE="$KEY_FOR_DECODE="
    [ "$(printf '%s' "$KEY_FOR_DECODE" | openssl base64 -d -A | wc -c | tr -d ' ')" = 32 ] || die 'Existing COOKIES_KEY is invalid; restore the original 32-byte key.'
    unset KEY_FOR_DECODE
  fi
fi
ask DOMAIN 'Публичный домен шлюза' "$(env_get "$ENV_FILE" PUBLIC_HOST)"
valid_domain "$DOMAIN" || die 'Invalid gateway domain.'
ask CONNECT_IP 'Публичный IPv4 сервера для HTTPS CONNECT' "$(env_get "$ENV_FILE" CONNECT_HOST)"
valid_public_ipv4 "$CONNECT_IP" || die 'CONNECT_HOST must be a public IPv4 address.'
FRONTDOOR_ADDRESS=$(env_get "$ENV_FILE" FRONTDOOR_IP)
FRONTDOOR_ADDRESS=${FRONTDOOR_ADDRESS:-172.30.240.2}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/claude-install.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
caddy_users "$DEPLOY_DIR/Caddyfile" > "$TMP/users"
if [ -f "$DEPLOY_DIR/Caddyfile" ] && [ ! -s "$TMP/users" ]; then
  die 'Existing Caddyfile has no recognizable bcrypt users; refusing to discard its authentication.'
fi
if [ -s "$TMP/users" ]; then
  while read -r existing_user existing_hash; do valid_user "$existing_user" || die 'Existing Caddyfile contains an invalid username.'; done < "$TMP/users"
  ADMIN_USER=$(awk 'NR==1 {print $1}' "$TMP/users")
  ok 'Существующие пользователи и хэши паролей сохранены'
else
  ask ADMIN_USER 'Имя первого пользователя' owner
  valid_user "$ADMIN_USER" || die 'Invalid username (1–64 ASCII letters, digits, dot, dash, underscore; excluding . and ..).'
  while :; do
    ask_secret ADMIN_PASS "Пароль для $ADMIN_USER (минимум 12 символов)"
    [ "${#ADMIN_PASS}" -ge 12 ] || { echo 'Пароль слишком короткий.'; continue; }
    ask_secret ADMIN_PASS2 'Повторите пароль'
    [ "$ADMIN_PASS" = "$ADMIN_PASS2" ] && break
    echo 'Пароли не совпадают.'
  done
  HASH=$(hash_password "$ADMIN_PASS")
  printf '%s %s\n' "$ADMIN_USER" "$HASH" > "$TMP/users"
  unset ADMIN_PASS ADMIN_PASS2
fi
TG_TOKEN=''; TG_CHAT=''
if ! env_has "$ENV_FILE" TELEGRAM_BOT_TOKEN; then
  ask_secret TG_TOKEN 'TELEGRAM_BOT_TOKEN (необязательно; Enter — пропустить)'
  [[ "$TG_TOKEN" =~ ^[a-zA-Z0-9:_-]*$ ]] || die 'Invalid Telegram token.'
  if [ -n "$TG_TOKEN" ]; then
    ask TG_CHAT TELEGRAM_CHAT_ID
    [[ "$TG_CHAT" =~ ^-?[0-9]+$ ]] || die 'Invalid Telegram chat ID.'
  fi
fi
render_caddy "$DOMAIN" "$TMP/users" server/Caddyfile.template "$TMP/Caddyfile"
validate_caddy "$TMP/Caddyfile" "$CONNECT_IP" "$FRONTDOOR_ADDRESS"
# Preserve all existing settings as inert dotenv text, replacing only addresses.
umask 077
if [ -f "$ENV_FILE" ]; then
  awk '{line=$0;sub(/^[ \t]*(export[ \t]+)?/,"",line);if(line ~ /^(PUBLIC_HOST|CONNECT_HOST)[ \t]*=/) next; print}' "$ENV_FILE" > "$TMP/.env"
else : > "$TMP/.env"; fi
printf 'PUBLIC_HOST=%s\nCONNECT_HOST=%s\n' "$DOMAIN" "$CONNECT_IP" >> "$TMP/.env"
# Cookie jars are sealed with keys derived from each user's gateway password;
# no shared COOKIES_KEY is generated. An existing one is kept for old jars.
env_has "$ENV_FILE" ADMIN_USERS || printf 'ADMIN_USERS=%s\n' "$ADMIN_USER" >> "$TMP/.env"
env_has "$ENV_FILE" TELEGRAM_BOT_TOKEN || printf 'TELEGRAM_BOT_TOKEN=%s\n' "$TG_TOKEN" >> "$TMP/.env"
env_has "$ENV_FILE" TELEGRAM_CHAT_ID || printf 'TELEGRAM_CHAT_ID=%s\n' "$TG_CHAT" >> "$TMP/.env"

sh ./extension/build.sh
mkdir -p "$DEPLOY_DIR/gateway/src" "$DEPLOY_DIR/gateway/cookies" "$DEPLOY_DIR/extension" "$DEPLOY_DIR/backups"
chmod 700 "$DEPLOY_DIR/gateway/cookies" "$DEPLOY_DIR/backups"
cp server/compose.yaml server/port443-mux.py server/privacy.html "$DEPLOY_DIR/"
cp gateway/gateway.js "$DEPLOY_DIR/gateway/src/gateway.js"
cp server/add-user.sh server/remove-user.sh server/admin.sh server/install-lib.sh server/backup.sh server/restore.sh "$DEPLOY_DIR/"
chmod +x "$DEPLOY_DIR"/*.sh
cp extension/dist/claude-gateway-chrome.zip extension/dist/claude-gateway-firefox.zip "$DEPLOY_DIR/extension/"
cp "$TMP/.env" "$DEPLOY_DIR/.env"
cp "$TMP/Caddyfile" "$DEPLOY_DIR/Caddyfile"
chmod 600 "$DEPLOY_DIR/.env" "$DEPLOY_DIR/Caddyfile"
while read -r existing_user existing_hash; do
  cookie_file="$DEPLOY_DIR/gateway/cookies/$existing_user.json"
  [ -f "$cookie_file" ] || printf '%s\n' '{"cookies":[]}' > "$cookie_file"
  chmod 600 "$cookie_file"
done < "$TMP/users"
ok "Файлы установлены: $DEPLOY_DIR"

BACKUP_KEY_FILE=${BACKUP_KEY_FILE:-/root/.claude-gateway-backup.key}
[[ "$BACKUP_KEY_FILE" =~ ^/[a-zA-Z0-9_./-]+$ ]] || die 'Backup key path must be an absolute path without shell metacharacters.'
if [ ! -f "$BACKUP_KEY_FILE" ]; then openssl rand -hex 32 > "$BACKUP_KEY_FILE"; fi
chmod 600 "$BACKUP_KEY_FILE"
ok "Ключ бэкапа: $BACKUP_KEY_FILE — сохраните отдельную копию в надёжном месте"
CRON_DIR=${CRON_DIR:-/etc/cron.d}
if [ -d "$CRON_DIR" ] && [ "$(id -u)" = 0 ]; then
  printf '17 3 * * * root cd %s && BACKUP_KEY_FILE=%s ./backup.sh >> backups/backup.log 2>&1\n' "$DEPLOY_DIR" "$BACKUP_KEY_FILE" > "$CRON_DIR/claude-gateway-backup"
  chmod 644 "$CRON_DIR/claude-gateway-backup"
  ok 'Ежедневный зашифрованный бэкап настроен (03:17)'
  if [ -n "$COOKIES_KEY" ]; then
    # Old installs: drop COOKIES_KEY (and backups holding it) once no Claude
    # session depends on it; the job then removes itself.
    printf '23 4 * * * root cd %s && BACKUP_KEY_FILE=%s ./admin.sh retire-legacy-key >> backups/retire-key.log 2>&1 && rm -f %s/claude-gateway-retire-key\n' "$DEPLOY_DIR" "$BACKUP_KEY_FILE" "$CRON_DIR" > "$CRON_DIR/claude-gateway-retire-key"
    chmod 644 "$CRON_DIR/claude-gateway-retire-key"
    ok 'Старый общий ключ COOKIES_KEY будет удалён автоматически, когда все сессии перейдут на ключи от паролей'
  fi
else echo 'cron не настроен: добавьте ежедневный запуск backup.sh вручную.'; fi

echo "DNS: домен $DOMAIN должен указывать на сервер; порт 80 должен быть доступен для выдачи IP-сертификата $CONNECT_IP."
confirm 'Запустить контейнеры?' || { echo 'Файлы готовы; запуск: docker compose up -d из каталога установки.'; exit 0; }
cd "$DEPLOY_DIR"
docker compose pull
docker compose up -d
# gateway.js, port443-mux.py and the Caddyfile are bind-mounted: running
# processes keep the previous version until they restart. Caddy reloads
# gracefully when its admin socket is up and restarts otherwise.
docker compose restart gateway frontdoor
reload_caddy
docker compose ps
CODE_NOAUTH=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "https://$DOMAIN/__health" || true)
echo "/__health без пароля: $CODE_NOAUTH (ожидаем 401; первая выдача сертификата может занять время)."
printf 'Готово: https://%s/\nРасширения: https://%s/__ext/\nУправление пользователями: ./add-user.sh / ./remove-user.sh в %s\nПанель на своём компьютере: dashboard/start.command или node dashboard/dashboard.js root@<сервер> (docs/DASHBOARD.md)\n' "$DOMAIN" "$DOMAIN" "$DEPLOY_DIR"
