#!/usr/bin/env bash
#
# install.sh — поэтапная установка сервера claude_for_browes.
#
# Запуск на сервере (Ubuntu/Debian, root или sudo):
#   git clone <repo> && cd claude_for_browes && bash install.sh
#
# Скрипт интерактивный: на каждом шаге объясняет, что делает, и спрашивает
# подтверждение. Можно прервать Ctrl+C и запустить заново — шаги идемпотентны.
#
set -euo pipefail

# ---------------------------------------------------------------- оформление --
if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; N=$'\033[0m'
else
  B=""; G=""; Y=""; R=""; C=""; N=""
fi
step() { echo; echo "${B}${C}═══ Шаг $1/$TOTAL · $2${N}"; }
ok()   { echo "${G}✔${N} $*"; }
warn() { echo "${Y}!${N} $*"; }
err()  { echo "${R}✖ $*${N}" >&2; }
die()  { err "$*"; exit 1; }
ask()  { # ask <var> <prompt> [default]
  local v="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then read -r -p "${B}$p${N} [$d]: " "$v" || true; eval "$v=\${$v:-$d}";
  else read -r -p "${B}$p${N}: " "$v" || true; fi
}
ask_secret() { local v="$1" p="$2"; read -r -s -p "${B}$p${N}: " "$v" || true; echo; }
confirm() { local a; read -r -p "${B}$1${N} [Y/n]: " a || true; case "${a:-Y}" in [Yy]*) return 0;; *) return 1;; esac; }

TOTAL=9
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

echo "${B}Установка claude_for_browes — сервер шлюза Claude${N}"
echo "Репозиторий: $REPO_DIR"

# ------------------------------------------------- Шаг 1: проверка окружения --
step 1 "Проверка окружения"
[ "$(id -u)" = "0" ] || warn "Не root. Команды docker должны работать без sudo, иначе будут ошибки."
command -v docker >/dev/null 2>&1 || die "docker не найден. Установите: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "docker compose plugin не найден."
command -v curl >/dev/null 2>&1 || die "curl не найден."
command -v openssl >/dev/null 2>&1 || die "openssl не найден (нужен для ключей и бэкапов)."
if ! command -v zip >/dev/null 2>&1; then
  warn "zip не найден — нужен для сборки расширения."
  if command -v apt-get >/dev/null 2>&1 && confirm "Установить zip через apt?"; then apt-get install -y zip >/dev/null; fi
  command -v zip >/dev/null 2>&1 || die "Установите zip и запустите install.sh снова."
fi
ok "docker $(docker --version | grep -oE '[0-9.]+' | head -1), compose, curl — на месте"
docker info >/dev/null 2>&1 || die "docker daemon не отвечает (нужны права root или группа docker)."
ok "docker daemon работает"

# ------------------------------------------------------- Шаг 2: домен шлюза --
step 2 "Домен шлюза"
echo "Это публичный адрес, по которому клиенты будут открывать Claude."
echo "DNS-запись должна указывать на IP этого сервера (A-запись)."
ask DOMAIN "Домен шлюза (например claude.example.com)" "${DOMAIN:-}"
[ -n "$DOMAIN" ] || die "Домен обязателен."
echo "$DOMAIN" | grep -qE '^[a-z0-9.-]+\.[a-z]{2,}$' || die "Некорректный домен: $DOMAIN"
ok "Домен: $DOMAIN"

# ------------------------------------------- Шаг 3: первый пользователь ------
step 3 "Первый пользователь (basic_auth)"
echo "Логин/пароль для доступа к шлюзу (это НЕ аккаунт Claude — а доступ к вашему шлюзу)."
echo "Пароль хранится только в виде bcrypt-хэша в Caddyfile. Минимум 12 символов."
ask ADMIN_USER "Имя пользователя" "owner"
echo "$ADMIN_USER" | grep -qE '^[a-zA-Z0-9._-]+$' || die "Имя: только буквы, цифры, точка, дефис, подчёркивание."
while :; do
  ask_secret ADMIN_PASS "Пароль для $ADMIN_USER"
  [ "${#ADMIN_PASS}" -ge 12 ] || { warn "Слишком короткий пароль (минимум 12 символов) — повторите."; continue; }
  ask_secret ADMIN_PASS2 "Повторите пароль"
  [ "$ADMIN_PASS" = "$ADMIN_PASS2" ] && break
  warn "Пароли не совпадают — повторите."
done
ok "Пользователь: $ADMIN_USER"

# ------------------------------------------- Шаг 4: генерация конфигов -------
step 4 "Генерация конфигов под домен"
echo "Заполняю шаблоны (extension, Caddyfile, compose) вашим доменом."
bash ./configure.sh "$DOMAIN"
[ -f server/Caddyfile ] || die "server/Caddyfile не создан."
HASH=$(docker run --rm caddy:2 caddy hash-password --plaintext "$ADMIN_PASS" 2>/dev/null | tail -1)
[ -n "$HASH" ] || die "Не удалось сгенерировать bcrypt-хэш."
# подставляем user+hash вместо плейсхолдеров
sed -i.bak "s/__BASIC_AUTH_USER__ __BASIC_AUTH_HASH__/$ADMIN_USER ${HASH//\//\\/}/" server/Caddyfile && rm server/Caddyfile.bak
grep -q "__BASIC_AUTH" server/Caddyfile && die "Плейсхолдеры basic_auth не заменены."
ok "Caddyfile настроен, хэш сгенерирован"
unset ADMIN_PASS ADMIN_PASS2

echo
echo "Секреты и уведомления (хранятся в .env на сервере, не в репозитории)."
COOKIES_KEY=$(openssl rand -hex 32)
ok "Сгенерирован ключ шифрования cookies на диске (AES-256-GCM)"
echo "Telegram-алерты (истёкшая сессия пользователя, блокировка IP) — необязательно."
echo "Создайте бота у @BotFather, узнайте chat id у @userinfobot. Пустой ввод — пропустить."
ask TG_TOKEN "TELEGRAM_BOT_TOKEN" ""
TG_CHAT=""
[ -z "$TG_TOKEN" ] || ask TG_CHAT "TELEGRAM_CHAT_ID" ""

# ------------------------------------------- Шаг 5: сборка каталога деплоя ---
step 5 "Сборка каталога деплоя"
ask DEPLOY_DIR "Куда установить сервер" "/root/claude-browser"
mkdir -p "$DEPLOY_DIR/gateway/src" "$DEPLOY_DIR/gateway/cookies"
cp server/compose.yaml "$DEPLOY_DIR/compose.yaml"
cp server/Caddyfile   "$DEPLOY_DIR/Caddyfile"
cp gateway/gateway.js "$DEPLOY_DIR/gateway/src/gateway.js"
cp server/add-user.sh server/remove-user.sh server/backup.sh server/restore.sh "$DEPLOY_DIR/"
chmod +x "$DEPLOY_DIR"/*.sh
mkdir -p "$DEPLOY_DIR/extension"
cp extension/dist/claude-gateway-chrome.zip extension/dist/claude-gateway-firefox.zip "$DEPLOY_DIR/extension/" \
  || die "Не найдены собранные расширения (extension/dist/*.zip)."
ok "Расширения (Chrome, Firefox) под $DOMAIN будут доступны пользователям на https://$DOMAIN/__ext/"
umask 077
{
  echo "PUBLIC_HOST=$DOMAIN"
  echo "COOKIES_KEY=$COOKIES_KEY"
  echo "ADMIN_USERS=$ADMIN_USER"
  echo "TELEGRAM_BOT_TOKEN=$TG_TOKEN"
  echo "TELEGRAM_CHAT_ID=$TG_CHAT"
} > "$DEPLOY_DIR/.env"
umask 022
chmod 600 "$DEPLOY_DIR/.env"
ok ".env записан (права 600)"
chmod 700 "$DEPLOY_DIR/gateway/cookies"
[ -f "$DEPLOY_DIR/gateway/cookies/$ADMIN_USER.json" ] || echo '{"cookies":[]}' > "$DEPLOY_DIR/gateway/cookies/$ADMIN_USER.json"
chmod 600 "$DEPLOY_DIR/gateway/cookies/$ADMIN_USER.json"
ok "Файлы в $DEPLOY_DIR"

# ------------------------------------------- Шаг 6: резервные копии ----------
step 6 "Резервные копии"
echo "Ежедневный зашифрованный бэкап: сессии пользователей, Caddyfile, .env (хранится 14 копий)."
BACKUP_KEY_FILE="${BACKUP_KEY_FILE:-/root/.claude-gateway-backup.key}"
if [ ! -f "$BACKUP_KEY_FILE" ]; then
  ( umask 077; openssl rand -hex 32 > "$BACKUP_KEY_FILE" )
  ok "Ключ бэкапа создан: $BACKUP_KEY_FILE"
fi
echo "${Y}ВАЖНО:${N} скопируйте ключ бэкапа в надёжное место ВНЕ сервера. Без него бэкапы не расшифровать:"
echo "  $(cat "$BACKUP_KEY_FILE")"
if [ -d /etc/cron.d ] && [ "$(id -u)" = "0" ]; then
  echo "17 3 * * * root cd $DEPLOY_DIR && ./backup.sh >> backups/backup.log 2>&1" > /etc/cron.d/claude-gateway-backup
  chmod 644 /etc/cron.d/claude-gateway-backup
  ok "cron: ежедневно в 03:17 (/etc/cron.d/claude-gateway-backup)"
else
  warn "cron не настроен автоматически — запускайте $DEPLOY_DIR/backup.sh вручную или добавьте в crontab."
fi
echo "Копия на другой сервер: добавьте BACKUP_REMOTE=user@host:/path в cron-строку (используется scp)."

# ------------------------------------------- Шаг 7: проверка DNS -------------
step 7 "Проверка DNS"
PUB_IP=$(curl -s4 --max-time 8 https://api.ipify.org || curl -s4 --max-time 8 https://ifconfig.me || echo "")
DNS_IP=$(getent hosts "$DOMAIN" | awk '{print $1}' | head -1 || true)
echo "  Публичный IP сервера: ${PUB_IP:-не удалось определить}"
echo "  $DOMAIN резолвится в: ${DNS_IP:-не резолвится}"
if [ -n "$PUB_IP" ] && [ -n "$DNS_IP" ] && [ "$PUB_IP" = "$DNS_IP" ]; then
  ok "DNS указывает на этот сервер"
elif [ -z "$DNS_IP" ]; then
  warn "Домен пока не резолвится. Создайте A-запись $DOMAIN -> $PUB_IP (и/или включите Cloudflare Proxied)."
else
  warn "DNS ($DNS_IP) != IP сервера ($PUB_IP). Если используете Cloudflare Proxied — это нормально (будет IP Cloudflare)."
fi
confirm "Продолжить установку?" || die "Прервано. Настройте DNS и запустите install.sh снова."

# ------------------------------------------- Шаг 8: запуск контейнеров -------
step 8 "Запуск контейнеров"
cd "$DEPLOY_DIR"
docker compose pull 2>/dev/null || true
docker compose up -d
ok "Контейнеры запущены"
docker compose ps

# ------------------------------------------- Шаг 9: проверка -----------------
step 9 "Проверка"
sleep 4
# без пароля ждём 401 (значит TLS + basic_auth на месте)
CODE_NOAUTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 12 "https://$DOMAIN/__health" || echo 000)
echo "  /__health без пароля -> $CODE_NOAUTH (ожидаем 401)"
if [ "$CODE_NOAUTH" = "401" ]; then
  ok "TLS + basic_auth работают"
else
  warn "Ожидался 401, получили $CODE_NOAUTH. Проверьте DNS/Cloudflare и 'docker compose logs caddy'."
fi
echo "  Проверить с паролем: curl -u $ADMIN_USER:'<пароль>' https://$DOMAIN/__health  (ожидаем {\"ok\":true,...})"

echo
echo "${B}${G}═══ Установка завершена ═══${N}"
cat <<EOF

${B}Что дальше${N}

1. ${B}DNS / Cloudflare${N}: убедитесь, что $DOMAIN указывает на сервер.
   Рекомендуется Cloudflare (Proxied, SSL/TLS Full) — скрывает origin и
   сглаживает обрывы соединения у некоторых провайдеров.

2. ${B}Первый вход в Claude${N}: откройте https://$DOMAIN/ , войдите в Claude
   по email (magic-link). Шлюз сам перехватит session-cookies в
   gateway/cookies/$ADMIN_USER.json

3. ${B}Расширение для клиентов${N}: уже собрано под ваш домен и лежит на
   https://$DOMAIN/__ext/   (за логином/паролем). Дайте клиенту эту ссылку,
   его логин и пароль — больше ничего собирать не нужно.

4. ${B}Пользователи${N} (cd $DEPLOY_DIR):
   ./add-user.sh <имя>            — создать (пароль сгенерируется и покажется один раз)
   ./add-user.sh <имя> <пароль>   — создать/сменить пароль
   ./remove-user.sh <имя>         — удалить
   Статус сессий (только для $ADMIN_USER): curl -u $ADMIN_USER https://$DOMAIN/__admin/status

5. ${B}Логи${N}:  cd $DEPLOY_DIR && docker compose logs -f gateway

Документация: README.md, docs/DEPLOY-SERVER.md, docs/SETUP-CLIENT.md, SECURITY.md
EOF
