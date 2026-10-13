# Публикация расширений в Chrome Web Store и Firefox AMO

Пользователи жалуются на безопасность: расширение unsigned, Chrome ругается «Отключите режим разработчика», Firefox — «не проверено». Решение — опубликовать в официальных магазинах. После этого:

- **Chrome/Edge**: ставится в один клик из Chrome Web Store, без режима разработчика.
- **Firefox ≥ 128**: ставится из AMO, без `about:debugging` и перезагрузки.

Публикация требует аккаунтов разработчика, которые **вы** создаёте сами. Я не могу зарегистрировать их за вас. Но всё остальное — подготовка пакетов, скрипты и инструкции — готово.

---

## Шаг 1. Аккаунты разработчика

### Chrome Web Store

1. Откройте https://chrome.google.com/webstore/devconsole/ (войдите в Google-аккаунт).
2. Заплатите $5 единоразово (Google Wallet).
3. **Account → Developer → Add new item → Extension**, заполните:
   - **Name**: `Claude Gateway`
   - **Upload a zip**: соберите `releases/claude-gateway-chrome-v1.7.0.zip` (см. ниже, как собрать)
   - **Visibility**: Unlisted (только по прямой ссылке)
4. Сохраните **Item ID** (начинается с `chrome-extension://...`).

### Firefox AMO

1. Откройте https://addons.mozilla.org/developers/ (войдите в Firefox-аккаунт).
2. **Submit a New Add-on → Continue**.
3. Заполните метаданные (имя, описание, категория Tools).
4. **Upload a package**: соберите `releases/claude-gateway-firefox-v1.7.0.zip`.
5. **Visibility**: Unlisted (только по прямой ссылке).
6. Сохраните **Add-on ID** и **UUID**.

---

## Шаг 2. Сборка пакетов для публикации

Пакеты в `releases/` — с плейсхолдером `__GATEWAY_HOST__`, их нельзя публиковать как есть. Нужно собрать под ваш домен **до** публикации:

```sh
git clone <этот-репозиторий> && cd claude_for_browes
./configure.sh claude.example.com    # собирает extension/dist/{chrome,firefox} + releases/*.zip
```

Если вы уже запускали `configure.sh`, плейсхолдеры заменены. Чтобы пересобрать пакеты с плейсхолдерами, сбросьте изменения:
```sh
git checkout -- extension/manifest.chrome.json extension/manifest.firefox.json \
              extension/rules.json extension/background.js
./extension/release.sh
```

Проверка: в `releases/*.zip` не должно остаться `__GATEWAY_HOST__`:
```sh
grep -l "__GATEWAY" releases/*.zip && echo "FAIL: плейсхолдер в пакете" || echo "OK: пакет готов к публикации"
```

---

## Шаг 3. Подпись Firefox (без AMO-кредов — не получится)

`web-ext sign` требует `--api-key` и `--api-secret` от AMO. Без них:
```sh
npx web-ext sign --source-dir extension/dist/firefox \
  --api-key <ВАШ_API_KEY> --api-secret <ВАШ_API_SECRET> --channel unlisted
```

Получите креды на https://addons.mozilla.org/developers/ → API Key. После подписи:
- Скачается подписаный `.xpi`.
- Пользователи ставят его по прямой ссылке (unlisted), без `about:debugging`.

**Если не хотите создавать аккаунт AMO**, есть обходной путь:
- Firefox Developer/Nightly: `about:config` → `xpinstall.signatures.required = false`, ставьте `.xpi` напрямую.
- Это работает только на Developer/Nightly, не на обычном Firefox.

---

## Шаг 4. Подпись Chrome (без аккаунта Google — не получится)

Chrome Web Store требует аккаунт Google-разработчика ($5). Без него:
- Загрузите `releases/claude-gateway-chrome-v1.7.0.zip` в DevConsole (Шаг 1).
- После проверки (1–3 дня) расширение появится в Web Store.
- Пользователи ставят по прямой ссылке (unlisted).

**Если не хотите платить $5**, есть обходной путь:**
- Enterprise-политика: `ExtensionInstallForcelist` в GPO/MDM, расширение ставится из `.crx` по прямой ссылке.
- Это работает только для управляемых устройств (Enterprise).

---

## Шаг 5. Обновление версий

Когда меняете расширение, поднимите версию в `manifest.chrome.json` и `manifest.firefox.json`, пересоберите пакеты (`./extension/release.sh`), загрузите новые версии в Web Store и AMO. Пользователи получат обновление автоматически.

---

## Чек-лист

- [ ] Аккаунт Google-разработчика ($5)
- [ ] Аккаунт AMO
- [ ] `./configure.sh <домен>` — пакеты собраны
- [ ] `grep "__GATEWAY" releases/*.zip` — плейсхолдеров нет
- [ ] Chrome: загружен в Web Store (unlisted)
- [ ] Firefox: загружен в AMO (unlisted)
- [ ] Ссылки установки добавлены в README

## Безопасность

Публикация снимает главную жалобу: расширение unsigned → «отключите режим разработчика» / «не проверено». После публикации:
- Chrome: ставится из Web Store, без режима разработчика, с цифровой подписью Google.
- Firefox: ставится из AMO, с подписю Mozilla.
- Код в магазине = код в репозитории (пользователи могут сверить).
- Обновления приходят автоматически, больше ручной установки.
