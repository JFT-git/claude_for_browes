# Публикация расширений в Chrome Web Store и Firefox AMO

**Где опубликовано сейчас:**

- Chrome Web Store: [Gateway Connector for Claude](https://chromewebstore.google.com/detail/gateway-connector-for-cla/gimbjmikcifpmiiohgpehkkcknkcccif), ID `gimbjmikcifpmiiohgpehkkcknkcccif`. Версия 2.0.9 прошла проверку в октябре 2026.
- Firefox: подписанный в AMO (unlisted) `.xpi` в [GitHub-релизах](https://github.com/JFT-git/claude_for_browes/releases/latest), автообновление через `updates.json`.

Пользователи жалуются на безопасность: расширение unsigned, Chrome ругается «Отключите режим разработчика», Firefox — «не проверено». Решение — опубликовать в официальных магазинах. После этого:

- **Chrome/Edge**: ставится в один клик из Chrome Web Store, без режима разработчика.
- **Firefox ≥ 128**: ставится из AMO, без `about:debugging` и перезагрузки.

Публикация требует аккаунтов разработчика, которые **вы** создаёте сами. Я не могу зарегистрировать их за вас. Но всё остальное — подготовка пакетов, графика и готовый текст для всех полей — готово.

---

## Шаг 1. Аккаунты разработчика

### Chrome Web Store

1. Откройте https://chrome.google.com/webstore/devconsole/ (войдите в Google-аккаунт).
2. Заплатите $5 единоразово (Google Wallet).
3. **Account → Developer → Add new item → Extension**, заполните поля (текст ниже).
4. **Upload a zip**: `releases/claude-gateway-chrome-v1.7.0.zip` (см. Шаг 2 — как собрать).
5. **Visibility**: Unlisted (только по прямой ссылке).
6. Сохраните **Item ID**: 32 латинские буквы, например `gimbjmikcifpmiiohgpehkkcknkcccif`.

### Firefox AMO

1. Откройте https://addons.mozilla.org/developers/ (войдите в Firefox-аккаунт).
2. **Submit a New Add-on → Continue**.
3. Заполните поля (текст ниже).
4. **Upload a package**: `releases/claude-gateway-firefox-v1.7.0.zip`.
5. **Visibility**: Unlisted (только по прямой ссылке).
6. Сохраните **Add-on ID** и **UUID**.

---

## Шаг 2. Сборка пакетов для публикации

Пакеты в `releases/` — универсальные, одна сборка на все домены. Пользователь вводит свой домен шлюза в настройках расширения, и расширение само запрашивает доступ и регистрирует правила. Собирайте под ваш домен **до** публикации:

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

Проверка: в `releases/*.zip` не должно остаться `__GATEWAY_HOST__` (плейсхолдер заменяется на домен):

```sh
grep -l "__GATEWAY" releases/*.zip && echo "FAIL: плейсхолдер в пакете" || echo "OK: пакет готов к публикации"
```

---

## Шаг 3. Текст для полей Chrome Web Store

### Сведения о продукте

| Поле | Значение |
|---|---|
| **Название** (все языки) | `Gateway Connector for Claude` |
| **Краткое описание** (≤132 симв.) | `Connect your browser to your team’s self-hosted gateway for Claude — fast, native, secure.` |
| **Описание** (≤16 000 симв.) | Claude Gateway connects your browser to a self-hosted gateway for the Claude web app. Built for teams and organizations that run their own secure gateway.  The extension routes Claude web traffic through your gateway and signs requests with your credentials, so the Claude interface loads fast and renders natively in your browser — full keyboard input, clipboard, and file drag-and-drop, with no remote-desktop streaming or input lag.  Features: • Connect to your own gateway — enter the host once in the options page; a single build works with any domain • Fast, native experience — the web app renders directly in your browser • Credentials stay on your server — the gateway keeps session state on the server side, nothing sensitive is stored in the browser • Team-ready — every member signs in with their own account • Privacy controls for the gateway page — consistent interface settings (UTC time zone, en-US language), geolocation and WebRTC restrictions • Open source — the gateway, extension, server configuration, and tests are published for full review  Setup: requires a running Claude Gateway server (see the project homepage for the installer). An active Claude subscription is required for each user.
| **Категория** | Productivity |
| **Язык** | English (United States) |
| **URL главной страницы** | `https://github.com/JFT-git/claude_for_browes` |
| **URL службы поддержки** | `https://github.com/JFT-git/claude_for_browes/issues` |

### Вкладка «Конфиденциальность» (Privacy practices) — готовые тексты

**Описание цели (Single purpose):**
```
Routes traffic to the Claude web app through the user's own self-hosted gateway server.
```

**declarativeNetRequest:**
```
Core functionality of the extension: it redirects requests to claude.ai and its asset domains to the gateway host that the user entered in the options page, and adds the user's basic-auth header to requests sent to that gateway. Without this permission the extension cannot route traffic through the user's gateway.
```

**scripting:**
```
The extension injects a small bundled script on the user's own gateway pages to apply consistent interface settings (UTC time zone, en-US language) and privacy restrictions (geolocation and WebRTC disabled). The script is packaged inside the extension; no code is downloaded at runtime.
```

**storage:**
```
Stores the user's gateway host and credentials locally (chrome.storage.local) so they do not have to be re-entered. The data stays on the user's device and is only sent to the user's own configured gateway server.
```

**proxy:**
```
Sends document-preview connections (claudeusercontent.com) through the gateway server the user configured. The page address stays the real preview host, which the preview requires, while the connection itself goes through the user's gateway. No other sites are proxied.
```

**webRequest:**
```
Used only to notice when the browser asks for credentials for that gateway proxy. The extension does not read page contents or modify requests with this permission.
```

**webRequestAuthProvider:**
```
Fills in the gateway username and password the user already saved, so the preview proxy does not show a second login prompt. Those credentials are sent only to the user's own gateway.
```

**privacy:**
```
Keeps the gateway route from being bypassed in the dedicated browser profile: sets WebRTC IP handling to "disable_non_proxied_udp" and turns off network prediction so the browser does not pre-connect to other addresses. The previous settings are restored when the extension is disabled or removed.
```

**alarms:**
```
Renews the short-lived gateway proxy session (about 15 minutes) shortly before it expires and closes the protected route when it expires. No data is collected.
```

**debugger:**
```
Used only on tabs of the user's own gateway and the Claude document-preview frames inside them. It adds the gateway origin to the preview response's Content-Security-Policy frame-ancestors and handles CORS for preview exports, so previews can be shown inside the gateway page. Responses are processed in memory only, are not stored and are never sent to the developer. Chrome shows its standard debugging banner while this is active.
```

**Использование удалённого кода:**
```
This extension does not use remotely hosted code. All JavaScript is bundled inside the extension package. The extension only redirects web requests to the user's own server; it never downloads or executes code from remote sources.
```

**Использование данных:** логин/пароль и домен шлюза хранятся локально в браузере; разработчику не передаются; уходят только на собственный сервер пользователя. Поставьте галочку сертификации.

**Передача данных:** отметьте только **«Данные для аутентификации»** (логин/пароль шлюза хранятся локально). Все три галочки подтверждения — отметить. **Удалённый код: «Нет»** (весь код в пакете).

**Политика конфиденциальности:** обязательна, т.к. отмечены данные для аутентификации. URL:
```
https://claude.jft-foruse.com/privacy
```

**Email издателя:** DevConsole → «Настройки» (Account settings) → добавьте email и подтвердите по ссылке из письма.

### Обоснование разрешений (Permission justification)

В Chrome Web Store отдельно спросят, зачем нужны разрешения. Вставьте:

| Разрешение | Обоснование |
|---|---|
| **Host access** | Fixed hosts: claude.ai and its asset/API hosts (redirected to the user's gateway), the Claude document-preview domains (claudeusercontent.com, claudemcpcontent.com), hcaptcha.com (the invisible check Claude requires for email sign-in) and the public libraries those previews load (jsDelivr, cdnjs, unpkg, Google Fonts, esm.sh, Tailwind CDN, jQuery CDN, Plotly CDN). The optional `https://*/*` is requested at runtime only for the single gateway domain the user enters in the options page. |
| **declarativeNetRequest** | Routes Claude web app requests to the user-configured gateway host and signs them with the user's credentials. |
| **scripting** | Applies consistent interface settings (UTC time zone, en-US language) and privacy controls on the gateway page. |
| **storage** | Saves the user's gateway host and credentials locally in the browser. |
| **proxy** | Sends document-preview connections through the user's own gateway. No other sites are proxied. |
| **webRequest** | Detects when the browser asks for the gateway proxy login. Does not read page contents. |
| **webRequestAuthProvider** | Submits the saved gateway username and password to the user's own gateway proxy. |
| **privacy** | Prevents WebRTC and network prediction from bypassing the gateway route; previous settings are restored on removal. |
| **alarms** | Renews the short-lived gateway proxy session before it expires. |
| **debugger** | Lets Claude document previews embed in the gateway page by adjusting only their frame-ancestors/CORS headers, on gateway tabs only. Nothing is stored or sent to the developer. |

### Графика

| Поле | Файл |
|---|---|
| **Значок** (128×128) | `extension/icon128.png` |
| **Скриншот** (1280×800 или 640×400) | `extension/store-assets/screenshot-1.jpg (1280×800) или screenshot-1-640.jpg (640×400)` |
| **Мал. промо** (440×280) | `extension/store-assets/promo-440x280.jpg` |
| **Больш. промо** (1400×560) | `extension/store-assets/promo-1400x560.jpg` |

### Дополнительные поля

| Поле | Значение |
|---|---|
| Официальный URL | — |
| URL главной страницы | `https://github.com/JFT-git/claude_for_browes` |
| URL службы поддержки | `https://github.com/JFT-git/claude_for_browes/issues` |
| Только для взрослых | Нет |

---

## Шаг 4. Текст для полей Firefox AMO

| Поле | Значение |
|---|---|
| **Name** | `Gateway Connector for Claude` |
| **Summary** (≤250 симв.) | `Connect your browser to your team’s self-hosted gateway for Claude — fast, native, secure.` |
| **Description** | Claude Gateway connects your browser to a self-hosted gateway for the Claude web app. Built for teams and organizations that run their own secure gateway.  The extension routes Claude web traffic through your gateway and signs requests with your credentials, so the Claude interface loads fast and renders natively in your browser — full keyboard input, clipboard, and file drag-and-drop, with no remote-desktop streaming or input lag.  Features: • Connect to your own gateway — enter the host once in the options page; a single build works with any domain • Fast, native experience — the web app renders directly in your browser • Credentials stay on your server — the gateway keeps session state on the server side, nothing sensitive is stored in the browser • Team-ready — every member signs in with their own account • Privacy controls for the gateway page — consistent interface settings (UTC time zone, en-US language), geolocation and WebRTC restrictions • Open source — the gateway, extension, server configuration, and tests are published for full review  Setup: requires a running Claude Gateway server (see the project homepage for the installer). An active Claude subscription is required for each user.
| **Categories** | Privacy & Security, Productivity |
| **Язык** | English (United States) |
| **Homepage URL** | `https://github.com/JFT-git/claude_for_browes` |
| **Support URL** | `https://github.com/JFT-git/claude_for_browes/issues` |

---

## Шаг 5. Подпись Firefox

`web-ext sign` требует `--api-key` и `--api-secret` от AMO. Без них:

```sh
npx web-ext sign --source-dir extension/dist/firefox \
  --api-key <ВАШ_API_KEY> --api-secret <ВАШ_API_SECRET> --channel unlisted
```

Получите креды на https://addons.mozilla.org/developers/ → API Key. После подписи:
- Скачается подписаный `.xpi`.
- Пользователи ставят его по прямой ссылке (unlisted), без `about:debugging`.

**Если не хотите создавать аккаунт AMO**, есть обходной путь:**
- Firefox Developer/Nightly: `about:config` → `xpinstall.signatures.required = false`, ставьте `.xpi` напрямую.
- Это работает только на Developer/Nightly, не на обычном Firefox.

---

## Публикация Chrome из CI

Первый черновик в Chrome Web Store создаётся руками (вкладки «Описание» и «Конфиденциальность» должны быть заполнены). Дальше каждую новую версию CI загружает сам и отправляет на проверку. На аккаунте Google должна быть включена двухэтапная проверка.

Один раз, в [Google Cloud Console](https://console.cloud.google.com/):

1. Создайте проект и включите **Chrome Web Store API** (поиск по этому имени → Enable).
2. **OAuth consent screen** → External → заполните название и email. Добавьте свой email в **Test users**. Чтобы токен не протухал через 7 дней, переведите экран в **In production** (если Google потребует верификацию приложения — оставьте Testing и обновляйте токен раз в неделю).
3. **Credentials → Create credentials → OAuth client ID** → тип **Web application**. В Authorized redirect URIs добавьте `https://developers.google.com/oauthplayground`. Сохраните **Client ID** и **Client secret**.
4. Откройте [OAuth Playground](https://developers.google.com/oauthplayground). Шестерёнка справа сверху → **Use your own OAuth credentials** → вставьте Client ID и secret. В поле scope впишите `https://www.googleapis.com/auth/chromewebstore` → **Authorize APIs** (войдите тем Google-аккаунтом, которым владеете магазином) → **Exchange authorization code for tokens**. Скопируйте **Refresh token**.
5. **Publisher ID** — в [DevConsole](https://chrome.google.com/webstore/devconsole/) → Account → Publisher settings.
6. **Extension ID** карточки «Gateway Connector for Claude» — `gimbjmikcifpmiiohgpehkkcknkcccif` (страница пакета, поле «Идентификатор»).

Секреты репозитория (Settings → Secrets and variables → Actions → New repository secret):

| Name | Что вставить |
|---|---|
| `CWS_CLIENT_ID` | Client ID |
| `CWS_CLIENT_SECRET` | Client secret |
| `CWS_REFRESH_TOKEN` | Refresh token |
| `CWS_PUBLISHER_ID` | Publisher ID |
| `CWS_EXTENSION_ID` | `gimbjmikcifpmiiohgpehkkcknkcccif` |

После этого пуш в `main` с **новой** версией в манифесте сам загружает zip и отправляет его на проверку. Повторная загрузка той же версии пропускается. Локально то же самое: `./extension/publish-chrome.sh` (предварительно `export` пяти переменных и `./extension/release.sh`).

---

## Автоподпись Firefox (без браузера)

Один раз получите API-ключи: https://addons.mozilla.org/developers/ → **API Keys** (JWT issuer + secret).

**Локально** — весь цикл одной командой (сборка → подпись на AMO → XPI в GitHub-релиз → `updates.json`):
```sh
export AMO_API_KEY=<issuer> AMO_API_SECRET=<secret>
./extension/sign-firefox.sh
```

**В CI** — добавьте те же ключи в GitHub: репозиторий → Settings → Secrets and variables → Actions →
`AMO_API_KEY`, `AMO_API_SECRET`. После этого каждый релиз подписывается и прикрепляется автоматически.

## Автообновления Firefox (`update_url`)

В манифесте Firefox прописан `update_url` → `updates.json` в корне репозитория (обязателен для
самостоятельного распространения). После подписи новой версии на AMO:

1. Скачайте подписанный `.xpi` из Developer Hub.
2. Переименуйте в `gateway-connector-firefox-<версия>.xpi` и прикрепите к GitHub-релизу этой версии.
3. Добавьте запись в `updates.json` (версия + ссылка на этот xpi) и запушьте.

Firefox у пользователей будет обновляться автоматически.

## Шаг 7. Обновление версий

Когда меняете расширение, поднимите версию в `manifest.chrome.json` и `manifest.firefox.json`, пересоберите пакеты (`./extension/release.sh`), загрузите новые версии в Web Store и AMO. Пользователи получат обновление автоматически.

---

## Чек-лист

- [x] Аккаунт Google-разработчика ($5)
- [x] Аккаунт AMO
- [ ] `./configure.sh <домен>` — пакеты собраны
- [ ] `grep "__GATEWAY" releases/*.zip` — плейсхолдеров нет
- [x] Chrome: поля заполнены, zip загружен в Web Store, проверка пройдена
- [ ] Firefox: поля заполнены, zip загружен в AMO (unlisted)
- [x] Firefox: `npx web-ext sign` — подписанный `.xpi` получен
- [x] Ссылки установки добавлены в README

## Безопасность

Публикация снимает главную жалобу: расширение unsigned → «отключите режим разработчика» / «не проверено». После публикации:
- Chrome: ставится из Web Store, без режима разработчика, с цифровой подписью Google.
- Firefox: ставится из AMO, с подписю Mozilla.
- Код в магазине = код в репозитории (пользователи могут сверить).
- Обновления приходят автоматически, больше ручной установки.
