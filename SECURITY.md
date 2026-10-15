# Безопасность и модель угроз

Этот документ описывает текущую архитектуру и известные ограничения. Он не является утверждением, что все функции проверены в настоящем Chrome и Firefox или что публичный сервер прошёл сквозную проверку.

## Потоки соединений

| Поток | Защита и данные |
|---|---|
| Claude и шлюз | Расширение перенаправляет поддерживаемые HTTPS-запросы Claude на настроенный домен шлюза. Basic credentials привязаны к точному HTTPS-origin шлюза. TLS завершается на Caddy; gateway добавляет серверные cookies Claude только к разрешённым upstream-запросам. |
| Артефакты и внешние зависимости | Для доменов артефактов `claudeusercontent.com`, `claudemcpcontent.com` и фиксированного списка CDN расширение запрашивает у шлюза отдельный короткоживущий proxy-токен. CONNECT идёт по HTTPS к публичному IP сервера; сертификат Let's Encrypt удостоверяет этот IP. После установления туннеля TLS к сайту назначения остаётся между браузером и этим сайтом. Токен не является паролем шлюза и хранится на сервере только как SHA-256 digest. |
| Caddy и публичные порты | Публичные TCP 443 принимает TLS-only front door; он направляет TLS для домена к Caddy, а CONNECT к gateway. Caddy обслуживает домен и HTTP-01 на TCP 80. Внутренние порты gateway 8088 и 8443 не публикуются наружу. |

Для обычного Claude-трафика Cloudflare, если он включён, видит клиентский IP и TLS-трафик до шлюза, поскольку TLS завершается на Cloudflare. При прямом подключении браузер видит IP сервера. CONNECT к артефактам идёт напрямую на IP сервера и не проходит через Cloudflare; оператор CONNECT-шлюза видит адрес назначения и время/объём соединения, но не содержимое внутреннего TLS-сеанса.

## Что защищает реализация

- Gateway принимает upstream-запросы только к фиксированным Claude/Anthropic hostnames; CONNECT отдельно ограничен двумя семействами artifact-доменов и явным списком CDN. Неизвестные запросы расширения, инициированные шлюзом или артефактом, блокируются. Это не универсальный HTTP/SOCKS proxy.
- Перед открытием публичных artifact routes Chromium делает фиксированный HTTPS `HEAD` к `cdn.jsdelivr.net` через verified-TLS CONNECT: без тела, с запретом redirect и таймаутом 8 секунд. Для новой сессии нужны ответ 2xx и фактический proxy-auth callback с новым токеном. Временное правило разрешает только этот запрос расширения; request `Authorization`/`Cookie` и response `Set-Cookie` удаляются. Ошибка проверки оставляет artifact routes закрытыми.
- CONNECT требует TLS и отдельную сессию с коротким сроком действия (15 минут). Сессия выпускается защищённым endpoint после проверки шлюзового Basic login; ответ содержит отдельные proxy credentials. На сервере сохраняется хэш токена. При обновлении клиент передаёт exact previous bearer token в защищённом запросе к тому же gateway authority. После успешной выдачи нового токена gateway отзывает именно предъявленный прежний токен и его туннели, даже если клиент сменил аккаунт; сама ротация не является массовым отзывом, отдельно действуют лимит числа сессий, истечение срока и удаление пользователя. Ошибка выдачи нового токена не отзывает действующий. Если выдача прошла, но проверка маршрута не завершилась, новый кандидат сохраняется для retry, а маршрутизация остаётся закрытой; прежний токен уже отозван. Секретный заголовок не пересылается upstream. Удаление пользователя с перезапуском gateway отзывает активные proxy-сессии и обрывает туннели.
- Gateway удаляет `Authorization` и клиентские IP-заголовки перед запросом к Claude, не передаёт `Set-Cookie` браузеру и редактирует query/fragment из обычных путей в логах. Настроенный default runtime logger Caddy удаляет целые поля `request.uri` и `request.headers`, включая query, Referer, UA и auth/cookie headers; на Caddy 2.11.7 проверка сохранила method/status и скрыла синтетические URI/header canaries. Диагностика `status`, `logger`, `msg` и TLS/ACME сохраняется; этот фильтр не очищает произвольные строки `msg` или журналы других компонентов. Чтобы применить изменение, пересоздайте Caddyfile и контейнер Caddy.
- Cookie-файлы шифруются AES-256-GCM, только если задан `COOKIES_KEY`. Без ключа поддерживается открытый режим хранения. Для развёртывания с чувствительными аккаунтами задайте 32-байтовый ключ в `.env` с правами `600`; защищайте его резервной копией вне сервера.
- Gateway может переписывать hostnames CSP для собственных upstream routes. Chromium-расширение использует `chrome.debugger` только в top-level вкладках с точным настроенным gateway origin и их iframe/OOPIF. Для подходящего inline artifact Document response (HTTPS, 200, подфрейм), который нужно изменить, расширение ограниченно читает body в памяти (до 8 MiB). Для такого response удаляется `X-Frame-Options`; gateway origin добавляется в существующую `frame-ancestors`, только если та уже разрешает `https://claude.ai` или `https://*.claude.ai`. Остальные CSP directives/policies сохраняются. Ошибка обработки или превышение лимита блокирует запрос, требующий изменения. Ответы с `Content-Disposition: attachment` проходят как штатные загрузки браузера без чтения/буферизации тела для этой совместимости; это не подтверждение успешной загрузки каждого типа файла. Это адресная совместимость CSP, а не её отключение. Выборочная проверка в браузере и её границы описаны ниже; это не подтверждение всех типов артефактов или публичного production-деплоя.
- В CONNECT allowlist входят `claudeusercontent.com`, `claudemcpcontent.com` и CDN `cdn.jsdelivr.net`, `cdnjs.cloudflare.com`, `unpkg.com`, `fonts.googleapis.com`, `fonts.gstatic.com`, `esm.sh`, `cdn.tailwindcss.com`, `code.jquery.com`, `cdn.plot.ly`. Запросы к иным внешним адресам могут быть заблокированы.
- Установщик и скрипты управления пользователями входят в область аудита отдельно: перед обновлением используйте резервную копию, сохраняйте `.env`, cookie-файлы и ключ бэкапа.

## Отпечаток и область расширения

Используйте отдельный профиль браузера только для шлюза. Пока защита активна, расширение ограничивает сетевой доступ всего профиля: неизвестные адреса блокируются и вне вкладок Claude, а WebRTC и network prediction privacy-настройки также действуют на весь профиль. Не используйте этот профиль для обычного веб-сёрфинга или другого браузерного трафика.

Расширение меняет часть браузерных API для страниц шлюза и артефактов: часовой пояс/локаль. WebRTC UDP ограничивается настройкой браузера. Оно не делает браузер анонимным и не нормализует экран, шрифты, GPU/canvas или TLS/HTTP2-отпечаток. Gateway по умолчанию передаёт Claude User-Agent браузера; `FIXED_UA` может его изменить и требует согласованной проверки client hints. Нельзя считать fingerprint активным, пока popup явно не подтверждает его регистрацию и не пройдена проверка раннего запуска скрипта в целевом браузере.

Поддержка браузеров зависит от сборки и её минимальной версии в manifest. Для Chromium-сборки 2.0.4 требуется Chrome 125+ из-за OOPIF debugger sessions; для Firefox package minimum — 140, но secure CONNECT и artifact preview там намеренно fail-closed/unsupported. Не считайте Firefox полноценным клиентом.

Для Chromium artifact маршруты открываются только после защищённой проверки gateway, настройки HTTPS CONNECT и фиксированного no-body HTTPS `HEAD` через CONNECT. На свежей сессии нужны 2xx и реальный proxy-auth callback с новым токеном; timeout/redirect/auth failure оставляет маршруты закрытыми. Перед открытием применяется только точное временное правило к этому запросу, которое удаляет origin Authorization/Cookie и response Set-Cookie. При потере proxy-контроля разрешающее правило закрывается. Claude/API WebSocket пути пока fail-closed, пока их cookie-сессионный rewrite не подтверждён. Проверки реального выхода с момента старта, смены конфигурации и отказа proxy остаются обязательными для релизной оценки.

## Известные ограничения

- Не все функции Claude используют только документированные хосты. Неизвестные CDN и некоторые WebSocket-пути могут быть заблокированы. Добавлять новый домен в allowlist можно только после проверки его назначения и маршрута.
- Google/Apple OAuth может завершиться `origin_mismatch`, потому что OAuth-провайдер сравнивает redirect origin с зарегистрированным адресом. Документированного исправления здесь нет; не обходите это добавлением произвольных перенаправлений или снижением проверки origin.
- При работе с artifact iframe Chromium показывает системную полосу о подключённой отладке. DevTools или другой debugger attachment могут помешать расширению; при attach failure, ручном detach или невозможности безопасно изменить конкретный response artifact остаётся недоступен. Закройте DevTools и откройте Claude заново, чтобы повторить attach.
- Изменение `frame-ancestors` ограничено документом артефакта, загруженным как подфрейм из точного gateway origin, и добавляет только этот origin. Другие CSP-директивы/политики должны оставаться нетронутыми; это не гарантирует, что каждый artifact page совместим.
- Удаление пользователя с перезапуском gateway отзывает proxy-сессии всех пользователей, поэтому активным пользователям придётся снова подключиться. После удаления они не должны продолжать работу со старым CONNECT токеном.
- Оператор сервера имеет доступ к cookie-файлам после расшифрования и к обычному HTTP-трафику между Caddy и gateway. Не используйте шлюз, оператору которого вы не доверяете. TLS внутри CONNECT защищает содержимое artifact/CDN-трафика от шлюза.
- Cloudflare видит обычный Claude-трафик при проксируемой DNS-записи. CONNECT к artifact/CDN-доменам идёт непосредственно к IP сервера, поэтому Cloudflare не скрывает этот адрес.
- Использование прокси может противоречить условиям Anthropic или ограничениям доступности сервиса.

## Статус проверок

Исторический аудит от 14 октября 2026 года относится к commit `8998ed0` и не доказывает свойства текущего кода. Его findings для сравнения:

| ID | Старое наблюдение | Текущая область проверки |
|---|---|---|
| F01–F03 | Basic credentials были привязаны шире нужного; Basic шёл до TLS и proxy challenge доверял любому challenger. | Код теперь отделяет HTTPS gateway Basic от отдельного TLS CONNECT-токена и проверяет endpoint/challenger. Нужна проверка реальных исходящих заголовков и challenge в целевом браузере. |
| F04–F05 | Fingerprint registration ошибки скрывались; CONNECT не был готов при старте/смене настроек. | Регистрация fingerprint и lifecycle теперь должны завершаться fail-closed; проверяйте запуск, рестарт, смену host и потерю proxy-контроля в browser E2E. |
| F06 | CONNECT-ошибки затрагивали общий IP-ban Caddy. | CONNECT теперь использует отдельный listener и краткоживущие user tokens. Проверяйте изоляцию отказов и лимитов на публичном маршруте. |
| F07 | Расширение удаляло всю CSP и XFO слишком широко. | Chromium debugger path ограничен точным gateway parent: для изменяемого ответа снимает XFO и добавляет gateway origin в `frame-ancestors` только если исходная политика уже разрешает Claude; остальные CSP политики сохраняются. См. выборочную browser coverage ниже; непроверенные типы не считаются поддержанными. |
| F08 | Ошибки могли включить cookie fragment или request headers в журналы. | Gateway использует `safeError`; default Caddy runtime logger удаляет `request.uri` и `request.headers`, но сохраняет диагностические поля. Canaries из повреждённого jar и HTTP-запроса должны оставаться в privacy regression suite. |
| F09 | Fingerprint test мог вернуть ложный успех; CI не запускал расширение. | Добавлены проверки расширения/браузера, но результат конкретного финального запуска см. в итоговой матрице проверок релиза. |
| F10–F13 | Свежая/повторная установка, cron, cookie key и container hardening имели проблемы. | Требуются чистая установка и повторный запуск installer с существующими данными; не считайте эти сценарии доказанными только по текущему compose-файлу. |
| F14 | Claude/API WSS не проходил те же правила маршрутизации. | Эти WebSocket пути сейчас fail-closed и не заявлены как поддерживаемые. |
| F15 | Gateway мог отдать одновременно `Transfer-Encoding` и `Content-Length`. | Эти заголовки исключаются из forwarded response headers; upstream-response regression test должен подтвердить поведение. |

### Проверка релизного кандидата 2.0.4

| Проверка | Результат и границы |
|---|---|
| CORS наблюдение на VPS | Сравнение того же artifact GET показало HTTP 200 и ожидаемое тело, но `Access-Control-Allow-Origin` присутствовал только при запросе с точным `Origin: https://claude.ai`. Это узкое наблюдение одного route/ответа, не общая CORS-проверка. |
| Финальные automated checks | 147 Node.js и 29 Python-тестов прошли без пропусков; Firefox 2.0.4 lint — 0 errors, 0 warnings, 0 notices. |
| CORS implementation/native gate | В точном gateway/frame scope CORS helper переписывает request `Origin` с gateway origin на `https://claude.ai`, затем меняет только один matching response `Access-Control-Allow-Origin` обратно на gateway origin. Wildcard, credential grant, CSP/other-header changes и response-body reads не добавлены. Helper-specific suite — 7 checks; integrated native gate — 18/18 PASS, независимый reviewer06 повтор также прошёл 18/18 на test `0431c2d`. Синтетический `fetch → Blob → native download` сохранил exact bytes, filename и hash; 9.4 MiB gzip-decoded fixture прошёл с exact SHA без body buffering этим CORS path. |
| Deployment smoke | На production развернуты проверенные 2.0.4 archive hashes; gateway owner health endpoint вернул успешный результат. Это smoke check, не полный public artifact E2E после CORS-изменения. |
| Post-CORS public owner E2E | После обновления профиля проверка владельца ещё выполняется. Результаты 2.0.3 ниже не подтверждают работу нового 2.0.4 artifact-CORS пути. |

### Результаты релиза 2.0.3 (исторический релиз)

| Проверка | Результат и границы |
|---|---|
| Unit/integration и static checks | 136 Node.js и 29 Python-тестов прошли без пропусков; набор gateway rewrite содержит 53 успешных теста. Firefox lint — 0 errors, 0 warnings, 0 notices. Фильтр Caddy runtime-логов проверен на Caddy 2.11.7. |
| Production runtime isolation | На Node.js 22 изолированный production-runtime набор прошёл 35/35. Эти проверки не означают, что все типы artifact preview проверены. |
| Ограниченный front-door load test | На `python:3.13-alpine` с memory 256 MiB, `pids_limit=320` и `nofile=1024`: при 256 занятых слотах 8 сверхлимитных попыток отклонены; после освобождения слотов приняты следующие 16. Пик RSS — 45.6 MiB, OOM не было. В production лимит соединений увеличен с 128 до 256 в 07:50 UTC; timeouts не менялись. Это синтетическая проверка конкретной конфигурации, не гарантия ёмкости для произвольной нагрузки. |
| Chromium native/browser gate | 12/12 PASS в изолированной синтетической fixture; независимый повтор exact-final test `032816` также прошёл 12/12. Проверены TLS proxy-auth lifecycle, cold image auth, CSP/OOPIF и fail-closed negative cases. |
| Синтетические вложения и следующий preview | В Chromium скачаны синтетические PDF и code attachment через authenticated TLS CONNECT; сохранённые байты, SHA-256, MIME и имя файла совпали с fixture. После скачивания исходная вкладка gateway оставалась открыта, а следующий CSP-зависимый inline preview отобразился в той же вкладке без перезагрузки. Отдельно проверен attachment PDF 9.4 MiB с точным совпадением байтов; inline preview остаётся ограничен 8 MiB. Это не проверка реального owner/public PDF или code artifact. |
| Front-door diagnostics | `FRONTDOOR_DIAGNOSTICS` по умолчанию выключен. При явном значении `1` front door пишет каждые 30 секунд только фиксированные счётчики категорий, активных соединений и пикового числа; адреса, hostname, токены и содержимое трафика не записываются этими счётчиками. Для последней production-выборки diagnostics был включён временно. |
| Публичная авторизация и PDF upload/read | На реальном домене с валидированным TLS в отдельном чистом Chromium-профиле прошли Basic-auth owner login и выдача native host permission через Options. Gateway health и shell вернули 200. Загруженный PDF был прочитан Claude; ответ с уникальным marker завершился после 7 streaming chunks. Это подтверждает этот owner flow, но не все виды сессий и артефактов. |
| Публичные HTML, CDN и PDF download | Интерактивный HTML artifact открылся под исходным artifact origin, кнопка сработала. Закреплённый `lodash@4.17.21` получил 200 через TLS CONNECT на proxy IP:443. Два реальных owner PDF download сохранили одни и те же точные 1,471 байт и SHA-256, ожидаемое имя; PDF содержит одну читаемую страницу по pypdf и успешно отрисовался Poppler. Повторная загрузка в новом профиле независимо подтверждена. |
| Ошибка декодирования скрипта | Один HTTP 200 script завершился ошибкой browser content decoding. Сохранённый Cloudflare gzip object имел зафиксированный UTF-8 hash, не совпавший с ожидаемым; browser не декодировал этот ответ, поэтому это не сравнение двух успешно распакованных bodies. Текущий Node 22/Caddy/front-door путь отдаёт identity body размером 57,981 байт с SHA, совпадающим с upstream; отдельный cache-busted URL также работает. `no-cache` не вытеснил объект исходного URL из Cloudflare cache. На 08:16 UTC пользователь подтвердил, что этот URL ещё не очищен вручную; до purge он может продолжать отдавать старую копию. Это объяснение относится только к этой decoder failure и не объясняет исторические 525. |
| Наблюдаемые сетевые ошибки | В измеренном интервале до изменения лимита 921 ответов: 920 статусов 200 и один 302; 525 не наблюдались. Front door сообщил пик 87/128 активных соединений и ноль ошибок фиксированных категорий. Историческая причина 525 не установлена; отсутствие 525 в этой выборке не доказывает, что проблема устранена глобально. |
| Непроверенные сценарии | Native HTML export, просмотр/скачивание code artifact и оставшиеся artifact types всё ещё проверяются. Этот ограниченный публичный прогон не означает полную поддержку всех artifact types или завершённый E2E для всех сценариев. |

Эти результаты подтверждают только перечисленные действия в одном public owner run; они не подтверждают поддержку всех артефактов или полное production E2E.

### Проверка релизного кандидата 2.0.2 (исторический запуск)

| Проверка | Результат и границы |
|---|---|
| Unit/integration и статический анализ | 120 Node.js и 20 Python-тестов прошли; Firefox lint — 0 errors, 0 warnings, 0 notices. Фильтр Caddy runtime-логов проверен на Caddy 2.11.7. |
| Chromium native/browser gate | 11/11 PASS: cold image auth с первым 407, точечный extension-only HEAD warm-up, ротация предъявленного токена и смена аккаунта, CSP/OOPIF и negative-collector checks. Это не полный product E2E. |
| Owner browser fixture, версия/архив 2.0.2 | PASS для интерактивных HTML и React previews, SVG с видимой геометрией, Mermaid с 3 видимыми узлами, Markdown и нового TXT marker в видимом ответе (21 streaming chunks). Это private SSH fixture, не положительная проверка публичного Basic-auth маршрута. Связка разрешённого CDN origin/PAC/proxy counter не доказывает, что каждый fulfilled document напрямую обращался к наблюдаемому IP. |
| Холодные artifact thumbnails | 4/5 вернули 200 через TLS CONNECT на public IP:443. Пятый React thumbnail вернул upstream 404 `text/plain` длиной 10 байт; тот же ответ совпал с прямой проверкой VPS с Chrome UA и без auth/Cloudflare challenge. Считайте его отсутствующим upstream thumbnail/ORB, а не пятым успешным thumbnail. |
| Публичная граница/TLS | Неавторизованные статусы проверены с Chrome UA на публичном endpoint. Положительный публичный Basic-auth E2E не выполнялся. Python UA через Cloudflare получил HTTP 403 с кодом ошибки Cloudflare 1010; это отдельное client/edge-ограничение и не свидетельство о Chrome-маршруте. |

На момент проверки 2.0.2 оставались непроверенными PDF download, code artifacts, Firefox runtime, clipboard/drop и conditional revalidation по trusted TLS. Последующий 2.0.3 public owner run проверил одну PDF upload/read/download цепочку; code artifacts, native HTML export, Firefox runtime, clipboard/drop и conditional revalidation по trusted TLS по-прежнему не проверялись.
Сообщить об уязвимости: создайте Issue в репозитории, не публикуя пароли, токены, cookies, логи с персональными данными или production-данные.

Лицензия: MIT (см. `LICENSE`).
