const $h = document.getElementById("host");
const $u = document.getElementById("user");
const $p = document.getElementById("pass");
const $s = document.getElementById("status");
const $perm = document.getElementById("perm-status");
let statusTimer;
const FIREFOX_BUILD = (() => {
  try { return !!chrome.runtime.getManifest()?.browser_specific_settings?.gecko; }
  catch (_) { return false; }
})();
const EXTENSION_API = FIREFOX_BUILD && typeof browser !== "undefined" ? browser : chrome;

function callApi(target, method, ...args) {
  if (FIREFOX_BUILD) return Promise.resolve(target[method](...args));
  return new Promise((resolve, reject) => {
    try {
      target[method](...args, result => {
        const error = chrome.runtime.lastError;
        if (error) reject(new Error(error.message || "Browser API call failed"));
        else resolve(result);
      });
    } catch (error) { reject(error); }
  });
}
const sendMessage = message => callApi(EXTENSION_API.runtime, "sendMessage", message);

function routeReasonText(reason, platform) {
  switch (reason) {
    case "firefox_android_unsupported":
      return "Поддерживается Firefox Desktop; Firefox для Android не поддерживается. Защищённый маршрут остаётся заблокирован.";
    case "firefox_proxy_api_unavailable":
      return "В этой сборке Firefox нет необходимых настроек прокси. Используйте актуальный Firefox Desktop; защищённый маршрут остаётся заблокирован.";
    case "auth_failed":
      return "Шлюз отклонил вход. Проверьте имя пользователя и пароль в настройках расширения.";
    case "proxy_baseline_unavailable":
      return "Не удалось подготовить защищённый маршрут Claude. Повторите подключение; запросы Claude остаются заблокированными.";
    case "secure_proxy_unavailable":
      return "Не удалось подтвердить защищённое соединение с шлюзом. Проверьте доступность шлюза и сертификат TLS; маршрут остаётся закрытым.";
    default:
      return platform === "firefox"
        ? "Защищённый маршрут Firefox не готов. Запросы Claude остаются заблокированными; другие сайты работают как обычно."
        : "Защищённый маршрут ещё не готов. Внешние запросы заблокированы до подключения.";
  }
}

function isRouteReady(health, state) {
  return health?.ok === true && state?.proxyReady === true && state?.fingerprint === true;
}
function shouldRetryHealth(reason) {
  return !reason || reason === "secure_proxy_unavailable" || reason === "auth_failed" || /^http_[45]\d{2}$/.test(reason);
}

// Firefox restricts only Claude traffic; Chromium restricts the whole profile.
for (const hint of document.querySelectorAll("[data-browser]")) hint.hidden = hint.dataset.browser !== (FIREFOX_BUILD ? "firefox" : "chromium");

function show(text, cls) {
  clearTimeout(statusTimer);
  $s.textContent = text;
  $s.className = cls || "";
  $s.style.display = "inline";
  statusTimer = setTimeout(() => { $s.style.display = "none"; }, 6000);
}
function refreshPerm() {
  sendMessage({ type: "status" }).then(st => {
    if (!st) { $perm.textContent = "Не удалось проверить защиту. Повторите проверку."; return; }
    if (!st.host) { $perm.textContent = "Введите домен шлюза."; return; }
    if (!st.granted) { $perm.textContent = "Разрешите доступ к шлюзу и адресам Claude кнопкой ниже."; return; }
    if (st.proxyReason && !shouldRetryHealth(st.proxyReason)) { $perm.textContent = routeReasonText(st.proxyReason, st.proxyPlatform); return; }
    if (st.proxyWarming) {
      $perm.textContent = "Проверяется HTTPS CONNECT и proxy-аутентификация; artifact-запросы остаются заблокированы.";
      return;
    }
    return sendMessage({ type: "health" }).then(health => {
      if (!health) { $perm.textContent = "Не удалось проверить защищённый маршрут. Повторите проверку."; return; }
      return sendMessage({ type: "status" }).then(latest => {
        if (!latest) { $perm.textContent = "Не удалось проверить защиту. Повторите проверку."; return; }
        if (latest.proxyReason || health.reason) {
          $perm.textContent = routeReasonText(latest.proxyReason || health.reason, latest.proxyPlatform || st.proxyPlatform);
          return;
        }
        const platform = latest.proxyPlatform || st.proxyPlatform;
        $perm.textContent = isRouteReady(health, latest)
          ? (platform === "firefox" ? "Защищённый маршрут активен. Остальные сайты Firefox работают как обычно." : "Защищённый маршрут активен. Другие внешние сайты заблокированы во всём профиле.")
          : routeReasonText("", platform);
      });
    });
  }).catch(() => { $perm.textContent = "Не удалось проверить защиту. Повторите проверку."; });
}

// Call permissions.request before the first await so the browser still has the
// click's user gesture. The manifest's wildcard permits custom gateway domains;
// the actual request is restricted to this gateway and the approved host list.
async function saveAndGrant() {
  const host = $h.value.trim().toLowerCase();
  if (!GatewayPrivacy.validGatewayHost(host)) { show("Введите домен шлюза без https:// и пути", "err"); return; }
  let granted;
  try {
    granted = await callApi(EXTENSION_API.permissions, "request", { origins: GatewayPrivacy.requiredOrigins(host) });
  } catch (_) { show("Браузер не разрешил доступ. Повторите нажатие кнопки.", "err"); return; }
  if (!granted) { show("Доступ не разрешён. Настройки не изменены.", "warn"); return; }
  await callApi(EXTENSION_API.storage.local, "set", { gatewayHost: host, authUser: $u.value.trim(), authPass: $p.value });
  const result = await sendMessage({ type: "apply" });
  if (!result?.ok) {
    const state = await sendMessage({ type: "status" });
    show(routeReasonText(result?.reason || state?.proxyReason, state?.proxyPlatform), "warn");
  }
  else {
    show("Настройки сохранены. Проверяем защищённый маршрут…");
    const health = await sendMessage({ type: "health" });
    const state = await sendMessage({ type: "status" });
    const ready = isRouteReady(health, state);
    const reason = health?.reason || state?.proxyReason;
    show(ready ? "Защищённый маршрут активен ✔" : routeReasonText(reason, state?.proxyPlatform), ready ? "" : "warn");
  }
  refreshPerm();
}
callApi(EXTENSION_API.storage.local, "get", ["gatewayHost", "authUser", "authPass"]).then(r => {
  $h.value = r.gatewayHost || "";
  $u.value = r.authUser || "";
  $p.value = r.authPass || "";
}).catch(() => { show("Не удалось загрузить настройки.", "err"); });
for (const id of ["save", "grant"]) document.getElementById(id).addEventListener("click", () => {
  saveAndGrant().catch(() => { show("Не удалось применить настройки. Повторите попытку.", "err"); refreshPerm(); });
});
refreshPerm();
