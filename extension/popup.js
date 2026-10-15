const $dot = document.getElementById("dot");
const $text = document.getElementById("status-text");
const $host = document.getElementById("host");
const $fp = document.getElementById("fp");
const $debuggerNote = document.getElementById("debugger-note");
const $open = document.getElementById("open");
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

function routeFailureText(reason, platform) {
  switch (reason) {
    case "firefox_android_unsupported":
      return "Firefox для Android не поддерживается; используйте Firefox Desktop.";
    case "firefox_proxy_api_unavailable":
      return "В этой сборке Firefox нет необходимых настроек прокси; используйте актуальный Firefox Desktop.";
    case "auth_failed":
      return "Шлюз отклонил вход. Проверьте имя пользователя и пароль в настройках.";
    case "proxy_baseline_unavailable":
      return "Не удалось подготовить защищённый маршрут Claude. Повторите проверку.";
    case "secure_proxy_unavailable":
      return "Не удалось подтвердить защищённое соединение с шлюзом.";
    default:
      return platform === "firefox" ? "Защищённый маршрут Firefox не готов; запросы Claude остаются заблокированными." : "Защищённый маршрут недоступен.";
  }
}

function showDebuggerStatus(status, platform) {
  if (platform === "firefox") {
    if (!status || status.available === false || status.lastError === "unsupported") {
      $debuggerNote.textContent = "Native-обработка артефактов Firefox недоступна; запросы остаются заблокированными.";
    } else if (status.lastError || status.blockedTabs > 0 || status.active !== true) {
      $debuggerNote.textContent = "Native-обработка артефактов Firefox не готова или остановлена; небезопасный обход не включается.";
    } else {
      $debuggerNote.textContent = "Firefox использует native header handling; debugger и баннер отладки не требуются.";
    }
    return;
  }
  if (!status || status.available === false || status.lastError === "unsupported") {
    $debuggerNote.textContent = "В этой сборке совместимость artifact preview недоступна; запросы остаются заблокированными.";
    return;
  }
  const conflict = ["attach_failed", "setup_failed", "detached", "response_failed", "attach_unavailable"].includes(status.lastError);
  if (conflict || status.blockedTabs > 0) {
    $debuggerNote.textContent = "Обработка артефактов недоступна (возможно, открыт DevTools). Закройте DevTools и перезагрузите Claude; небезопасный обход не включается.";
    return;
  }
  $debuggerNote.textContent = status.attachedTabs > 0
    ? "Баннер Chrome «отладка» ожидаем. DevTools может остановить обработку артефактов."
    : "Chrome показывает баннер отладки при подключённой вкладке шлюза. Для Firefox debugger не используется.";
}

function setState(cls, text) { $dot.className = "dot " + cls; $text.textContent = text; }
function blocked(text) {
  $open.disabled = true;
  setState("bad", text);
  $fp.textContent = FIREFOX_BUILD ? "Запросы Claude заблокированы до подключения; другие сайты работают." : "Внешние запросы заблокированы до подключения.";
}
function ready(health, state) {
  return health?.ok === true && state?.proxyReady === true && state?.fingerprint === true;
}
function shouldRetryHealth(reason) {
  return !reason || reason === "secure_proxy_unavailable" || reason === "auth_failed" || /^http_[45]\d{2}$/.test(reason);
}
async function refresh() {
  $open.disabled = true;
  let st;
  try { st = await sendMessage({ type: "status" }); }
  catch (_) { blocked("Не удалось проверить защиту"); return; }
  if (!st) { blocked("Не удалось проверить защиту"); return; }
  $host.textContent = st.host || "Шлюз не настроен";
  showDebuggerStatus(st.artifactDebugger, st.proxyPlatform);
  $fp.textContent = FIREFOX_BUILD ? "Через шлюз идут только Claude и его артефакты." : "Отдельный профиль для Claude · другие сайты блокируются.";
  if (!st.host) { setState("warn", "Укажите шлюз в настройках"); return; }
  if (!st.granted) { setState("warn", "Разрешите доступ в настройках"); return; }
  if (st.proxyReason && !shouldRetryHealth(st.proxyReason)) { blocked(routeFailureText(st.proxyReason, st.proxyPlatform)); return; }
  setState("unknown", st.proxyWarming ? "Проверяется HTTPS CONNECT…" : "Проверяем защищённый маршрут…");
  let result;
  try { result = await sendMessage({ type: "health" }); }
  catch (_) { blocked("Не удалось проверить маршрут"); return; }
  if (!result) { blocked("Не удалось проверить маршрут"); return; }
  if (result.ok !== true) { blocked(routeFailureText(result.reason, st.proxyPlatform)); return; }
  let latest;
  try { latest = await sendMessage({ type: "status" }); }
  catch (_) { blocked("Не удалось проверить защиту"); return; }
  if (!latest) { blocked("Не удалось проверить защиту"); return; }
  showDebuggerStatus(latest.artifactDebugger, latest.proxyPlatform);
  if (latest.proxyReason) { blocked(routeFailureText(latest.proxyReason, latest.proxyPlatform)); return; }
  if (!ready(result, latest)) { blocked("Защищённый маршрут ещё не готов"); return; }
  $open.disabled = false;
  $fp.textContent = FIREFOX_BUILD ? "UTC / en-US во вкладках Claude · другие сайты не затронуты" : "UTC / en-US · другие сайты заблокированы во всём профиле";
  if (result.session === "expired") setState("warn", "Маршрут защищён · войдите в Claude снова");
  else if (result.session === "none") setState("warn", "Маршрут защищён · войдите в Claude");
  else setState("ok", "Защищённый маршрут активен");
}
$open.addEventListener("click", () => callApi(EXTENSION_API.tabs, "create", { url: "https://claude.ai" }).catch(() => blocked("Не удалось открыть Claude")));
document.getElementById("test").addEventListener("click", () => refresh().catch(() => blocked("Не удалось проверить защиту")));
document.getElementById("settings").addEventListener("click", () => callApi(EXTENSION_API.runtime, "openOptionsPage").catch(() => blocked("Не удалось открыть настройки")));
refresh().catch(() => blocked("Не удалось проверить защиту"));
