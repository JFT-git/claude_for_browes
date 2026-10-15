const $dot = document.getElementById("dot");
const $text = document.getElementById("status-text");
const $host = document.getElementById("host");
const $fp = document.getElementById("fp");
const $debuggerNote = document.getElementById("debugger-note");
const $open = document.getElementById("open");

function showDebuggerStatus(status) {
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
    : "Chrome показывает баннер отладки при подключённой вкладке шлюза. Firefox preview артефактов не поддерживается.";
}

function setState(cls, text) { $dot.className = "dot " + cls; $text.textContent = text; }
function blocked(text) {
  $open.disabled = true;
  setState("bad", text);
  $fp.textContent = "Внешние запросы заблокированы до подключения.";
}
function refresh() {
  $open.disabled = true;
  chrome.runtime.sendMessage({ type: "status" }, st => {
    if (chrome.runtime.lastError || !st) { blocked("Не удалось проверить защиту"); return; }
    $host.textContent = st.host || "Шлюз не настроен";
    showDebuggerStatus(st.artifactDebugger);
    $fp.textContent = "Отдельный профиль для Claude · другие сайты блокируются.";
    if (!st.host) { setState("warn", "Укажите шлюз в настройках"); return; }
    if (!st.granted) { setState("warn", "Разрешите доступ в настройках"); return; }
    setState("unknown", st.proxyWarming ? "Проверяется HTTPS CONNECT…" : "Проверяем защищённый маршрут…");
    chrome.runtime.sendMessage({ type: "health" }, res => {
      if (chrome.runtime.lastError || !res) { blocked("Не удалось проверить маршрут"); return; }
      if (!res.ok) {
        blocked(res.reason === "auth_failed" ? "Проверьте данные входа в настройках" : res.reason === "firefox_proxy_unsupported" ? "Защищённый режим Firefox пока недоступен" : "Защищённый маршрут недоступен");
        return;
      }
      // Confirm the browser route after health: a successful HTTP response alone
      // does not establish a secure CONNECT proxy or MAIN-world protection.
      chrome.runtime.sendMessage({ type: "status" }, ready => {
        if (chrome.runtime.lastError || !ready?.proxyReady || !ready.fingerprint) { blocked("Защищённый маршрут ещё не готов"); return; }
        $open.disabled = false;
        $fp.textContent = "UTC / en-US · другие сайты заблокированы во всём профиле";
        if (res.session === "expired") setState("warn", "Маршрут защищён · войдите в Claude снова");
        else if (res.session === "none") setState("warn", "Маршрут защищён · войдите в Claude");
        else setState("ok", "Защищённый маршрут активен");
      });
    });
  });
}
$open.addEventListener("click", () => chrome.tabs.create({ url: "https://claude.ai" }));
document.getElementById("test").addEventListener("click", refresh);
document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
refresh();
