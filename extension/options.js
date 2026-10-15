const $h = document.getElementById("host");
const $u = document.getElementById("user");
const $p = document.getElementById("pass");
const $s = document.getElementById("status");
const $perm = document.getElementById("perm-status");
let statusTimer;

function show(text, cls) {
  clearTimeout(statusTimer);
  $s.textContent = text;
  $s.className = cls || "";
  $s.style.display = "inline";
  statusTimer = setTimeout(() => { $s.style.display = "none"; }, 6000);
}
function refreshPerm() {
  chrome.runtime.sendMessage({ type: "status" }, st => {
    if (chrome.runtime.lastError || !st) { $perm.textContent = "Не удалось проверить защиту. Повторите проверку."; return; }
    if (!st.host) { $perm.textContent = "Введите домен шлюза."; return; }
    if (!st.granted) { $perm.textContent = "Разрешите доступ к шлюзу и адресам Claude кнопкой ниже."; return; }
    $perm.textContent = st.proxyReady && st.fingerprint
      ? "Защищённый маршрут активен. Другие внешние сайты заблокированы во всём профиле."
      : st.proxyWarming
        ? "Проверяется HTTPS CONNECT и proxy-аутентификация; artifact-запросы остаются заблокированы."
        : "Защищённый маршрут ещё не готов. Внешние запросы заблокированы до подключения.";
  });
}

// Call permissions.request before the first await so the browser still has the
// click's user gesture. The manifest's wildcard permits custom gateway domains;
// the actual request is restricted to this gateway and the approved host list.
async function saveAndGrant() {
  const host = $h.value.trim().toLowerCase();
  if (!GatewayPrivacy.validGatewayHost(host)) { show("Введите домен шлюза без https:// и пути", "err"); return; }
  let granted;
  try {
    granted = await chrome.permissions.request({ origins: GatewayPrivacy.requiredOrigins(host) });
  } catch (_) { show("Браузер не разрешил доступ. Повторите нажатие кнопки.", "err"); return; }
  if (!granted) { show("Доступ не разрешён. Настройки не изменены.", "warn"); return; }
  await chrome.storage.local.set({ gatewayHost: host, authUser: $u.value.trim(), authPass: $p.value });
  const result = await chrome.runtime.sendMessage({ type: "apply" });
  if (!result?.ok) show("Настройки сохранены. Защищённый маршрут пока недоступен.", "warn");
  else {
    show("Настройки сохранены. Проверяем защищённый маршрут…");
    const health = await chrome.runtime.sendMessage({ type: "health" });
    const state = await chrome.runtime.sendMessage({ type: "status" });
    const ready = health?.ok && state?.proxyReady && state.fingerprint;
    show(ready ? "Защищённый маршрут активен ✔" : "Маршрут недоступен. Проверьте шлюз и данные входа.", ready ? "" : "warn");
  }
  refreshPerm();
}
chrome.storage.local.get(["gatewayHost", "authUser", "authPass"], r => {
  $h.value = r.gatewayHost || "";
  $u.value = r.authUser || "";
  $p.value = r.authPass || "";
});
for (const id of ["save", "grant"]) document.getElementById(id).addEventListener("click", () => {
  saveAndGrant().catch(() => { show("Не удалось применить настройки. Повторите попытку.", "err"); refreshPerm(); });
});
refreshPerm();
