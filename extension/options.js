const $h = document.getElementById("host");
const $u = document.getElementById("user");
const $p = document.getElementById("pass");
const $s = document.getElementById("status");
const $perm = document.getElementById("perm-status");

function show(t, cls) { $s.textContent = t; $s.className = cls || ""; $s.style.display = "inline"; setTimeout(() => { $s.style.display = "none"; }, 3000); }

async function refreshPerm() {
  chrome.runtime.sendMessage({ type: "status" }, (st) => {
    if (chrome.runtime.lastError || !st) return;
    if (!st.host) { $perm.textContent = "Введите домен шлюза."; return; }
    if (st.granted) { $perm.textContent = "✔ Доступ к " + st.host + " разрешён" + (st.fingerprint ? " · отпечаток UTC/en-US активен" : ""); }
    else { $perm.textContent = "✖ Доступ к " + st.host + " не разрешён — нажмите «Сохранить и разрешить»"; }
  });
}

// permissions.request() MUST be called directly from this click handler
// (Chrome only allows it with a live user gesture — not via background messages).
async function requestAccess() {
  const host = $h.value.trim();
  if (!host) { show("Введите домен шлюза", "err"); return false; }
  // Request broad access: the redirect rules cover claude.ai + asset hosts, and Chrome
  // applies DNR redirects reliably only when the extension has wide host access.
  // The prompt will read "Доступ к вашим данным для всех веб-сайтов".
  let granted = false;
  try {
    granted = await chrome.permissions.request({ origins: ["https://*/*"] });
  } catch (e) {
    show("Ошибка: " + e.message, "err");
    return false;
  }
  if (granted) await chrome.runtime.sendMessage({ type: "apply" });
  return granted;
}

chrome.storage.local.get(["gatewayHost", "authUser", "authPass"], (r) => {
  $h.value = r.gatewayHost || "";
  $u.value = r.authUser || "";
  $p.value = r.authPass || "";
});

document.getElementById("save").addEventListener("click", async () => {
  await chrome.storage.local.set({
    gatewayHost: $h.value.trim(),
    authUser: $u.value.trim(),
    authPass: $p.value
  });
  const granted = await requestAccess();
  if (granted) show("Сохранено и доступ разрешён ✔");
  else show("Сохранено. Разрешите доступ к домену, когда браузер спросит.", "warn");
  refreshPerm();
});

document.getElementById("grant").addEventListener("click", async () => {
  const granted = await requestAccess();
  if (granted) show("Доступ разрешён ✔");
  refreshPerm();
});

refreshPerm();
