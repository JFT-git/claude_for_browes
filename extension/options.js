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
  const res = await chrome.runtime.sendMessage({ type: "requestPermission" });
  if (res && res.granted) { show("Сохранено и доступ разрешён ✔"); }
  else if (res && res.error) { show("Ошибка: " + res.error, "err"); }
  else { show("Сохранено. Разрешите доступ к домену, когда браузер спросит.", "warn"); }
  refreshPerm();
});

document.getElementById("grant").addEventListener("click", async () => {
  const res = await chrome.runtime.sendMessage({ type: "requestPermission" });
  if (res && res.granted) { show("Доступ разрешён ✔"); }
  else { show("Доступ не разрешён", "err"); }
  refreshPerm();
});

refreshPerm();
