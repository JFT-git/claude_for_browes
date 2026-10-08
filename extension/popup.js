const $dot = document.getElementById("dot");
const $text = document.getElementById("status-text");
const $host = document.getElementById("host");

function setState(cls, text) {
  $dot.className = "dot " + cls;
  $text.textContent = text;
}

async function refresh() {
  const { gatewayHost } = await chrome.storage.local.get(["gatewayHost"]);
  const host = (gatewayHost || "").trim();
  $host.textContent = host && !host.includes("__") ? host : "not configured";
  if (!host || host.includes("__")) { setState("warn", "Not configured — open Settings"); return; }
  setState("unknown", "Checking…");
  chrome.runtime.sendMessage({ type: "health" }, (res) => {
    if (chrome.runtime.lastError || !res) { setState("bad", "Error"); return; }
    if (res.ok) setState("ok", "Connected" + (typeof res.users === "number" ? " · " + res.users + " user(s)" : ""));
    else if (res.reason === "auth_failed") setState("bad", "Auth failed — check credentials");
    else if (res.reason === "unreachable") setState("bad", "Gateway unreachable");
    else setState("bad", "Error " + (res.status || res.reason || ""));
  });
}

document.getElementById("open").addEventListener("click", () => chrome.tabs.create({ url: "https://claude.ai" }));
document.getElementById("test").addEventListener("click", refresh);
document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());

refresh();
