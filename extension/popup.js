const $dot = document.getElementById("dot");
const $text = document.getElementById("status-text");
const $host = document.getElementById("host");
const $fp = document.getElementById("fp");

function setState(cls, text) { $dot.className = "dot " + cls; $text.textContent = text; }

async function refresh() {
  chrome.runtime.sendMessage({ type: "status" }, (st) => {
    if (chrome.runtime.lastError || !st) { setState("bad", "Error"); return; }
    $host.textContent = st.host || "not configured";
    $fp.textContent = st.fingerprint ? "UTC / en-US" : "off";
    if (!st.host) { setState("warn", "Not configured — open Settings"); return; }
    if (!st.granted) { setState("warn", "Access not granted — open Settings"); return; }
    setState("unknown", "Checking…");
    chrome.runtime.sendMessage({ type: "health" }, (res) => {
      if (chrome.runtime.lastError || !res) { setState("bad", "Error"); return; }
      if (res.ok) {
        if (res.session === "expired") setState("warn", "Connected · session expired — sign in again");
        else if (res.session === "none") setState("warn", "Connected · not signed in — open Claude and sign in");
        else setState("ok", "Connected · Claude session OK");
      }
      else if (res.reason === "auth_failed") setState("bad", "Auth failed — check credentials");
      else if (res.reason === "no_permission") setState("warn", "Grant access in Settings");
      else if (res.reason === "unreachable") setState("bad", "Gateway unreachable");
      else setState("bad", "Error " + (res.status || res.reason || ""));
    });
  });
}

document.getElementById("open").addEventListener("click", () => chrome.tabs.create({ url: "https://claude.ai" }));
document.getElementById("test").addEventListener("click", refresh);
document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
refresh();
