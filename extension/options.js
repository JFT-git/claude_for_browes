const $h = document.getElementById("host");
const $u = document.getElementById("user");
const $p = document.getElementById("pass");
const $s = document.getElementById("status");

chrome.storage.local.get(["gatewayHost", "authUser", "authPass"], (r) => {
  $h.value = r.gatewayHost || "";
  $u.value = r.authUser || "";
  $p.value = r.authPass || "";
});

document.getElementById("save").addEventListener("click", () => {
  chrome.storage.local.set({
    gatewayHost: $h.value.trim(),
    authUser: $u.value.trim(),
    authPass: $p.value
  }, () => {
    $s.style.display = "inline";
    setTimeout(() => { $s.style.display = "none"; }, 2000);
  });
});
