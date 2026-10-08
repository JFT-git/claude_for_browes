import json, os, sys, time, urllib.request, websocket
DEBUG = os.environ.get("CDP_URL", "http://127.0.0.1:9222")
OUT = "/config/gateway/cookies/claude.json"
tabs = json.loads(urllib.request.urlopen(DEBUG + "/json").read())
page = next((t for t in tabs if t.get("type") == "page"), None)
if not page:
    print("ERROR: no page tab"); sys.exit(1)
ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=15)
ws.send(json.dumps({"id": 1, "method": "Storage.getCookies", "params": {}}))
resp = json.loads(ws.recv())
ws.close()
cookies = resp.get("result", {}).get("cookies", [])
keep = [c for c in cookies if ("anthropic" in c.get("domain","")) or ("claude" in c.get("domain",""))]
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as f:
    json.dump({"extracted_at": int(time.time()), "cookies": keep}, f, indent=2)
os.chmod(OUT, 0o600)
domains = sorted(set(c.get("domain","") for c in keep))
now = int(time.time())
session = [c for c in keep if c.get("expires", -1) <= 0]
longterm = [c for c in keep if c.get("expires", -1) > now + 86400]
dom_str = ", ".join(domains)
auth_names = [c["name"] for c in keep if any(k in c["name"].lower() for k in ("session","auth","token","key","user"))]
auth_str = ", ".join(auth_names)
print("OK extracted " + str(len(keep)) + " cookies across " + str(len(domains)) + " domains")
print("  session (no-expiry): " + str(len(session)))
print("  long-term >24h: " + str(len(longterm)))
print("  domains: " + dom_str)
print("  saved to: " + OUT)
print("  auth-ish cookie names (values hidden): " + auth_str)
