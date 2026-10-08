#!/usr/bin/env python3
"""Extract Claude session cookies from the remote Chromium via CDP.

Multi-user: pass the gateway username as the first argument to write to
<COOKIES_DIR>/<user>.json. Default user is "claude" (single-user setup).

Prints ONLY a summary (count, domains, expiry). NEVER prints cookie values.
"""
import json, os, sys, time, urllib.request, websocket

DEBUG = os.environ.get("CDP_URL", "http://127.0.0.1:9222")
COOKIES_DIR = os.environ.get("COOKIES_DIR", "/config/gateway/cookies")

def sanitize(u):
    s = "".join(c for c in str(u) if c.isalnum() or c in "._-")
    return "" if s in ("", ".", "..") else s

def main():
    user = sanitize(sys.argv[1] if len(sys.argv) > 1 else "claude")
    if not user:
        print("ERROR: bad username", file=sys.stderr); sys.exit(1)
    out = os.path.join(COOKIES_DIR, user + ".json")

    tabs = json.loads(urllib.request.urlopen(DEBUG + "/json").read())
    page = next((t for t in tabs if t.get("type") == "page"), None)
    if not page:
        print("ERROR: no page tab found", file=sys.stderr); sys.exit(1)
    ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=15)
    ws.send(json.dumps({"id": 1, "method": "Storage.getCookies", "params": {}}))
    resp = json.loads(ws.recv())
    ws.close()
    cookies = resp.get("result", {}).get("cookies", [])
    keep = [c for c in cookies if ("anthropic" in c.get("domain","")) or ("claude" in c.get("domain",""))]
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"extracted_at": int(time.time()), "cookies": keep}, f, indent=2)
    os.chmod(out, 0o600)

    domains = sorted(set(c.get("domain","") for c in keep))
    now = int(time.time())
    session = [c for c in keep if c.get("expires", -1) <= 0]
    longterm = [c for c in keep if c.get("expires", -1) > now + 86400]
    auth_names = [c["name"] for c in keep if any(k in c["name"].lower() for k in ("session","auth","token","key","user"))]
    print("OK user=" + user + " extracted " + str(len(keep)) + " cookies across " + str(len(domains)) + " domains")
    print("  session (no-expiry): " + str(len(session)))
    print("  long-term >24h: " + str(len(longterm)))
    print("  domains: " + ", ".join(domains))
    print("  saved to: " + out)
    print("  auth-ish cookie names (values hidden): " + ", ".join(auth_names))

if __name__ == "__main__":
    main()
