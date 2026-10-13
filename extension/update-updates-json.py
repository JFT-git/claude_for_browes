#!/usr/bin/env python3
"""Insert or replace the entry for <version> in updates.json (Firefox auto-updates).
Usage: update-updates-json.py <version> [path-to-updates.json]"""
import json, sys

v = sys.argv[1]
path = sys.argv[2] if len(sys.argv) > 2 else "updates.json"
ID = "{3f7a9c2e-8b4d-4e1a-9c5f-2d6b8a4e7f1c}"
link = f"https://github.com/JFT-git/claude_for_browes/releases/download/v{v}/gateway-connector-firefox-{v}.xpi"

u = json.load(open(path))
ups = u["addons"][ID]["updates"]
for x in ups:
    if x["version"] == v:
        x["update_link"] = link
        break
else:
    ups.insert(0, {"version": v, "update_link": link})
json.dump(u, open(path, "w"), indent=2)
print(f"updates.json: v{v} -> {link}")
