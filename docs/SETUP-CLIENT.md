# Client setup (Mac)

Set this up on each client's machine. ~5 minutes.

## What you need from your administrator

- The `extension/` folder (already configured for the gateway domain)
- Gateway host (e.g. `claude.example.com`)
- Your basic_auth **user** and **password**

## 1. Create a dedicated browser profile

Use a separate Chrome/Edge profile so your main browser is untouched:

1. Chrome → profile icon (top right) → **Add**
2. Name it e.g. "Claude"
3. Do **not** sign into a Google account in this profile

## 2. Clean fingerprint (so Claude doesn't see your real region)

In this profile:

1. **Language:** `chrome://settings/languages` → move **English (United States)** to the top
2. **Timezone UTC:** install a timezone-override extension (e.g. "Change Timezone") and set **UTC**
3. **WebRTC off:** `chrome://flags/#disable-webrtc` → Enabled (or a WebRTC-control extension)
4. **Geolocation off:** `chrome://settings/content/location` → don't allow

## 3. Install the extension

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select the `extension/` folder
4. Open the extension's **Options** (Details → Extension options)
5. Enter:
   - **Gateway host:** e.g. `claude.example.com`
   - **User / Password:** your basic_auth credentials
6. **Save**

## 4. Use Claude

Open `https://claude.ai` in this profile. It loads through the gateway with your session already authenticated.

- Type in Russian, paste text/links, drag-and-drop files — all native, no lag
- Claude sees the server's IP, not yours

## Troubleshooting

| Symptom | Fix |
|---|---|
| Browser login popup loops | Re-enter credentials in the extension Options, then reload the extension (⟳) |
| Asks to log in to Claude | Session cookies expired — ask the admin to re-extract cookies (DEPLOY-SERVER.md step 6) |
| Fonts look wrong | Hard reload: ⌘+Shift+R |
| Page partially loads / times out | Your network may be resetting the connection — try another network or ask the admin about the Cloudflare setup |

## Don't

- Don't open claude.ai outside this profile (it would use your real IP)
- Don't set Russian as the profile language
- Don't disable the extension while working
