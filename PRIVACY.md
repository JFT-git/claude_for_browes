# Privacy Policy — Gateway Connector for Claude

_Last updated: October 13, 2026_

## What the extension stores

The extension stores the following data **locally in your browser** (`chrome.storage.local`):

- Your gateway host (the domain of your own gateway server)
- Your gateway username and password (basic-auth credentials)

## Where this data goes

These credentials are sent **only** to the gateway server that you configure yourself,
to authenticate your requests. They are **never** transmitted to the extension's
developer or any third party.

## What the extension does not do

- No analytics, tracking, or telemetry of any kind
- No data collection by the developer — the developer receives nothing
- No browsing history, page content, or personal data is read or stored
- No data is sold or shared with third parties

## Permissions usage

- **declarativeNetRequest** — routes requests to claude.ai and its asset domains to
  your configured gateway host and adds your credentials to requests to that host.
- **scripting** — applies interface settings (UTC time zone, en-US language) and
  privacy restrictions (geolocation and WebRTC disabled) on your gateway pages only.
  The script is bundled in the extension; no remote code is downloaded or executed.
- **storage** — persists your gateway host and credentials locally in the browser.

## Source code

The extension is open source. You can audit exactly what it does:
https://github.com/JFT-git/claude_for_browes

## Contact

Open an issue at https://github.com/JFT-git/claude_for_browes/issues
