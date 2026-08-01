# Message Header Analyzer (MHA)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

**Live demo:** [mha.jnlte.de](https://mha.jnlte.de)

A modern, dark-mode tool for parsing email headers and verifying **SPF**, **DKIM**, **DMARC** and **BIMI** live against public DNS — plus spam-filter header decoding, TLS/hop inspection, a side-by-side header comparison view, and password-protected sharing.

The core analysis (SPF/DKIM/DMARC/BIMI checks, header parsing, DKIM signature verification) runs **entirely client-side** via DNS-over-HTTPS and the Web Crypto API — nothing about the message you're analyzing is sent anywhere. A small backend exists only for two opt-in features: country-flag IP lookups and the Share function, and the backend never sees your data unless you explicitly click Share and consent to it.

## Features

- Paste raw headers (or a full RFC822 message), or upload/drag-and-drop an `.eml` / `.msg` file
- Live SPF evaluation (RFC 7208) — resolves the sender's SPF record, follows `include`/`redirect`, checks the IP against `ip4`/`ip6`/`a`/`mx`/`exists`
- Live DKIM verification (RFC 6376) — fetches the signer's public key from DNS and, when the message body is available, performs real RSA signature verification via the Web Crypto API
- Live DMARC lookup (RFC 7489) with SPF/DKIM alignment evaluation against the `From:` domain
- BIMI lookup — shows the sender's authenticated logo if published, with a note when DMARC isn't enforced enough for it to actually display in mailbox providers
- Spam filter header decoder — Rspamd (`X-Spamd-Result`), SpamAssassin (`X-Spam-Status`), Microsoft 365 Defender (`SCL`/`PCL`), and generic `X-Spam-Flag` / `X-Spam-Score`
- Received-chain timeline: per-hop delay in the visitor's own timezone, TLS detection (protocol-aware — doesn't flag internal/LMTP hops), reverse-DNS mismatch warnings, and country flags per IP
- Searchable header table (grouped into "other" vs "all"), plus raw source view
- **Compare** (`/compare`) — diff two messages side by side: verdict-by-verdict (SPF/DKIM/DMARC), Received-chain-by-chain, and header-by-header with a "show only differences" toggle
- **Share** — generates a password-protected, self-expiring link (`/s/<id>`) for either an analysis or a comparison, so you can hand a result to a colleague without them re-uploading anything

## Quick start (Docker)

```bash
cp .env.example .env   # then optionally fill in IPDB_API_KEY, see below
docker compose up -d --build
```

Open **http://localhost:3000** (configurable, see [Configuration](#configuration)).

Stop with `docker compose down`. Add `-v` to also delete the Postgres volume (share data).

## Configuration

All configuration lives in `.env` (copy `.env.example` to get started — every value has a sane default, so an empty/missing `.env` still works fine except for IP flags).

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Single source of truth for the app's port — propagates to nginx, its healthcheck, and the Docker port mapping. Change this one value, nothing else. |
| `IPDB_API_KEY` | *(empty)* | API key for an IPDB-style IP lookup service, used to show a country flag per hop. Without it, flags are silently skipped — everything else still works. Get a free key at [ipdb.jnlte.de](https://ipdb.jnlte.de) ([API docs](https://ipdb.jnlte.de/api)) — a free public instance provided alongside this project, not affiliated with the original IPDB project — or point `IPDB_BASE_URL` at your own. |
| `IPDB_BASE_URL` | `https://ipdb.jnlte.de/api/v1` | Base URL of the IPDB instance. |
| `APP_URL` | *(empty → inferred from the request)* | Public URL the app is reachable at, used to build Share links. Set this if you're behind a reverse proxy that terminates TLS — otherwise share links would be generated as `http://` instead of `https://`. |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `mha` / `mha` / `mha` | Local Postgres credentials — only reachable from inside the Docker network, used solely for Share storage. |
| `TZ` | `UTC` | Default timezone for container logs and the Postgres session. Times shown in the UI (Received chain, share expiry) always use each *visitor's own browser timezone* regardless of this setting. |

## Architecture

```
index.html, compare.html, view.html + js/*.js   → static frontend, no build step
server/                                          → small Express API (/api/geoip, /api/share*)
Postgres                                         → Share storage only
```

- **Frontend** — plain HTML/CSS/JS, ES modules, no bundler. `js/renderAnalysis.js` and `js/renderCompare.js` hold the rendering logic shared between the live analyzer/compare pages and the read-only share view (`view.html` + `js/view.js`), so a shared result renders identically to the live one.
- **Backend** (`server/`) — Express, used only for `/api/geoip/:ip` (proxies to IPDB so the API key never reaches the browser) and `/api/share*`. Every SPF/DKIM/DMARC/BIMI check and all header parsing happens in the browser — the backend is never involved unless you click Share.
- **Share encryption** — each share is AES-256-GCM encrypted with a key derived (scrypt) from a randomly generated one-time password. That password is shown once and never stored, so the ciphertext sitting in Postgres is not decryptable without it. Shares expire 24 hours after creation (checked on every read, plus a periodic cleanup job) and cannot be renewed.
- **nginx** serves the static frontend, reverse-proxies `/api/` to the backend, and rewrites `/compare` → `compare.html`, `/s/<id>` → `view.html`.

## Local development (frontend only, no Docker)

The analyzer and compare pages are static and work without the backend — Share and IP flags just won't be available:

```bash
npx serve .
# or
python3 -m http.server 3000
```

Then open the printed URL. Opening `index.html` directly via `file://` will **not** work — ES module imports require an actual HTTP server. Note that `/compare` and `/s/<id>` (extensionless URLs) are nginx rewrites specific to the Docker setup; outside Docker, use `compare.html` directly.

## Known limitations

- SPF/DKIM domain and IP are auto-detected from `Received-SPF`, `Return-Path`, `From` and the `Received` chain — these are heuristics. Use the "Recheck" override fields in the SPF panel if the wrong hop gets picked (not available on read-only share views).
- DKIM verification needs the message **body** to fully verify a signature. Header-only paste can only confirm the public key exists in DNS ("unverified") — upload the `.eml` for a full pass/fail.
- `.msg` parsing uses [`@kenjiuno/msgreader`](https://github.com/HiraokaHyperTools/msgreader) loaded from a CDN — requires internet access. If a `.msg` file has no raw transport headers stored (common for locally-composed drafts), only limited metadata can be reconstructed.
- The organizational-domain heuristic for DMARC (used when no record exists on the exact `From` domain) covers common two-part TLDs but isn't a full Public Suffix List implementation.
- Share links are password-protected but not access-logged or rate-limited beyond normal HTTP — treat the password like any other secret you'd share over chat.

## License

[MIT](LICENSE.md) © Justin Nolte
