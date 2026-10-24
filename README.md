# 🛡 GVH SHIELD

**Seal a normal HTML website into a single encrypted PHP file.**

GVH SHIELD takes a client's `.html` page (plus its CSS, JS, images, audio and
video), analyses it, keeps the heavy visual assets as streams, and encrypts
everything else into **one `index.php`** that only opens in a real browser on
its original HTTPS host. The markup is never served in plain text, the defence
engine is never served in readable form, and editing the credit banner locks
the site.

Built for **Termux** (Android), any Linux box and shared PHP hosting.
Pure Python standard library + PHP. No framework, no cloud, no database.

```
 SECURED BY : @SHACKER_ENCRYPTION_bot
 DEVELOPER  : Shacker
 DEV USER   : @Haki_xmw
```

---

## Table of contents

1. [What it does](#what-it-does)
2. [Requirements](#requirements)
3. [Install](#install)
4. [Quick start](#quick-start)
5. [CLI reference](#cli-reference)
6. [How the sealing works](#how-the-sealing-works)
7. [Defence engine](#defence-engine)
8. [Credit banner and tamper lock](#credit-banner-and-tamper-lock)
9. [Media and asset handling](#media-and-asset-handling)
10. [Deployment](#deployment)
11. [Testing](#testing)
12. [Honest security notes](#honest-security-notes)
13. [Troubleshooting](#troubleshooting)
14. [Repository layout](#repository-layout)

---

## What it does

The requested pipeline is implemented one-to-one:

| Step | Requested | Implemented as |
|------|-----------|----------------|
| 1 | AI analysis: what can move server-side | `src/lib/parser.py` tokenises the page; the analysis engine classifies markup, inline CSS/JS, comments, and every local asset. Report: `gvh inspect` / `steps.ai` in the audit file. |
| 2 | Visual filter: video/images stay client-side | video, audio, fonts and images above `--inline-limit` stay client-side and are **streamed** from the encrypted vault with HTTP `Range` support, so a weak host never stutters. Small icons are inlined as `data:` URIs. |
| 3 | Base64 the client-side content | the whole rewritten document is base64-encoded inside the PHP helper. |
| 4 | Split base64 into chunks | `--chunk-size` (default 16 384 base64 chars) → as many chunks as needed (79 chunks for the 1 MB test page). |
| 5 | AES-256, one random **50-character** key per chunk, keys server-side, one hashed API per key + fake APIs | content chunks: AES-256-GCM with `sha256(50-char key)`. Each chunk has its own hashed endpoint (`sha256(site|api|salt|index)[:32]`). 24 decoy endpoints answer with plausible fake records. |
| 6 | Defence layer (right click, shortcuts, devtools, eruda, bookmarklets, webviews, headless, iframe, …) | 20+ detector families in the sealed engine — **no `debugger` statement and no debugger loop anywhere**. |
| 7 | Obfuscation + credit banner + credit checker | engine envelope: base64 → 50 chunks → AES-256-GCM per chunk → binary → reverse → PBKDF2-SHA256 (120 000 iterations) + AES-GCM → GVH-VM ARX layer → base64. Branded banner is prepended to the engine, to the bootstrap script and to the HTML (right after the doctype). Editing it shows the credit-lock page. |
| 8 | Output a PHP file | `index.php` (+ optional encrypted media folder), plus an audit report written **next to** the output folder. |

Everything runs offline. Nothing about the client's page leaves the machine.

---

## Requirements

**Build machine**

- Python **3.7+** (standard library only)
- PHP **7.2+** CLI with the `openssl` and `zlib` extensions
- Node.js only for the optional test-suite

**Server**

- PHP **7.2+** with `openssl` + `zlib` (both are standard on virtually every
  shared host)
- **HTTPS** — WebCrypto is required and browsers disable it on plain HTTP.
  `http://localhost` is the only exception.

### Termux

```bash
pkg update
pkg install python php
# check that the crypto extension is present:
php -m | grep -i openssl
```

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install python3 php-cli php-openssl
```

---

## Install

```bash
git clone https://github.com/Alkama-hacker/git-vid-host.git
cd git-vid-host
chmod +x gvh
./gvh doctor          # verifies python, php, openssl, termux detection
```

`gvh` is a two-line launcher; you can also run `python3 src/gvh.py …` directly.

---

## Quick start

```bash
# 0) see what the analyzer would move, without building anything
./gvh inspect examples/demo/index.html

# 1) seal the page
./gvh build examples/demo/index.html -o demo-secured

# 2) local test (PHP built-in server)
./gvh serve demo-secured
#    open http://localhost:8080/index.php  (also works on the phone)

# 3) upload ONLY what is inside demo-secured/
#      index.php
#      vault_xxxxxxxx/        (only when media is in files mode)
```

The audit file (`demo-secured.report.json`) and the upload notes
(`demo-secured.DEPLOY.txt`) are written **next to** the output folder, not
inside it, so you cannot accidentally publish them.

Build output looks like this:

```
────── BUILD COMPLETE ───────────────────────────────────────
  ✔ output      : /home/me/demo-secured/index.php
  ✔ size        : 127.8 KB  (shell 115.7 KB + content 2.5 KB)
  ✔ chunks      : 2 sealed content chunks · 50 engine chunks
  ✔ api keys    : 2 (one AES-256 key per chunk) + 24 decoys
  ✔ media vault : embedded in index.php
  ✔ time        : 2.02s
  ✔ credit      : @SHACKER_ENCRYPTION_bot  ·  DEV Shacker · @Haki_xmw
```

---

## CLI reference

```
gvh                            interactive mode (asks for the file)
gvh build <input.html> [opts]   seal a page
gvh inspect <input.html>        analysis only (no PHP, no files written)
gvh doctor                      environment check
gvh serve <dir> [-p PORT]       PHP built-in server for a sealed folder
gvh check <dir>                 lint + live HTTP smoke test
gvh version                     version + credit
```

Global: `--php /path/to/php`

### `build` options

| Option | Default | Meaning |
|--------|---------|---------|
| `-o, --output DIR` | `<input>-secured/` | output folder |
| `--asset-mode auto\|embed\|files` | `auto` | `auto` switches to `files` when routed media > 1.5 MB |
| `--deny-url URL` | `https://access-denied.wasmer.app/` | redirect target on detection |
| `--chunk-size N` | `16384` | base64 characters per content chunk |
| `--inline-limit N` | `8192` | images up to N bytes become `data:` URIs |
| `--title TEXT` | from `<title>` | splash title |
| `--allow-crawlers` | off | let search-engine bots through |
| `--allow-webview` | off | do not block in-app webviews |
| `--allow-dynamic` | off | allow dynamic script/iframe injection (weaker) |
| `--allow-iframe` | off | allow embedding the page in an iframe (staging, own-site embeds; disables XFO/`frame-ancestors` and the frame check) |
| `--allow-non-native` | off | skip the `[native code]` check (emulators, test browsers) |
| `--allow-hooks` | off | skip the clean-realm hook/tamper scan (weaker; dev only) |
| `--allow-print` | off | allow printing |
| `--no-select` | off | allow text selection/copy |
| `--no-rightclick` | off | allow the context menu |
| `--keep-comments` | off | keep HTML comments (they become public) |
| `--ua-extra REGEX` | — | block extra user agents |
| `--force` | off | overwrite a non-empty output folder |
| `--quiet`, `--json` | off | scripting modes |

> Naming note: `--no-rightclick` / `--no-select` **disable the protection**
> (they read as "no right-click blocking", "no select blocking").

---

## How the sealing works

Full wire-format details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
page.html ──► parser/rewriter ──► credit comment + rewritten HTML
                    │
                    ├── small images ──────────────► data: URIs
                    ├── css/js/svg/fonts/media ────► asset vault
                    │        (AES-256-CTR, Range streaming)
                    └── document ──► base64 ──► chunks
                                      └── AES-256-GCM, 50-char key per chunk
                                          └── server-side key APIs (hashed names)
defence.js ──► banner ──► base64 ──► 50 chunks ──► AES-GCM
          ──► reverse ──► PBKDF2-SHA256(120k) + AES-GCM
          ──► GVH-VM ARX ──► base64 ──► sealed envelope in index.php

index.php = obfuscated config blob + encrypted page + encrypted engine
```

At runtime the browser:

1. shows the branded splash screen;
2. checks the credit banner of the bootstrap script;
3. refuses webviews, headless browsers, bots and iframes;
4. decodes the session manifest (XOR + base64, key delivered per session);
5. decrypts the engine envelope (GVH-VM → PBKDF2 → reverse → 50 AES chunks);
6. fetches each content chunk from **its own hashed API**, signed with
   HMAC-SHA256 over the session key;
7. rewrites the asset placeholders to vault URLs, injects the engine and writes
   the final document.

The PHP file itself contains no readable markup, no readable CSS/JS, no asset
filenames and no plaintext keys. Session tokens are HMAC-signed with a per-build
secret, expire after 12 hours, and chunk APIs are rate-limited (180 req/min/IP).

---

## Defence engine

Detection is silent and immediate. On a detection the page is wiped and the
visitor is redirected to `--deny-url` (default
`https://access-denied.wasmer.app/`). If the redirect is blocked (sandbox,
CSP, no network, `top` inaccessible), the pretty hacking-style page is shown:

> **Nice Try Hacker! ☠️**
> **You Are Still NOOB. 😂**

Detectors (all configurable through build flags where noted):

| Area | Signals |
|------|---------|
| Right click | `contextmenu` cancelled (keep enabled for form fields) |
| Keyboard | F12, Ctrl+Shift+I/J/C/K, Ctrl+U, Cmd+Opt+I/J/C/U, Ctrl+S/P |
| DevTools | window-size delta, lazy console probe, console cleared on kill |
| Devtools apps | `eruda`, `vConsole`, their DOM ids, React/Vue devtools hooks |
| Automation | `navigator.webdriver`, `HeadlessChrome`, Puppeteer/Playwright/Selenium/PhantomJS/Nightmare/Electron, `cdc_*`/`$wdc_*`/`__puppeteer*` globals, `domAutomation*` |
| Headless | software WebGL renderer (SwiftShader/llvmpipe), plugin/language/`chrome` heuristics |
| Browsers | Kiwi, Lemur, Mises, Yandex (desktop-extension mobile browsers) |
| Webviews | `; wv` UA, FB/Instagram/Line/WeChat/etc., `ReactNativeWebView`, `Android` bridges, iOS non-Safari |
| Server-side | crawler/script UAs (`curl`, `wget`, `python-requests`, `node-fetch`, Googlebot, …), empty UA |
| Frames | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, JS `top !== self` |
| Injection | MutationObserver on late `<script>`/`<iframe>`/`<object>`/`<embed>`, `javascript:` hrefs |
| Bookmarklets | `designMode`, `contenteditable` on `<html>`/`<body>`, own script removed |
| Copy | selection/copy/cut/drag blocked outside inputs, print blocked |
| Hooks | full clean-realm scan: a hidden same-origin frame exposes the *true* source of every watched built-in (`Function.prototype.toString`, `Object.defineProperty`, XHR `open`/`send`, `getAttribute`/`setAttribute`, `appendChild`, `addEventListener`, `history.pushState`, `Storage`, `JSON`, `Reflect`, `contentWindow`, …). Any replaced/wrapped built-in is caught even when the attacker fakes `toString`, because the answer comes from another realm |
| Traffic hooks | `fetch`, XHR, `atob`/`btoa`, `window.open`, `sendBeacon`, `eval`/`Function` are baseline-pinned; a change after boot counts, three at once kills (one analytics wrapper is allowed) |
| Frame integrity | the bridge key between shell and sealed frame is verified every tick; the frame cannot be re-parented or detached |
| Traffic | decoy key APIs are called alongside real ones |
| Rate limit | 600 key-API requests per minute per IP |

**Design rules enforced in the code and the tests:**

- **No `debugger` statement and no debugger loop** — a test asserts this on every
  build.
- The site keeps working: same-origin scripts/iframes and the page's own
  bootstrap are explicitly whitelisted, all listeners are passive unless they
  protect a specific gesture, and every detector is wrapped in `try/catch`.
- The engine is injected **after** the page markup, so it cannot delay or alter
  the site's own code.

### The outer DOM is empty (frame isolation)

The protected document is never written into the page you can see in
"Elements". The shell that PHP returns is a small, branded loader; once the
payload is decrypted it creates a full-viewport **same-origin iframe** and
writes the site inside *that* document. Immediately afterwards the loader
deletes the splash markup, its styles, the favicon link and **its own
`<script>` — including the encrypted manifest**. What is left in the outer
document is:

```html
<body><iframe data-gvh="1" aria-label="protected content" …></iframe></body>
```

So a visitor who inspects the outer page finds no headlines, no forms, no text
and no keys — the real DOM lives one level down, inside the sealed frame, which
is also where the defence engine runs.

Two details make this behaviour invisible to visitors:

- a `<base>` shim is injected into the frame document, so relative links, forms
  and assets resolve against the real URL instead of `about:blank`;
- clicking a same-origin link (or submitting a form, including POST) is promoted
  to the outer window, so a multi-page site never ends up with a frame inside a
  frame. Handlers run in the bubble phase and bail out when the site's own code
  already called `preventDefault()`, so SPA routers keep working.

Detection inside the frame is delegated to the shell: the frame asks the shell
to wipe both documents and navigate the real address bar to `--deny-url`, so a
kill inside the frame cannot be contained by the frame.

---

## Credit banner and tamper lock

The banner is written to three places:

1. the first line of the sealed defence engine,
2. the first line of the bootstrap script,
3. the HTML document, immediately after the doctype (visible in *view-source*).

```
/*!
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║                     ██  G V H   S H I E L D  ██                      ║
 * ║                  SEALED  ·  ENCRYPTED  ·  PROTECTED                  ║
 * ╠══════════════════════════════════════════════════════════════════════╣
 * ║  SECURED BY   :  @SHACKER_ENCRYPTION_bot                             ║
 * ║  DEVELOPER    :  Shacker                                             ║
 * ║  DEV USERNAME :  @Haki_xmw                                           ║
 * ║  SIGNATURE    :  ⟨GVH::SHACKER::7F3A-91C2-D00D-BEEF⟩                  ║
 * ╠══════════════════════════════════════════════════════════════════════╣
 * ║  [!] EDITING OR REMOVING THIS CREDIT WILL BREAK THIS WEBSITE.        ║
 * ║  [!] THIS CREDIT IS CRYPTOGRAPHICALLY BOUND TO THE DECRYPTOR.        ║
 * ║  [!] DO NOT REMOVE. DO NOT RENAME. DO NOT RE-UPLOAD EDITED.          ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 */
```

The banner text is part of the PBKDF2 password and is checked every 2.6 s. If it
was edited or removed, or the engine script was detached, the site is replaced
with:

> **Baby, You are edit my credit.** 🥲
> **So, Your website is not working.** 🥰☠️

---

## Media and asset handling

- **Images ≤ `--inline-limit`** → `data:` URI inside the sealed payload
  (saves a request; `srcset`/`style="url(...)"` entries are always routed so the
  comma-separated syntax stays valid).
- **Images > limit, video, audio, fonts, CSS, JS, SVG** → encrypted asset vault.
  - `embed` mode: ciphertext lives inside `index.php` (single-file deploy).
  - `files` mode: ciphertext lives in `vault_<id>/*.gvh`, served with
    `AES-256-CTR` + **HTTP Range** support, so video seeking and audio work
    without loading the whole file. A `.htaccess` denies direct access.
  - `auto` (default) switches to `files` when routed bytes > 1.5 MB.
- External `http(s)` assets (CDNs) cannot be sealed — they stay public and the
  build prints a warning.
- `data:` URIs already present in the page stay inline (warning printed).

---

## Deployment

See [`docs/DEPLOY.md`](docs/DEPLOY.md) for details. The short version:

1. Upload **everything inside** the output folder (`index.php` + `vault_*`).
2. Make `index.php` the directory index, or visit `/index.php`.
3. Serve over **HTTPS** (Let's Encrypt is fine).
4. Do **not** upload `*.report.json`, `*.DEPLOY.txt`, or the original source.
5. Works on Apache, Nginx + PHP-FPM, LiteSpeed and PHP built-in server.

---

## Testing

The dev harness runs the **real PHP runtime** (php-wasm) and a **real DOM with
real WebCrypto** (jsdom). No browser download needed, so it runs on Termux too.

```bash
npm install                  # @php-wasm/node + jsdom (dev only)
npm test                     # = bash tests/run_all.sh
```

`tests/run_all.sh` generates five fixture sites, seals all of them, and runs
two suites per build:

- `tests/api_suite.mjs` — server side: headers, manifest, every chunk API,
  bad signatures/tokens/nonces, decoy APIs, crawler blocking, asset bytes,
  Range/suffix/416/304/HEAD, hotlink protection, files mode, rate limiting.
- `tests/browser_suite.mjs` — client side: boot, decrypted markup, per-fixture
  behaviour (forms, textarea, external CSS/JS, `srcset`, `<picture>`, SVG
  `<image>`, inline styles, 12 000-row page, Bengali/Japanese/Arabic/emoji),
  right click, F12, the whole detection matrix, credit-edit lock, boot-time
  tamper detection and false-positive checks.

Fixtures are generated on the fly (`tests/fixtures_gen.py`); no binaries are
committed. `GVH_PHP_MODE=wasm` tells the CLI to use the php-wasm bridge instead
of a system PHP binary (dev only).

Want to see a sealed page in a real browser without installing PHP?

```bash
GVH_PHP_MODE=wasm ./gvh build examples/demo/index.html -o /tmp/demo --allow-iframe
node tests/preview_server.mjs /tmp/demo 8090     # http://localhost:8090
```

---

## Honest security notes

GVH SHIELD is a **client-side protection layer**, not DRM and not a licence
server. It makes copying, mirroring, automation and casual inspection
expensive, but:

- A browser that can render the page must be able to decrypt it. A determined
  human with a debugger, a patched browser or infinite time can reconstruct
  what their machine displays. The goal is to make that **impractical and
  unprofitable**, not theoretically impossible.
- Search engines are blocked by design (use `--allow-crawlers` if you need SEO;
  the page will still not be readable by crawlers).
- Forms must post to a real backend; `index.php` only re-renders the sealed
  page.
- Links to other local `.html` files are not protected automatically — seal
  each page.
- No security tool should be deployed without the site owner's permission.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Splash stays, then "SEALED PAGE" | Opened via `file://`, a static host, or plain HTTP. Serve over HTTPS with PHP. |
| "PHP OpenSSL missing" | `pkg install php` on Termux, enable `php-openssl` on the host. |
| "Vault missing" | Upload the whole folder, not only `index.php`. |
| Page shows the credit-lock page | The banner was edited (by a formatter, an IDE, a proxy). Rebuild and re-upload. |
| Video does not seek | Use `files` mode (`--asset-mode files`) so Range requests stream from the vault. |
| Site looks zoomed out on phones | Add `<meta name="viewport" content="width=device-width,initial-scale=1">` (build warns). |
| 403 for everyone | Check the UA: some hosts' security layers inject UAs; test with `--allow-crawlers` first. |

---

## Repository layout

```
gvh                      launcher
src/gvh.py               CLI
src/lib/builder.py       pipeline (analysis → rewrite → crypto → emit)
src/lib/parser.py        stdlib HTML tokeniser / rewriter
src/lib/brand.py         the credit banner (single source of truth)
src/lib/crypt_build.php  build-time crypto (single source of wire formats)
src/assets/template.php  generated PHP front controller
src/assets/js/boot.js    sealed bootstrap
src/assets/js/defense.js defence engine (never shipped readable)
src/assets/templates/    splash / fallback / credit / offline / https pages
tests/                   php-wasm + jsdom acceptance suites
docs/                    architecture and deployment notes
examples/demo/           a small site to try the tool on
```

---

**SECURED BY @SHACKER_ENCRYPTION_bot** · **DEV Shacker** · **@Haki_xmw**

Use it only on websites you own or are authorised to protect.
