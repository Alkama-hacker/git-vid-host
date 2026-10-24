# Architecture & wire formats

This document describes exactly what `gvh build` writes and what the browser
does with it. Every format below is implemented **twice** on purpose — once in
`src/lib/crypt_build.php` (build time and PHP runtime) and once in
`src/assets/js/boot.js` (browser) — and the test suite checks both sides agree.

---

## 1. Build pipeline

```
input.html
   │
   ├─ parser.tokenize()            stdlib HTML tokenizer, order preserving
   ├─ rewrite                       asset URLs, srcset, style url(), SVG <image>,
   │                                <base>, comments, source maps
   ├─ credit comment                HTML banner inserted right after <!DOCTYPE>
   ├─ analysis                      classify markup/CSS/JS/comments + every asset
   ├─ asset store                   inline (small images) vs route (vault)
   ├─ PHP crypt bridge  ──┐
   │   asset  (AES-CTR)   │
   │   content (AES-GCM)  │
   │   bundle  (envelope) │
   │   cfg     (blob)     │
   └─────────────────────┘
   │
   ├─ index.php       = template.php with @@CFG@@ replaced by the config blob
   ├─ vault_<id>/      (files mode only)  ciphertext assets + .htaccess
   ├─ <out>.report.json      audit report (never uploaded)
   └─ <out>.DEPLOY.txt       deployment notes (never uploaded)
```

All AES work happens in PHP so there is exactly one implementation of each
format. The Python side only orchestrates.

---

## 2. Secrets generated per build

| Name | Size | Purpose |
|------|------|---------|
| `master` | 32 B | HMAC key for session tokens |
| `sign` | 32 B | HMAC key for per-session API signatures |
| `mx` | 32 B | XOR key for the manifest blob |
| `core` | string | `GVHCORE::<24 hex>::<signature>`, part of the PBKDF2 password |
| `site` | `gvh_<12 hex>` | build id, mixed into hashes and rate-limit keys |
| cookie name | `gv_<6 hex>` | session cookie |
| query names `gw/pn/ps/pt/ap` | 6 hex each | API / nonce / signature / token / asset parameters |
| `data_dir` | `vault_<8 hex>` | media vault folder |
| `host_key` | `h_<16 hex>` | shell ↔ sealed-frame bridge marker (`CFG.hostKey`) |

---

## 3. `index.php`

```php
<?php
$GVH = gvh_cfg_decode('G1.…');   // base64( gzdeflate( json ) )
…
```

The config blob contains:

```jsonc
{
  "v": 2, "site": "gvh_…", "cookie": "gv_…", "master": "b64", "sign": "b64",
  "gw": "…", "pn": "…", "ps": "…", "pt": "…", "ap": "…",
  "shell": "<the whole splash document + bootstrap>",
  "manifest": { …metadata, no session key… },
  "api":   { "<32-hex>": { "n": 0, "k": "b64(50-char key)", "iv": "b64", "ct": "b64", "tg": "b64" }, … },
  "assets": { "<40-hex>": { "m": "video/mp4", "size": 123, "k": "b64", "iv": "b64",
                            "ct": "b64" | "file": "….gvh", "name": "movie.mp4" }, … },
  "mx": [ …32 ints… ], "files": true|false, "data_dir": "vault_…",
  "fb": "<fallback page>", "credit": "<credit page>", "offline": "<offline page>",
  "https": "<https-required page>", "block_bots": true, "rate": 180
}
```

`gvh_cfg_decode` accepts `G1.` (gzip) and falls back to `B1.` (plain base64).

---

## 4. Session token

```
raw   = "<unix-seconds>.<18 hex>"
token = raw + "." + HMAC-SHA256(raw, master)
```

- sent as an `HttpOnly`, `SameSite=Lax` cookie (plus `Secure` over HTTPS);
- accepted from the cookie, the `X-GVH-S` header, or the `?<pt>=` query
  parameter (needed for media elements that cannot set headers);
- valid for 12 hours;
- the **raw** part is what feeds the per-session key:

```
sessionKey = HMAC-SHA256("k|" + raw, sign)        // 32 bytes
```

---

## 5. Manifest (inside the shell)

```js
var MAN_B64 = "…";                 // base64( json XOR mx )
var MX = [ …32 ints… ];
var MAN = JSON.parse(utf8(xor(b64d(MAN_B64), MX)));
```

```jsonc
{
  "v": 2, "site": "…", "core": "…", "guard": "g_…",
  "vm":     { "k": "b64(32)", "n": "b64(16)", "p": "b64(program)", "r": 2 },
  "pbkdf2": { "salt": "b64(16)", "iv": "b64(12)", "tag": "b64(16)", "iter": 120000 },
  "chunks": [ { "k": "b64(50 chars)", "iv": "b64(12)" }, … ],   // 50 engine chunks
  "srcHash":"<sha256 of the engine source>",
  "content": { "n": 79, "apis": ["<32 hex>", …] },
  "fakes":   ["<32 hex>", … 24 decoy endpoint names],
  "gw":"…","pn":"…","ps":"…","pt":"…","ap":"…",
  "hb": "<!-- credit banner -->",
  "sess": { "t": "<token>", "k": "b64(sessionKey)" }   // injected per request
}
```

The manifest is regenerated on every request; only `sess` changes.

---

## 6. Content chunks (one API per chunk)

**Signature**

```
nonce = 24 hex chars (client)
sig   = HMAC-SHA256(sessionKey, api + "|" + nonce)        // hex
GET index.php?<gw>=<api>&<pn>=<nonce>&<ps>=<sig>&<pt>=<token>
```

The server recomputes the same HMAC and compares with `hash_equals`. Unknown
API names (including the 24 decoys) return a **plausible fake record** with
`n = -1`, a random 50-char key, random IV/ciphertext — so blind probing yields
nothing.

**Response**

```json
{ "p": "<base64 sealed payload>" }
```

**Sealing**

```
stream = SHA256( sessionKey ‖ "|" ‖ api ‖ "|" ‖ nonce ‖ "|r" )     // 32 B
sealed = payload_json XOR stream (repeating)
p      = base64(sealed)
```

**Payload**

```json
{ "n": 0, "k": "b64(50-char key)", "iv": "b64(12)", "ct": "b64", "tg": "b64" }
```

**Decryption**

```
aesKey = SHA256( base64decode(k) )          // 32-byte AES-256 key
plain  = AES-256-GCM-Decrypt(aesKey, iv, ct ‖ tg)
```

The plaintext is a **base64 fragment** of the page. Chunks are concatenated in
index order and decoded once. Chunk sizes are multiples of 4 so each fragment
is a valid base64 quartet.

---

## 7. Defence-engine envelope (step 7)

```
source
  → base64
  → 50 chunks (sizes multiple of 4)
  → per chunk: AES-256-GCM with SHA256(b64decode(key)) and a random IV
  → record = u32be(plainLen) ‖ u32be(ctLen) ‖ iv12 ‖ tag16 ‖ ct
  → container = "GVH1" ‖ u16be(count) ‖ u32be(b64Len) ‖ records…
  → reverse every byte
  → salt16 ‖ iv12 ‖ tag16 ‖ AES-256-GCM(PBKDF2-SHA256(password, salt, 120000))
  → GVH-VM XOR layer
  → base64  →  BLOB
```

Password: `core ‖ "|" ‖ site ‖ "|" ‖ base64(salt) ‖ "|" ‖ banner`.

### GVH-VM layer

- seed = `SHA256(vmKey ‖ vmNonce)` → eight little-endian `u32` state words;
- program = 96 random instructions, 16-bit each: `op(3) | a(3) | b(3)`;
- operations: add, xor, rotate-left by `1+b%31`, multiply by odd, swap,
  add `0x9E3779B9 + block`, xor `block * 0x85EBCA6B`, add `state[(a+1)&7] ^ block`;
- two rounds per 32-byte block; the block index is mixed into `s[0]`/`s[6]`;
- the eight state words (little-endian) are XORed with the data block, so
  encrypt and decrypt are the same operation.

---

## 8. Asset vault

Assets are encrypted with **AES-256-CTR** (32-byte random key, 16-byte IV), which
allows O(1) seeking:

- block index = `offset / 16`;
- the server increments the IV (big-endian counter) by the block index;
- it decrypts `len + (offset % 16)` bytes starting at the block boundary and
  returns the requested slice.

`embed` mode keeps the ciphertext base64 inside `index.php`.
`files` mode writes raw ciphertext to `vault_<id>/<asset-id>.gvh`.

`GET index.php?<ap>=<asset-id>&<pt>=<token>` supports:

| Feature | Behaviour |
|---|---|
| full GET | `200`, `Content-Type`, `Content-Length`, `ETag`, `Accept-Ranges: bytes` |
| `Range: bytes=a-b` | `206` + `Content-Range` |
| `Range: bytes=-n` | `206`, last n bytes |
| invalid / past EOF | `416` + `Content-Range: bytes */size` |
| `If-None-Match` | `304` |
| `HEAD` | headers only |
| cross-site / hotlink / no credentials | `403 sealed` |

Asset URLs contain the session token, so a leaked URL stops working when the
session expires. `Sec-Fetch-Site: same-origin` is accepted for native media
loads (browsers set it; scripts cannot forge it).

---

## 9. Request routing in `index.php`

```
?<ap>=…  → asset stream
?<gw>=…  → key API (JSON)
else     → shell (splash + bootstrap), cookie issued if needed
```

Bot/user-agent filtering runs before the shell is emitted (empty UA and
crawler/script UAs get the fallback page with HTTP 403). Shell responses carry:

```
X-Frame-Options: DENY
Content-Security-Policy: … frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cache-Control: no-store
X-Robots-Tag: noindex, nofollow, noarchive
Cross-Origin-Resource-Policy: same-origin
```

---

## 10. Boot sequence (browser)

```
1  raw script must start with the credit banner            → else credit page
2  file:// ? → offline page; no crypto.subtle ? → https page
3  webdriver / headless UA / webview / top!==self / bot UA → deny
4  decode manifest, validate shape                          → else offline page
5  decrypt engine (VM → PBKDF2 → AES-GCM → reverse → 50 chunks → checksum)
6  fetch content chunks (4 concurrent, HMAC-signed URLs, retries)
7  verify the HTML credit comment is present                → else credit page
8  replace __GVH_A_<id>__ tokens with vault URLs
9  inject the engine before </body>, set the render guard
10 create a same-origin <iframe>, install __GVH_BRIDGE__ = {k: hostKey, deny, credit, dead}
11 write <base href=real-URL> + finalHtml into the frame document
12 strip the outer document: splash, styles, favicon link, own <script> (manifest)
13 call two decoy APIs to blur traffic analysis
```

### Frame isolation

The decrypted markup never reaches the outer document. After step 12 the outer
DOM is literally `<body><iframe data-gvh="1" …></iframe></body>` — no text, no
forms, no keys. The engine runs inside the frame and checks every tick that
`window.__GVH_BRIDGE__.k` still equals `CFG.hostKey`; a missing or altered
bridge is treated as a frame tamper. Any kill is delegated to the shell
(`BRIDGE.deny()`), so the shell wipes both documents and drives the real
address bar. Navigation out of the frame is handled by two bubble-phase
listeners (link click → `top.location.replace`, form submit → cloned form in the
outer document, POST preserved); both skip events the site already handled.

### Hook / tamper scan

`buildWatch()` creates one hidden same-origin frame — a second JS realm — and
uses **its** `Function.prototype.toString`, `Object.getOwnPropertyDescriptor`
and `Object.getPrototypeOf` to read the true source of every watched built-in
in the main realm. A wrapper is a different function object, so its real source
differs; a hook that fakes `toString()` in the main realm cannot affect the
answer produced by another realm's intrinsic. Two tiers:

- **hard** (36 built-ins: `Function.prototype.*`, `Object.defineProperty`,
  `Reflect.*`, `JSON.*`, `Document.prototype.write/querySelector*`,
  `Element.prototype.getAttribute/setAttribute`, `Node.prototype.appendChild`,
  `EventTarget.prototype.addEventListener`, `HTMLIFrameElement.prototype
  .contentWindow/contentDocument`, `History.*`, `Storage.*`, …) — any mismatch
  is an immediate kill with reason `hook:<path>`.
- **soft** (`fetch`, XHR `open`/`send`/`setRequestHeader`, `eval`, `atob`,
  `btoa`, `URL.createObjectURL`, `window.open`, `sendBeacon`,
  `Location.replace/assign`) — the source is pinned at boot; only a *later*
  change counts, and three at once kill. One analytics wrapper stays alive.

A fresh realm must own different intrinsics (`cleanWin.Object !== window.Object`);
if it does not, frame creation itself was hooked and the scan refuses to run.

The engine then runs its own start-up checks and wires the detectors. It
verifies its own script text still begins with the banner every 2.6 s and that
it is still attached to the document; otherwise it shows the credit-lock page.

---

## 11. Threat model (short)

| Attacker | Result |
|---|---|
| View source / save page | splash + encrypted blobs only |
| `curl` / scraper | 403 fallback page |
| Headless browser / Puppeteer | wiped page, redirect |
| iframe on another site | blocked by headers + JS |
| DevTools / eruda | wiped page, redirect |
| Bookmarklet / injected script | wiped page |
| Read the outer DOM | only `<iframe>`: the real DOM lives one level down |
| Hooked `fetch`/XHR/`defineProperty`/`toString` | clean-realm source comparison catches it |
| Faked `toString` to hide a hook | detected — the answer comes from a second realm |
| Remove the credit | credit-lock page |
| Edit the credit | credit-lock page (banner is inside the PBKDF2 password) |
| Hotlink media | 403 |
| Brute-force key APIs | hashed names, HMAC signatures, decoys, rate limit |

See the honest limitations in the main README: a browser that can display the
page can eventually be made to reveal it.
