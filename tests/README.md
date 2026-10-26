# Test suite

Two independent layers are tested on top of the **real** runtime:

| Layer | Engine | What it proves |
|---|---|---|
| Vault | `@php-wasm/node` (PHP 8.3) | files/folders/zips seal and reopen byte-identically; wrong password and tampering fail; the generated `unlock.php` streams the payload |
| Server | `@php-wasm/node` (PHP 8.3) | the generated `index.php` behaves like a web app: headers, sessions, key APIs, assets, Range, rate limit |
| Browser | `jsdom` + Node `webcrypto` | the sealed page boots, decrypts, renders and defends itself like a browser |

No Chromium download is required, so the whole suite runs on Termux.

## Install

```bash
npm install        # @php-wasm/node, @php-wasm/universal, jsdom
```

## Run

```bash
bash tests/run_all.sh       # vault suite + 5 fixtures + the demo, all layers each
```

or individually:

```bash
GVH_PHP_MODE=wasm python3 src/gvh.py build tests/fixtures/simple.html -o /tmp/o/simple --force --allow-non-native
node tests/api_suite.mjs /tmp/o/simple tests/fixtures/simple.html
node tests/browser_suite.mjs /tmp/o/simple tests/fixtures/simple.html
```

Other scripts:

```bash
node tests/softcrypto_test.mjs  # pure-JS sha256/hmac/pbkdf2/aes-gcm vs node:crypto (30 checks)
node tests/vault_suite.mjs    # Shacker-Security vault: seal/open/tamper/unlock.php (35 checks)
node tests/codec_test.mjs     # PHP envelope -> browser decoder round-trip (15 checks)
node tests/vm_selftest.mjs    # GVH-VM parity between PHP and JS
node tests/e2e.mjs /tmp/o/simple        # quick boot check
node tests/render_smoke.mjs /tmp/o/simple  # quick render + click + right-click check
```

## Fixtures

`tests/fixtures_gen.py` generates them under `/tmp/gvh-sites` (no binaries in
the repo):

| Fixture | Exercises |
|---|---|
| `simple` | the leak-marker page (`SECRET SAUCE`, comments, generator meta) |
| `rich` | uppercase tags, entities, `srcset`, `<picture>`, SVG `<image>`, inline styles, data: URIs, external CSS/JS, form/textarea, conditional comments |
| `media` | 3 MB mp4 + 400 KB mp3 + 800×450 PNG → files mode, Range requests |
| `big` | 12 000 rows → 79 content chunks |
| `unicode` | Bengali, Japanese, Arabic, emoji, combining marks |

## Files

- `php_server.mjs` — HTTP harness over php-wasm (`startServer(index.php)`).
- `client_test.mjs` — jsdom harness: `boot()` (splash → decrypted document; it
  also installs the fake environment into every iframe the shell creates and
  returns the post-boot **outer** DOM so frame isolation can be asserted) and
  `render()` (live DOM with resource loading, WebCrypto, XHR and redirect
  capture).
- `api_suite.mjs` — server-side acceptance checks.
- `browser_suite.mjs` — client-side acceptance checks + detection matrix. New
  groups: **frame isolation** (outer document holds only the iframe, no markup,
  no decrypted text, no manifest, `<base>` shim, break-out navigation) and
  **hook scan** (hooked `toString`/`defineProperty`/`getAttribute`/
  `Document.write`/`addEventListener`/`Storage` must kill; one legit traffic
  wrapper must not; three must; forged bridge key must be rejected) matrix.
- `phpwasm_cli.mjs` — CLI bridge used by `GVH_PHP_MODE=wasm` (dev only).


## Notes

- jsdom cannot render pixels, load media or implement navigation. Media is
  validated through the asset API (bytes, Range, seek), and redirects are
  validated by the capture shim plus the fallback page.
- The browser suite renders with `--allow-non-native` builds because Node's
  WebCrypto functions are not `[native code]`; real browsers pass that check.
