# Test suite

Two independent layers are tested on top of the **real** runtime:

| Layer | Engine | What it proves |
|---|---|---|
| Server | `@php-wasm/node` (PHP 8.3) | the generated `index.php` behaves like a web app: headers, sessions, key APIs, assets, Range, rate limit |
| Browser | `jsdom` + Node `webcrypto` | the sealed page boots, decrypts, renders and defends itself like a browser |

No Chromium download is required, so the whole suite runs on Termux.

## Install

```bash
npm install        # @php-wasm/node, @php-wasm/universal, jsdom
```

## Run

```bash
bash tests/run_all.sh       # builds 5 fixtures + the demo, runs both suites on each
```

or individually:

```bash
GVH_PHP_MODE=wasm python3 src/gvh.py build tests/fixtures/simple.html -o /tmp/o/simple --force --allow-non-native
node tests/api_suite.mjs /tmp/o/simple tests/fixtures/simple.html
node tests/browser_suite.mjs /tmp/o/simple tests/fixtures/simple.html
```

Other scripts:

```bash
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
- `client_test.mjs` — jsdom harness: `boot()` (splash → decrypted document) and
  `render()` (live DOM with resource loading, WebCrypto, XHR and redirect
  capture).
- `api_suite.mjs` — server-side acceptance checks.
- `browser_suite.mjs` — client-side acceptance checks + detection matrix.
- `phpwasm_cli.mjs` — CLI bridge used by `GVH_PHP_MODE=wasm` (dev only).
- `preview_server.mjs` — real HTTP preview of a sealed build on top of php-wasm
  (`node tests/preview_server.mjs /tmp/gvh-out/demo 8090`), useful to see the
  page decrypt in a real browser without installing PHP.

## Notes

- jsdom cannot render pixels, load media or implement navigation. Media is
  validated through the asset API (bytes, Range, seek), and redirects are
  validated by the capture shim plus the fallback page.
- The browser suite renders with `--allow-non-native` builds because Node's
  WebCrypto functions are not `[native code]`; real browsers pass that check.
