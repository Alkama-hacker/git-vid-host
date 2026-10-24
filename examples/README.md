# Examples

## `demo/` — a small site to seal

A realistic one-page studio site that exercises every part of the pipeline:

- external CSS (`assets/style.css`) and JS (`assets/app.js`) → encrypted vault
- small SVG logo → inlined as a `data:` URI
- large PNG hero → streamed from the AES-256-CTR vault
- a form, a textarea, a button handler, Bengali/Japanese/Arabic/emoji text

```bash
./gvh inspect examples/demo/index.html     # analysis only
./gvh build examples/demo/index.html -o /tmp/demo-secured
./gvh serve /tmp/demo-secured
# open http://localhost:8080/index.php
```

What to look at:

1. **View source** — only the splash screen, the credit banner and an
   encrypted blob. No markup, no CSS, no JS. Once the page unlocks, the outer
   document is reduced to a single `<iframe>`: the real DOM lives one level
   down, inside the sealed frame.
2. **The page works** — the button reacts, the form keeps its values, the image
   loads from `index.php?<secret>=<id>`.
3. **Right click / F12 / Ctrl+Shift+I** — page wiped, redirect or the
   "Nice Try Hacker" fallback.
4. **Edit the credit banner** in the generated file (e.g. in DevTools) — the
   credit-lock page appears within ~3 seconds.
4b. **Hook something** in the console before the page unlocks, e.g.
   `const o = fetch; fetch = (...a) => o(...a)` three times over (fetch, XHR
   `open`, `atob`) — the hook scan wipes the page. A single wrapper is allowed
   on purpose, so analytics code keeps working.
5. **Curl it** — `curl -A "curl/8" http://localhost:8080/index.php` → HTTP 403
   and the fallback page.

> The demo's form posts to `/submit`, which does not exist. Point it at your
> real backend; `index.php` only serves the sealed page.

## Deploying a real site

1. Copy the whole site into one folder (`index.html` + `assets/`).
2. Run `./gvh build index.html -o secured`.
3. Upload **only** the contents of `secured/`.
4. Keep the original sources and the `secured.report.json` on your machine.

If the site has several pages, seal each one and upload each output into its own
folder (or rename the generated file and keep the vault folder next to it — the
vault path is relative to `index.php`).
