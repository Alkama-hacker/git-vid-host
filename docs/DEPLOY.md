# Deployment guide

## What you upload

```
secured/
├── index.php          ← required (this is the whole site)
└── vault_xxxxxxxx/    ← only in files mode
    ├── <id>.gvh       ← AES-256-CTR ciphertext
    ├── .htaccess      ← deny direct access (Apache)
    └── index.html     ← 404 stub for directory listing
```

**Never upload:**

- the original `.html` / `assets/` folder,
- `secured.report.json` (audit: asset names, decisions, paths),
- `secured.DEPLOY.txt` (notes for you).

Both files are written next to the output folder on purpose.

---

## Requirements on the host

| Item | Value |
|---|---|
| PHP | 7.2 or newer (8.x recommended) |
| Extensions | `openssl`, `zlib` (always compiled in on mainstream hosts) |
| WebCrypto | HTTPS **required** (browsers disable `crypto.subtle` on plain HTTP). `http://localhost` works; plain-HTTP domains and LAN IPs show the **HTTPS REQUIRED** page. Behind a proxy send `X-Forwarded-Proto: https`. |
| Writes | none — the site needs no database and no writable folder |

`gvh check <folder>` runs a live smoke test against the PHP built-in server and
verifies the response headers, the credit banner and that the shell is sealed.

---

## Apache (cPanel, shared hosting)

1. Upload the folder contents into `public_html/` (or a subfolder).
2. Make `index.php` the directory index:

   ```apache
   DirectoryIndex index.php index.html
   ```

3. Enable HTTPS (AutoSSL / Let's Encrypt in cPanel).
4. Keep the generated `.htaccess` inside the vault folder; it denies direct
   access on both Apache 2.2 and 2.4.

If your host forces `index.html` before `index.php`, delete any leftover
`index.html` in the folder.

## Nginx + PHP-FPM

```nginx
server {
    listen 443 ssl http2;
    server_name example.org;
    root /var/www/secured;
    index index.php;

    location ~ \.gvh$ { deny all; return 404; }
    location ~ /vault_[^/]+/ { deny all; return 404; }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

The PHP front controller already sends the security headers, so do not
duplicate `X-Frame-Options` (duplicates can break some browsers).

## PHP built-in server (local test)

```bash
./gvh serve secured           # http://localhost:8080/index.php
./gvh serve secured -p 9000 --host 0.0.0.0
```

`localhost` is treated as a secure context by browsers, so WebCrypto works.
Other devices on your LAN need HTTPS.

## Termux (on the phone)

```bash
pkg install python php
./gvh build index.html -o secured
./gvh serve secured
# open http://localhost:8080/index.php in the phone browser
```

To share it on the LAN, use a reverse proxy with TLS (e.g. `caddy`) — plain
`http://192.168.x.x` will show the “HTTPS required” page by design.

---

## Caching / CDN

The front controller sends `Cache-Control: no-store` for the shell and
`private, max-age=1800` for vault assets. If you use Cloudflare:

- do **not** enable “Rocket Loader” (it rewrites scripts) or HTML minification;
- do **not** enable “Email Address Obfuscation” (it injects scripts → the
  injection detector will wipe the page);
- keep “Bot Fight Mode” off for the domain (it changes the User-Agent and the
  server will answer 403).

A proxy that strips `Sec-Fetch-*` headers is fine; the session token is still
required.

**Iframes / CSP.** The sealed page renders itself inside a same-origin
`about:blank` frame, so the host must not send a CSP that forbids frames
(`frame-src 'self'` is enough; `frame-src 'none'` breaks the page). The
generated headers already allow it. A tool that rewrites `document.write`
(Rocket Loader, some "optimizers") breaks the boot — disable them.

**Don't wrap the site in your own iframe** unless you built it with
`--allow-iframe`; the shell blocks foreign parents by design.

What the sealed page sends so nobody can embed it:

| Layer | Value |
|---|---|
| Header | `X-Frame-Options: DENY` |
| Header | CSP `frame-ancestors 'none'` |
| Header | `Cross-Origin-Opener-Policy: same-origin` |
| Server | `Sec-Fetch-Dest: iframe\|frame\|embed\|object` → **403** + hacker fallback, before any markup is sent |
| Client | `top !== self`, `frameElement` without the shield marker, opaque origin (`sandbox`), blocked `localStorage`, `sandbox` attribute on the parent frame → wipe + redirect |

If you *do* need your own site to frame it (staging, dashboard widget), build
with `--allow-iframe`: it drops XFO/`frame-ancestors` and the client frame
check, but the sandbox and the hook scan stay active.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| “SEALED PAGE” after upload | Served over HTTP or `file://`, or PHP is not executing (the `.php` file was downloaded as text). |
| 500 “Configuration error” | The file was edited/minified; rebuild and upload the original. |
| “Vault missing” | Upload the vault folder, keep the same name. |
| Everyone gets 403 | A CDN / security layer rewrites User-Agents. Test with `--allow-crawlers` or disable that layer. |
| Blank page on one browser | Check the console: if the page was killed, the browser is being detected (webview, extension, devtools). Rebuild with `--allow-webview` for that client, or accept the block. |
| Video does not seek | The vault is in `embed` mode or the host buffers whole responses. Use `--asset-mode files`. |
| Page flashes then locks | Something injects a script after load (browser extension, translation widget, ad script). Remove it, or rebuild with `--allow-dynamic`. |

---

## Updating a sealed site

Rebuild from the original sources and upload the new `index.php` (and the new
vault if it changed). All session tokens and URLs from the previous build stop
working immediately — that is intentional.
