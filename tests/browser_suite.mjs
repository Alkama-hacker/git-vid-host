/**
 * Browser-level acceptance suite for a sealed build (jsdom + php-wasm).
 *
 *   node browser_suite.mjs /tmp/gvh-out/simple fixtures/simple.html
 *
 * Covers: loader, decrypted markup, per-fixture behaviour (forms, external
 * JS/CSS, media URLs, huge pages, unicode), and the whole detection matrix.
 */
import { startServer, boot, render } from './client_test.mjs';
import { readFileSync } from 'node:fs';

const dir = process.argv[2];
const srcFile = process.argv[3];
const fixture = (srcFile || '').split('/').pop().replace('.html', '');
const src = srcFile ? readFileSync(srcFile, 'utf8') : '';
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: !!ok, detail: String(detail).slice(0, 300) });
  console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok || !detail ? '' : '  [' + String(detail).slice(0, 300) + ']'));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const srv = await startServer(dir + '/index.php');

/* ------------------------------------------------------------------ */
/* 1. boot phase                                                       */
/* ------------------------------------------------------------------ */
const b = await boot(srv, { globals: { __GVH_DEBUG: 1 } });
check('boot renders the page', b.finalHtml.length > 500, b.finalHtml.length);
check('boot has no jsdom errors', b.errors.filter((e) => !/Not implemented/.test(e)).length === 0, b.errors.slice(0, 2).join(' | '));
check('boot has no GVH errors', !b.logs.some((l) => l.includes('GVH-ERR')), b.logs.filter((l) => l.includes('GVH-ERR')).join(' | '));
check('final document keeps standards mode', /^<!DOCTYPE html>/i.test(b.finalHtml.trim()), b.finalHtml.trim().slice(0, 30));
check('html credit banner after doctype', b.finalHtml.slice(0, 4000).includes('@SHACKER_ENCRYPTION_bot'));
check('banner is the first client-side comment', /^<!DOCTYPE html>\s*\n?<!--/i.test(b.finalHtml.trim()));
check('engine injected once', (b.finalHtml.match(/GVH SHIELD :: defence engine/g) || []).length === 1);
check('no asset placeholders left', !b.finalHtml.includes('__GVH_A_'));
check('no server-only comments left', !b.finalHtml.includes('this comment must move server-side') && !b.finalHtml.includes('internal note'));
check('shell never contained the page', !/id="headline"/.test(b.shellHtml) && !b.shellHtml.includes('SECRET SAUCE'));
check('shell has no manifest leakage of chunk keys', !/\"ct\":/.test(b.shellHtml));


/* ------------------------------------------------------------------ */
/* 1a. frame isolation: the outer document holds no site markup        */
/* ------------------------------------------------------------------ */
{
  check('page is hosted in a frame', b.frameCount === 1, 'frames=' + b.frameCount);
  check('outer document has no site markup',
    !/id="headline"/.test(b.topHtml) && !/<h1/i.test(b.topHtml) && !/id="btn"/.test(b.topHtml),
    b.topHtml.slice(0, 160));
  const topBody = (b.topHtml.match(/<body[\s\S]*<\/body>/i) || [''])[0];
  check('outer document has no decrypted text',
    !/Neon Coffee|Order placed|headline/.test(topBody), topBody.slice(0, 160));
  check('outer document keeps no splash/ui leftovers',
    !/Decrypting secure layers/.test(b.topHtml) && !/id="pbar"/.test(b.topHtml) && !/pmsg/.test(b.topHtml));
  check('outer document keeps no bootstrap (encrypted blob gone)',
    !/MAN_B64/.test(b.topHtml) && !/var MX/.test(b.topHtml) && !/__GVH_BRIDGE__/.test(b.topHtml));
  check('frame fills the viewport',
    /position:\s*fixed/i.test(b.topHtml) && /width:\s*100%/i.test(b.topHtml) && /height:\s*100%/i.test(b.topHtml),
    (b.topHtml.match(/<iframe[^>]*>/) || [''])[0].slice(0, 160));
  check('frame is the only body child', (b.topHtml.match(/<iframe/g) || []).length === 1);
  const hostKey = (b.shellHtml.match(/var HOSTKEY = "([^"]+)"/) || [])[1];
  check('shell carries a frame-host key', !!hostKey && /^h_[0-9a-f]{12,16}$/.test(hostKey), hostKey);
}

const html = b.finalHtml;

/* ------------------------------------------------------------------ */
/* 1b. boot-time tamper detection                                      */
/* ------------------------------------------------------------------ */
{
  const tampered = await boot(srv, {
    transformHtml: (h) => h.replace('<script>/*!', '<script>// tampered\n/*!'),
  });
  check('boot detects an edited credit banner', tampered.finalHtml.includes('edit my credit'), tampered.finalHtml.slice(0, 60));
}
{
  const tampered = await boot(srv, {
    transformHtml: (h) => h.replace(/var MAN_B64 = "[^"]+"/, 'var MAN_B64 = "AAAA"'),
  });
  const offline = /SEALED <span>PAGE|Secure manifest could not be read|unlocks from its original server/.test(tampered.finalHtml);
  check('boot rejects a tampered manifest', offline, tampered.finalHtml.slice(0, 80));
}
{
  // plain HTTP: browsers do not expose crypto.subtle outside a secure context
  const plain = await boot(srv, { globals: { crypto: {} } });
  check('plain http shows the HTTPS-required page',
    /HTTPS/i.test(plain.finalHtml) && /REQUIRED/i.test(plain.finalHtml) && !plain.finalHtml.includes('MAN_B64'),
    plain.finalHtml.slice(0, 80));
}
{
  const tampered = await boot(srv, { webdriver: true });
  check('boot blocks a webdriver browser', /NOOB|edit my credit/.test(tampered.finalHtml), tampered.finalHtml.slice(0, 60));
}
{
  const tampered = await boot(srv, { topDifferent: true });
  check('boot blocks an iframe embed', /NOOB|SEALED <span>PAGE/.test(tampered.finalHtml), tampered.finalHtml.slice(0, 60));
}

/* ------------------------------------------------------------------ */
/* 2. live DOM: page works                                             */
/* ------------------------------------------------------------------ */
const r = render(html, srv, {});
await sleep(700);
const w = r.win, d = r.doc;
const cleanErrors = r.errors.filter((e) => !/Not implemented|Could not parse CSS/.test(e));

check('document rendered', !!d.body && d.body.children.length > 0);
check('inner document resolves relative URLs from the real page', d.baseURI === 'https://protected.example/', d.baseURI);
check('inner document carries a <base> shim', /<base href="https:\/\/protected\.example\/"/.test(html), (html.match(/<base[^>]*>/) || [''])[0]);
check('title preserved', d.title.length > 0, d.title);

function byId(id) { return d.getElementById(id); }
function textOf(id) { const el = byId(id); return el ? el.textContent.trim() : null; }

if (fixture === 'simple') {
  check('headline decrypted', textOf('headline') === 'Neon Coffee', textOf('headline'));
  check('inline JS ran', d.body.getAttribute('data-ready') === '1', d.body.getAttribute('data-ready'));
  const btn = byId('btn');
  if (btn) btn.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  check('site click handler works', textOf('sub') === 'Order placed!', textOf('sub'));
  check('server-only comment removed from content', !html.includes('do not publish'));
  check('generator meta removed', !html.includes('SomeBuilder'));
}

if (fixture === 'rich' || (srcFile || '').includes('rich')) {
  check('entities decoded', textOf('headline') === 'Rich & Tricky ★', textOf('headline'));
  check('bengali + emoji preserved', (textOf('sub') || '').includes('বাংলা লেখা') && (textOf('sub') || '').includes('😂'), textOf('sub'));
  check('external js executed', textOf('js-status') === 'external-js-ok', textOf('js-status'));
  check('inline js executed', textOf('inline-status') === 'inline-ok', textOf('inline-status'));
  const sealedUrl = (v) => /\?[a-z0-9]{2,8}=[a-f0-9]{40}&/.test(v || '');
  const inlined = (v) => /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(v || '');
  const pic = byId('pic');
  check('small img inlined as data URI', !!pic && (inlined(pic.getAttribute('src')) || sealedUrl(pic.getAttribute('src'))), (pic && pic.getAttribute('src') || '').slice(0, 40));
  check('inlined data URI is a real PNG', !!pic && Buffer.from((pic.getAttribute('src') || '').split(',')[1] || '', 'base64').subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])));
  const big = byId('big');
  check('large img served from sealed vault', !!big && sealedUrl(big.getAttribute('src')), big && big.getAttribute('src'));
  check('srcset rewritten', !!pic && (pic.getAttribute('srcset') || '').split(',').length === 2 && (pic.getAttribute('srcset') || '').split(',').every((c) => sealedUrl(c) || inlined(c.trim().split(' ')[0])), pic && pic.getAttribute('srcset'));
  const svgImg = d.querySelector('svg image');
  const svgHref = svgImg && (svgImg.getAttribute('href') || svgImg.getAttribute('xlink:href') || '');
  check('svg image rewritten', !!svgImg && (sealedUrl(svgHref) || inlined(svgHref)), (svgHref || '').slice(0, 40));
  const bgSpan = d.querySelector('span[style*="background-image"]');
  const bgStyle = bgSpan && bgSpan.getAttribute('style') || '';
  check('inline style url rewritten', !!bgSpan && (/=[a-f0-9]{40}/.test(bgStyle) || /data:image\/png/.test(bgStyle)), bgStyle.slice(0, 80));
  check('data: image kept inline', !!d.querySelector('img[src^="data:image/png"]'));
  check('remote cdn image untouched', !!d.querySelector('img[src^="https://cdn.example.org"]'));
  check('form preserved', !!d.querySelector('form[action="/submit"][method="post"]'));
  check('input value preserved', d.querySelector('input[name="q"]').value === 'hello');
  check('textarea text preserved', d.querySelector('textarea[name="t"]').value === 'select me');
  check('conditional comment preserved', html.includes('<!--[if IE]>'));
  check('stylesheet count >= 2', d.styleSheets.length >= 2, d.styleSheets.length);
}

if (fixture === 'media') {
  const v = byId('movie');
  const srcUrl = d.querySelector('video source') && d.querySelector('video source').getAttribute('src');
  check('video element present', !!v);
  check('video source rewritten', /=[a-f0-9]{40}/.test(srcUrl || ''), srcUrl);
  check('video poster rewritten', /=[a-f0-9]{40}/.test((v && v.getAttribute('poster')) || ''), v && v.getAttribute('poster'));
  check('audio source rewritten', /=[a-f0-9]{40}/.test((d.querySelector('audio') || {}).getAttribute ? d.querySelector('audio').getAttribute('src') : ''), d.querySelector('audio') && d.querySelector('audio').getAttribute('src'));
  check('poster img rewritten', /=[a-f0-9]{40}/.test((byId('poster') || d.querySelector('img[alt="poster"]') || {}).getAttribute ? d.querySelector('img[alt="poster"]').getAttribute('src') : ''));
}

if (fixture === 'big') {
  const rows = d.querySelectorAll('.row');
  check('all 12000 rows decrypted', rows.length === 12000, rows.length);
  check('last row intact', rows.length > 0 && rows[rows.length - 1].textContent.includes('row 11999'), rows[rows.length - 1] && rows[rows.length - 1].textContent);
}

if (fixture === 'unicode') {
  check('unicode headline', (textOf('t') || '').includes('বাংলা ইউনিকোড 🚀 日本語 العربية'), textOf('t'));
  check('unicode js ran', (textOf('p') || '').includes('js-ünicode-ok'), textOf('p'));
}

// interactions / protections on the live page
const cm = new w.MouseEvent('contextmenu', { bubbles: true, cancelable: true });
const cmAllowed = d.dispatchEvent(cm);
check('right click blocked', !cmAllowed && cm.defaultPrevented, String(cmAllowed));

await sleep(1500);
check('no false kill on the live page', r.writes.length === 0 && !/NOOB/.test((r.writes[0] || '')), r.writes.length);
check('live page still intact', !!d.body && d.body.children.length > 0 && d.title.length > 0);

const f12 = new w.KeyboardEvent('keydown', { key: 'F12', keyCode: 123, bubbles: true, cancelable: true });
d.dispatchEvent(f12);
check('F12 blocked', f12.defaultPrevented);
await sleep(1200);
check('F12 wipes the page', r.writes.length > 0 && /NOOB/.test(r.writes.join('')), r.writes.length);

/* ------------------------------------------------------------------ */
/* 3. detection matrix (fresh DOM per scenario)                        */
/* ------------------------------------------------------------------ */
async function scenario(name, opts, expect, fn, wait) {
  const rr = render(html, srv, opts);
  await sleep(400);
  if (fn) await fn(rr);
  await sleep(wait || (expect === 'credit' ? 3200 : 1500));
  const killed = (rr.writes.join('\n').match(/NOOB|NICE TRY|NICE TRY/gi) || []).length > 0;
  const credited = rr.writes.join('\n').includes('edit my credit');
  const redirected = rr.redirects.some((u) => u.startsWith('https://access-denied.wasmer.app'));
  let ok;
  let detail = 'writes=' + rr.writes.length + ' redirects=' + JSON.stringify(rr.redirects.slice(0, 2));
  if (expect === 'live') ok = rr.writes.length === 0;
  else if (expect === 'credit') ok = credited;
  else ok = killed || redirected;
  check('detect: ' + name, ok, detail);
  try { rr.close(); } catch (e) { }
}

const UA_BOT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36';
const UA_JSDOM = 'Mozilla/5.0 (linux) AppleWebKit/537.36 (KHTML, like Gecko) jsdom/26.1.0';
const UA_WEBVIEW = 'Mozilla/5.0 (Linux; Android 13; SM-G991B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36';
const UA_KIWI = 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 Kiwi/120.0.0.0';
const UA_LEMUR = 'Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36 Lemur/1.0';
const UA_CURL = 'curl/8.5.0';

await scenario('webdriver flag', { webdriver: true }, 'deny');
await scenario('headless chrome UA', { ua: UA_BOT }, 'deny');
await scenario('jsdom UA', { ua: UA_JSDOM }, 'deny');
await scenario('in-app webview UA', { ua: UA_WEBVIEW }, 'deny');
await scenario('kiwi browser UA', { ua: UA_KIWI }, 'deny');
await scenario('lemur browser UA', { ua: UA_LEMUR }, 'deny');
await scenario('curl UA', { ua: UA_CURL }, 'deny');
await scenario('iframe / different top', { topDifferent: true }, 'deny');
await scenario('sandboxed embed (opaque origin)', { globals: { origin: 'null' } }, 'deny');
await scenario('eruda devtools', { globals: { eruda: { _: 1 } } }, 'deny');
await scenario('vconsole devtools', { globals: { vConsole: { _: 1 } } }, 'deny');
await scenario('puppeteer global', { globals: { __puppeteer_evaluation_script__: {} } }, 'deny');
await scenario('selenium global', { globals: { domAutomation: true } }, 'deny');
await scenario('phantom global', { globals: { callPhantom: function () { } } }, 'deny');
await scenario('react devtools hook', { globals: { __REACT_DEVTOOLS_GLOBAL_HOOK__: {} } }, 'deny');
await scenario('designMode tamper', {}, 'deny', async (rr) => { rr.doc.designMode = 'on'; }, 3400);
await scenario('late injected cross-origin script', {}, 'deny', async (rr) => {
  await sleep(1400);
  const s = rr.doc.createElement('script');
  s.src = 'https://evil.example/payload.js';
  rr.doc.body.appendChild(s);
});
await scenario('late injected iframe', {}, 'deny', async (rr) => {
  await sleep(1400);
  const f = rr.doc.createElement('iframe');
  f.src = 'https://evil.example/frame';
  rr.doc.body.appendChild(f);
});
await scenario('object/embed injection', {}, 'deny', async (rr) => {
  await sleep(1400);
  const o = rr.doc.createElement('object');
  rr.doc.body.appendChild(o);
});
await scenario('edited credit banner', {}, 'credit', async (rr) => {
  const scripts = [...rr.doc.querySelectorAll('script')];
  const engine = scripts[scripts.length - 1];
  engine.textContent = engine.textContent.replace('SECURED BY', 'SECURED  BY');
});
await scenario('removed engine script', {}, 'credit', async (rr) => {
  const scripts = [...rr.doc.querySelectorAll('script')];
  scripts[scripts.length - 1].remove();
});


/* ------------------------------------------------------------------ */
/* 2b. hook / tamper detection (clean-realm scan)                      */
/* ------------------------------------------------------------------ */
await scenario('hooked Function.prototype.toString', {}, 'deny', async (rr) => {
  const orig = rr.win.Function.prototype.toString;
  rr.win.Function.prototype.toString = function () { return orig.call(this); };
  rr.win.Function.prototype.toString.toString = function () { return orig.call(orig); };
}, 2600);
await scenario('hooked Object.defineProperty', {}, 'deny', async (rr) => {
  const orig = rr.win.Object.defineProperty;
  rr.win.Object.defineProperty = function (o, p, d) { return orig.call(this, o, p, d); };
}, 2600);
await scenario('hooked Element.getAttribute (dom spy)', {}, 'deny', async (rr) => {
  const orig = rr.win.Element.prototype.getAttribute;
  rr.win.Element.prototype.getAttribute = function (n) { return orig.call(this, n); };
}, 2600);
await scenario('hooked Document.prototype.write', {}, 'deny', async (rr) => {
  const orig = rr.win.Document.prototype.write;
  rr.win.Document.prototype.write = function () { return orig.apply(this, arguments); };
}, 2600);
await scenario('hooked addEventListener (event spy)', {}, 'deny', async (rr) => {
  const orig = rr.win.EventTarget.prototype.addEventListener;
  rr.win.EventTarget.prototype.addEventListener = function () { return orig.apply(this, arguments); };
}, 2600);
await scenario('hooked storage (key thief)', {}, 'deny', async (rr) => {
  const orig = rr.win.Storage.prototype.getItem;
  rr.win.Storage.prototype.getItem = function (k) { return orig.call(this, k); };
}, 2600);
{
  // a single analytics-style fetch wrapper is legitimate: the site must live
  const rr = render(html, srv, {});
  await sleep(900);
  try {
    const orig = rr.win.fetch;
    if (orig) rr.win.fetch = function () { return orig.apply(this, arguments); };
    const xo = rr.win.XMLHttpRequest.prototype.send;
    rr.win.XMLHttpRequest.prototype.send = function () { return xo.apply(this, arguments); };
  } catch (e) { }
  await sleep(2600);
  check('detect: one legit traffic wrapper stays alive', rr.writes.length === 0, rr.writes.length);
  try { rr.close(); } catch (e) { }
}
{
  // ...but three of them at once is a proxy/injector
  const rr = render(html, srv, {});
  await sleep(900);
  try {
    const w = rr.win;
    if (w.fetch) { const o = w.fetch; w.fetch = function () { return o.apply(this, arguments); }; }
    const xo = w.XMLHttpRequest.prototype.open;
    w.XMLHttpRequest.prototype.open = function () { return xo.apply(this, arguments); };
    const xs = w.XMLHttpRequest.prototype.send;
    w.XMLHttpRequest.prototype.send = function () { return xs.apply(this, arguments); };
    const ao = w.atob;
    w.atob = function (s) { return ao.call(this, s); };
    const bo = w.btoa;
    w.btoa = function (s) { return bo.call(this, s); };
  } catch (e) { }
  await sleep(2800);
  const killed = /NOOB|NICE TRY/i.test(rr.writes.join('')) || rr.redirects.some((u) => u.includes('access-denied'));
  check('detect: three traffic hooks trip the soft tier', killed, 'writes=' + rr.writes.length);
  try { rr.close(); } catch (e) { }
}

/* ------------------------------------------------------------------ */
/* 2c. frame bridge: deny is delegated to the shell                    */
/* ------------------------------------------------------------------ */
{
  const hostKey = (b.shellHtml.match(/var HOSTKEY = "([^"]+)"/) || [])[1];
  let denied = 0;
  const rr = render(html, srv, {
    globals: { __GVH_BRIDGE__: { k: hostKey, deny: () => { denied++; }, credit: () => { }, dead: () => { } } },
  });
  await sleep(800);
  check('own frame boots without a frame kill', rr.writes.length === 0, rr.writes.length);
  const f12 = new rr.win.KeyboardEvent('keydown', { key: 'F12', keyCode: 123, bubbles: true, cancelable: true });
  rr.doc.dispatchEvent(f12);
  await sleep(600);
  check('own frame delegates the wipe to the shell', denied > 0, 'denied=' + denied);
  try { rr.close(); } catch (e) { }
}
{
  // a forged bridge key must NOT be trusted
  const rr = render(html, srv, {
    topDifferent: true,
    globals: { __GVH_BRIDGE__: { k: 'h_forged000000', deny: () => { } } },
  });
  await sleep(1200);
  const killed = rr.writes.length > 0 || rr.redirects.some((u) => u.includes('access-denied'));
  check('detect: forged frame bridge key', killed, 'writes=' + rr.writes.length);
  try { rr.close(); } catch (e) { }
}

/* ------------------------------------------------------------------ */
/* 2d. navigation break-out (frame -> real window)                     */
/* ------------------------------------------------------------------ */
{
  const hostKey = (b.shellHtml.match(/var HOSTKEY = "([^"]+)"/) || [])[1];
  const rr = render(html, srv, {
    globals: { __GVH_BRIDGE__: { k: hostKey, deny: () => { }, credit: () => { }, dead: () => { } } },
  });
  await sleep(800);
  const a = rr.doc.createElement('a');
  a.href = '/next-page.html';
  a.textContent = 'next';
  rr.doc.body.appendChild(a);
  a.dispatchEvent(new rr.win.MouseEvent('click', { bubbles: true, cancelable: true }));
  await sleep(300);
  // jsdom blocks real navigation, so a *navigation attempt* is the signal
  const tried = rr.errors.some((e) => /Not implemented: navigation/.test(e)) ||
    rr.redirects.some((u) => /next-page\.html/.test(u));
  check('same-origin link breaks out of the frame', tried,
    'redirects=' + JSON.stringify(rr.redirects.slice(0, 2)) + ' errors=' + rr.errors.slice(0, 1));
  try { rr.close(); } catch (e) { }
}
{
  // site code that handles the click itself must stay in control
  const hostKey = (b.shellHtml.match(/var HOSTKEY = "([^"]+)"/) || [])[1];
  const rr = render(html, srv, {
    globals: { __GVH_BRIDGE__: { k: hostKey, deny: () => { }, credit: () => { }, dead: () => { } } },
  });
  await sleep(800);
  const a = rr.doc.createElement('a');
  a.href = '/spa-route.html';
  a.textContent = 'spa';
  a.addEventListener('click', (e) => e.preventDefault());
  a.setAttribute('data-gvh', '1');
  rr.doc.body.appendChild(a);
  a.dispatchEvent(new rr.win.MouseEvent('click', { bubbles: true, cancelable: true }));
  await sleep(300);
  check('site-owned click handlers keep control', rr.redirects.length === 0, JSON.stringify(rr.redirects.slice(0, 2)));
  try { rr.close(); } catch (e) { }
}

// redirect target + navigation attempt (jsdom blocks real navigation, so the
// fallback page is expected there - which is exactly the documented fallback)
check('deny target is access-denied.wasmer.app',
  /var DENY = "https:\/\/access-denied\.wasmer\.app\/"/.test(b.shellHtml));
{
  const rr = render(html, srv, { globals: { eruda: { _: 1 } } });
  await sleep(1200);
  const navigated = rr.errors.some((e) => /Not implemented: navigation/.test(e));
  check('detection attempts a redirect', navigated || rr.writes.length > 0, 'nav=' + navigated + ' writes=' + rr.writes.length);
  check('blocked redirect falls back to the hacker page', /NOOB/.test(rr.writes.join('')), rr.writes.length);
  try { rr.close(); } catch (e) { }
}

// no debugger statement anywhere in the shipped runtime
check('no debugger statement in the sealed page', !/\bdebugger\s*;/.test(html));

// a same-origin lazily inserted script must NOT kill the page
{
  const assetUrl = (html.match(/https:\/\/protected\.example\/[^"'\s<>]*\?[a-z0-9]{2,8}=[a-f0-9]{40}&[a-z0-9]{2,8}=[a-f0-9]+/) || [])[0];
  if (assetUrl) {
    const rr = render(html, srv, {});
    await sleep(2000);
    const s = rr.doc.createElement('script');
    s.src = assetUrl;
    rr.doc.body.appendChild(s);
    await sleep(900);
    check('same-origin dynamic script allowed', rr.writes.length === 0, rr.writes.length);
    try { rr.close(); } catch (e) { }
  } else {
    console.log('skip same-origin dynamic script (fixture has no js asset)');
  }
}

check('no unexpected jsdom errors in defence runs', cleanErrors.length === 0, cleanErrors.slice(0, 2).join(' | '));

r.close();
const failed = results.filter((x) => !x.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
