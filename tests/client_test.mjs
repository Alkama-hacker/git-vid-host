/**
 * Browser-level tests for the sealed page, executed with jsdom against the real
 * PHP runtime (php-wasm).  jsdom cannot render like Chrome, but it gives us a
 * real DOM + real WebCrypto + real script execution, which is exactly what the
 * loader and the defence engine touch.
 */
import { JSDOM, VirtualConsole, ResourceLoader } from 'jsdom';
import { webcrypto } from 'node:crypto';
import { startServer } from './php_server.mjs';

const UA = 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36';
const BASE = 'https://protected.example/';

class PhpResourceLoader extends ResourceLoader {
  constructor(srv, log) {
    super();
    this.srv = srv;
    this.log = log || [];
  }
  fetch(url) {
    const u = new URL(url, BASE);
    this.log.push('RES ' + u.pathname + u.search.slice(0, 60));
    return this.srv.request({
      path: u.pathname + u.search,
      headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Dest': 'script' },
    }).then((res) => Buffer.from(res.body));
  }
}

export function makeXHR(srv, log = []) {
  return class XHR {
    constructor() {
      this.readyState = 0;
      this.status = 0;
      this.responseText = '';
      this.timeout = 0;
      this._headers = {};
    }
    open(method, url) {
      this._url = url;
      this._method = method;
    }
    setRequestHeader(k, v) { this._headers[k.toLowerCase()] = v; }
    getResponseHeader() { return null; }
    send() {
      const u = new URL(this._url, BASE);
      log.push('XHR ' + u.pathname + u.search.slice(0, 60));
      const headers = {};
      if (this._headers['x-gvh-s']) headers['x-gvh-s'] = this._headers['x-gvh-s'];
      srv.request({ path: u.pathname + u.search, headers }).then((res) => {
        this.status = res.status;
        this.responseText = res.text();
        this.readyState = 4;
        if (this.onreadystatechange) this.onreadystatechange();
      }).catch(() => {
        this.status = 0;
        this.readyState = 4;
        if (this.onerror) this.onerror(new Error('network'));
      });
    }
  };
}

/**
 * Simulate the Android WebView bug that motivated src/assets/js/soft.js:
 * a crypto.subtle whose PBKDF2 (or AES-GCM) rejects valid input with the same
 * OperationError a real broken build throws.
 */
function brokenCrypto(kind) {
  const boom = () => {
    const e = new Error('The operation failed for an operation-specific reason');
    e.name = 'OperationError';
    return Promise.reject(e);
  };
  const real = webcrypto.subtle;
  return {
    getRandomValues: (a) => webcrypto.getRandomValues(a),
    subtle: {
      digest: real.digest.bind(real),
      importKey: (...a) => real.importKey(...a),
      sign: (...a) => real.sign(...a),
      deriveKey: kind === 'pbkdf2' ? boom : (...a) => real.deriveKey(...a),
      decrypt: kind === 'gcm' ? boom : (...a) => real.decrypt(...a),
    },
  };
}

function installGlobals(win, srv, log, opts, redir) {
  const define = (name, value) => {
    try { Object.defineProperty(win, name, { value, configurable: true, writable: true }); } catch (e) { }
  };
  define('crypto', opts && opts.breakCrypto ? brokenCrypto(opts.breakCrypto) : webcrypto);
  define('TextEncoder', TextEncoder);
  define('TextDecoder', TextDecoder);
  try {
    Object.defineProperty(win.navigator, 'userAgent', { value: (opts && opts.ua) || UA, configurable: true });
  } catch (e) { }
  define('XMLHttpRequest', makeXHR(srv, log));
  define('requestAnimationFrame', (cb) => setTimeout(() => cb(Date.now()), 0));
  if (opts && opts.topDifferent) {
    try { Object.defineProperty(win, 'top', { value: {}, configurable: true }); } catch (e) { }
    if (win.top === win) { try { win._top = {}; } catch (e) { } }
  }
  if (opts && typeof opts.webdriver !== 'undefined') {
    try { Object.defineProperty(win.navigator, 'webdriver', { value: opts.webdriver, configurable: true }); } catch (e) { }
  }
  if (opts && opts.globals) {
    for (const [k, v] of Object.entries(opts.globals)) define(k, v);
  }
  // capture navigations so we can assert the deny redirect without a network
  try {
    const L = win.Location.prototype;
    for (const name of ['replace', 'assign']) {
      Object.defineProperty(L, name, {
        configurable: true, writable: true,
        value: function (u) { redir.push(String(u)); },
      });
    }
  } catch (e) { }
}

/**
 * Every iframe the shell creates must get the same fake environment the top
 * window has (crypto, XHR, patched location, capture hooks), otherwise the
 * sealed frame cannot decrypt or would look "hooked" to the defence engine.
 */
function patchFrames(win, srv, opts, redir, writes) {
  let proto;
  try { proto = win.Node.prototype; } catch (e) { return; }
  const orig = proto.appendChild;
  Object.defineProperty(proto, 'appendChild', {
    configurable: true, writable: true,
    value: function (node) {
      const out = orig.call(this, node);
      try {
        if (node && String(node.tagName).toUpperCase() === 'IFRAME' && node.contentWindow) {
          const fw = node.contentWindow;
          if (!fw.__gvhPatched) {
            fw.__gvhPatched = true;
            installGlobals(fw, srv, [], opts, redir);
            documentWriteHooks(fw, writes);
          }
        }
      } catch (e) { }
      return out;
    },
  });
}

function documentWriteHooks(win, writes) {
  let buf = [];
  let writing = false;
  Object.defineProperty(win.document, 'open', {
    configurable: true, writable: true, value: () => { writing = true; buf = []; },
  });
  Object.defineProperty(win.document, 'write', {
    configurable: true, writable: true,
    value: (chunk) => { if (writing) buf.push(String(chunk)); else writes.push(String(chunk)); },
  });
  Object.defineProperty(win.document, 'close', {
    configurable: true, writable: true,
    value: () => { writing = false; if (buf.length) writes.push(buf.join('')); },
  });
}

function makeConsole(errors, logs) {
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => {
    errors.push(String((e && e.message) || e));
    if (process.env.GVH_TRACE) {
      const detail = (e && (e.detail || e));
      errors.push('STACK ' + String((detail && detail.stack) || '').slice(0, 900));
    }
  });
  for (const level of ['log', 'warn', 'error', 'info']) {
    vc.on(level, (...a) => logs.push(level + ': ' + a.map(String).join(' ')));
  }
  return vc;
}

/**
 * Load the sealed shell, run the loader, capture what it document.write()s.
 */
export async function boot(srv, opts = {}) {
  const res = await srv.request({ path: opts.path || '/index.php', ua: opts.ua, headers: opts.headers || {} });
  let html = res.text();
  if (opts.transformHtml) html = opts.transformHtml(html);
  const writes = [];
  const errors = [];
  const logs = [];
  const redir = [];
  const virtualConsole = makeConsole(errors, logs);
  const dom = new JSDOM(html, {
    url: BASE,
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    virtualConsole,
    beforeParse(win) {
      installGlobals(win, srv, [], opts, redir);
      documentWriteHooks(win, writes);
      patchFrames(win, srv, opts, redir, writes);
    },
  });
  const deadline = Date.now() + (opts.timeout || 25000);
  const hardErrors = () => errors.filter((e) => !/Not implemented/.test(e));
  while (Date.now() < deadline && writes.length === 0 && hardErrors().length === 0) {
    await new Promise((r) => setTimeout(r, 40));
  }
  const out = writes[0] || '';
  // the post-boot outer document: it must not carry a single node of the site
  let topHtml = '';
  let frameCount = 0;
  try {
    topHtml = dom.window.document.documentElement.outerHTML;
    frameCount = dom.window.document.querySelectorAll('iframe').length;
  } catch (e) { }
  try { dom.window.close(); } catch (e) { }
  return {
    shellHtml: html, cookie: res.setCookies[0] || '', finalHtml: out,
    topHtml, frameCount,
    errors, logs, redirects: redir, shellStatus: res.status, shellHeaders: res.headers,
  };
}

/**
 * Build a live "rendered page" DOM from the captured final HTML and run the
 * defence engine inside it.
 */
export function render(finalHtml, srv, opts = {}) {
  const writes = [];
  const errors = [];
  const logs = [];
  const redir = [];
  const resLog = [];
  const virtualConsole = makeConsole(errors, logs);
  const dom = new JSDOM(finalHtml, {
    url: opts.url || BASE,
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    virtualConsole,
    resources: new PhpResourceLoader(srv, resLog),
    beforeParse(win) {
      installGlobals(win, srv, opts.xhrLog || [], opts, redir);
      documentWriteHooks(win, writes);
    },
  });
  return {
    dom,
    win: dom.window,
    doc: dom.window.document,
    writes,
    errors,
    logs,
    redirects: redir,
    resLog,
    close: () => { try { dom.window.close(); } catch (e) { } },
  };
}

export { startServer, UA, BASE };
