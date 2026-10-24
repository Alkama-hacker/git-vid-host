/* ==========================================================================
 *  GVH SHIELD :: sealed bootstrap (client side)
 *  --------------------------------------------------------------------------
 *  This file is the *shell* loader.  It never contains readable markup or the
 *  readable defence engine: the page payload is AES-256-GCM sealed per chunk
 *  and the engine travels inside a five-layer client-key envelope.  Both only
 *  materialise in memory after the credit banner and the session manifest line
 *  up with the server.
 *
 *  ES5-safe on purpose (older Android browsers / Kiwi / Lemur).
 * ========================================================================== */
(function () {
  'use strict';

  var W = window, D = document;
  var BANNER = @@BANNER@@;
  var DENY = @@DENY@@;
  var BLOB = "@@BLOB@@";
  var MAN_B64 = "@@MANIFEST@@";
  var MX = @@MX@@;
  var BLOCKFRAME = @@IFRAME@@;
  var PAGES = @@PAGES@@;

  var SELF = D.currentScript || D.scripts[D.scripts.length - 1];
  var RAW = SELF ? (SELF.textContent || SELF.text || '') : '';
  var SC = (W.crypto && W.crypto.subtle) ? W.crypto.subtle : null;
  var START = (W.performance && W.performance.now) ? W.performance.now() : Date.now();
  var FAILED = false;

  /* ------------------------------------------------------------------ */
  /* utilities                                                          */
  /* ------------------------------------------------------------------ */
  function b64d(s) {
    var bin = W.atob(s), n = bin.length, out = new Uint8Array(n);
    for (var i = 0; i < n; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function u8(s) {
    if (W.TextEncoder) return new W.TextEncoder().encode(s);
    var out = [], i, c;
    for (i = 0; i < s.length; i++) {
      c = s.charCodeAt(i);
      if (c < 128) out.push(c);
      else if (c < 2048) out.push(192 | (c >> 6), 128 | (c & 63));
      else if (c < 55296 || c >= 57344) out.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63));
      else {
        i++;
        c = 65536 + (((c & 1023) << 10) | (s.charCodeAt(i) & 1023));
        out.push(240 | (c >> 18), 128 | ((c >> 12) & 63), 128 | ((c >> 6) & 63), 128 | (c & 63));
      }
    }
    return new Uint8Array(out);
  }
  function utf8(b) {
    if (W.TextDecoder) return new W.TextDecoder('utf-8').decode(b);
    var s = '', i = 0, c;
    while (i < b.length) {
      c = b[i++];
      if (c < 128) s += String.fromCharCode(c);
      else if (c < 224) s += String.fromCharCode(((c & 31) << 6) | (b[i++] & 63));
      else if (c < 240) s += String.fromCharCode(((c & 15) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63));
      else {
        var cp = ((c & 7) << 18) | ((b[i++] & 63) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
        cp -= 65536;
        s += String.fromCharCode(55296 + (cp >> 10), 56320 + (cp & 1023));
      }
    }
    return s;
  }
  function cat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }
  function rev(a) {
    var n = a.length, out = new Uint8Array(n);
    for (var i = 0; i < n; i++) out[i] = a[n - 1 - i];
    return out;
  }
  function xorB(a, b) {
    var out = new Uint8Array(a.length), n = b.length;
    for (var i = 0; i < a.length; i++) out[i] = a[i] ^ b[i % n];
    return out;
  }
  function hex(n) {
    var s = '', chars = '0123456789abcdef', buf = new Uint8Array(n);
    if (W.crypto && W.crypto.getRandomValues) W.crypto.getRandomValues(buf);
    else for (var j = 0; j < n; j++) buf[j] = (Math.random() * 256) | 0;
    for (var i = 0; i < n; i++) s += chars.charAt(buf[i] >> 4) + chars.charAt(buf[i] & 15);
    return s;
  }
  function hexOf(b) {
    var s = '', c = '0123456789abcdef';
    for (var i = 0; i < b.length; i++) s += c.charAt(b[i] >> 4) + c.charAt(b[i] & 15);
    return s;
  }
  function rd16(b, o) { return (b[o] | (b[o + 1] << 8)) >>> 0; }
  function rd32le(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function progress(p, msg) {
    var bar = D.getElementById('pbar'), txt = D.getElementById('pmsg');
    if (bar) bar.style.width = Math.max(0, Math.min(100, p)) + '%';
    if (txt && msg) txt.textContent = msg;
  }

  /* ------------------------------------------------------------------ */
  /* page replacement                                                   */
  /* ------------------------------------------------------------------ */
  function render(html) {
    try { D.open(); D.write(html); D.close(); return true; } catch (e) { }
    try { D.documentElement.innerHTML = html; } catch (e2) { }
    return false;
  }
  function creditPage() {
    if (FAILED) return;
    FAILED = true;
    render(PAGES.credit);
  }
  function denyPage() {
    if (FAILED) return;
    FAILED = true;
    try { D.documentElement.style.display = 'none'; } catch (e) { }
    var shown = false;
    setTimeout(function () { if (!shown) { shown = true; render(PAGES.fallback); } }, 900);
    try {
      if (W.top !== W.self) W.top.location.href = DENY;
      else W.location.replace(DENY);
    } catch (e) { }
  }
  function dead(msg) {
    if (FAILED) return;
    FAILED = true;
    var page = PAGES.offline;
    if (msg) {
      page = page.replace('<div class="code">',
        '<div style="color:#ffb3c0;font-size:13px;line-height:1.6;margin-top:16px;text-align:left">' + msg + '</div><div class="code">');
    }
    render(page);
  }

  /* ------------------------------------------------------------------ */
  /* 0. credit banner (bound to the decoder)                            */
  /* ------------------------------------------------------------------ */
  if (RAW.indexOf(BANNER) !== 0) {
    return creditPage();
  }

  /* ------------------------------------------------------------------ */
  /* 1. environment gates                                               */
  /* ------------------------------------------------------------------ */
  if (location.protocol === 'file:') return dead();
  if (!SC) return render(PAGES.https);

  var UA = navigator.userAgent || '';
  var EARLY_BOT = navigator.webdriver === true ||
    /HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium|Electron\/|Nightmare|jsdom\/|WebDriver/i.test(UA) ||
    /curl\/|Wget\/|python-|Go-http-client|node-fetch|axios\/|okhttp|Java\/|libwww|scrapy|aiohttp|httpclient/i.test(UA);

  if (BLOCKFRAME && W.top !== W.self) {
    try { W.top.location.href = DENY; } catch (e) { }
    setTimeout(function () { if (!FAILED) { FAILED = true; render(PAGES.fallback); } }, 350);
    return;
  }
  if (EARLY_BOT) { return denyPage(); }

  /* ------------------------------------------------------------------ */
  /* 2. manifest                                                        */
  /* ------------------------------------------------------------------ */
  var MAN;
  try {
    MAN = JSON.parse(utf8(xorB(b64d(MAN_B64), MX)));
  } catch (e) {
    return dead('Secure manifest could not be read. The page must be served by PHP from its original server.');
  }
  if (!MAN || !MAN.vm || !MAN.pbkdf2 || !MAN.content || !MAN.sess || !MAN.sess.t) {
    return dead('Secure manifest is incomplete. Re-upload the generated index.php.');
  }
  progress(6, 'checking shield integrity…');

  /* ------------------------------------------------------------------ */
  /* 3. WebCrypto helpers                                               */
  /* ------------------------------------------------------------------ */
  function digest(bytes) {
    return SC.digest('SHA-256', bytes).then(function (b) { return new Uint8Array(b); });
  }
  function mac(keyRaw, msg) {
    return SC.importKey('raw', keyRaw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      .then(function (k) { return SC.sign('HMAC', k, msg); })
      .then(function (b) { return new Uint8Array(b); });
  }
  function gcm(keyRaw, iv, ctAndTag) {
    return SC.importKey('raw', keyRaw, { name: 'AES-GCM' }, false, ['decrypt'])
      .then(function (k) {
        return SC.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, k, ctAndTag);
      }).then(function (b) { return new Uint8Array(b); });
  }

  /* ------------------------------------------------------------------ */
  /* 4. GVH-VM layer (mirrors src/lib/crypt_build.php)                  */
  /* ------------------------------------------------------------------ */
  function mul32(a, b) { return Math.imul(a, b) >>> 0; }
  function rotl32(x, r) { r &= 31; return r ? (((x << r) | (x >>> (32 - r))) >>> 0) : (x >>> 0); }
  function vmX(data, seed, prog, rounds) {
    var s = new Array(8), i;
    for (i = 0; i < 8; i++) s[i] = rd32le(seed, i * 4);
    var plen = prog.length >> 1;
    var out = new Uint8Array(data.length);
    var nBlocks = Math.ceil(data.length / 32), n, r, p, ins, op, a, b, tmp, w, pos;
    var word = new Uint8Array(32);
    for (n = 0; n < nBlocks; n++) {
      s[0] = (s[0] ^ n) >>> 0;
      s[6] = (s[6] + n) >>> 0;
      for (r = 0; r < rounds; r++) {
        for (p = 0; p < plen; p++) {
          ins = prog[p * 2] | (prog[p * 2 + 1] << 8);
          op = ins & 7; a = (ins >> 3) & 7; b = (ins >> 6) & 7;
          if (op === 0) s[a] = (s[a] + s[b]) >>> 0;
          else if (op === 1) s[a] = (s[a] ^ s[b]) >>> 0;
          else if (op === 2) s[a] = rotl32(s[a], 1 + (b % 31));
          else if (op === 3) s[a] = mul32(s[a], (2 * s[b] + 1) >>> 0);
          else if (op === 4) { tmp = s[a]; s[a] = s[b]; s[b] = tmp; }
          else if (op === 5) s[a] = (s[a] + 0x9E3779B9 + n) >>> 0;
          else if (op === 6) s[a] = (s[a] ^ mul32(n, 0x85EBCA6B)) >>> 0;
          else s[a] = (s[a] + (s[(a + 1) & 7] ^ n)) >>> 0;
        }
      }
      for (i = 0; i < 8; i++) {
        w = s[i];
        word[i * 4] = w & 255; word[i * 4 + 1] = (w >>> 8) & 255;
        word[i * 4 + 2] = (w >>> 16) & 255; word[i * 4 + 3] = (w >>> 24) & 255;
      }
      for (i = 0; i < 32; i++) {
        pos = n * 32 + i;
        if (pos < data.length) out[pos] = data[pos] ^ word[i];
      }
    }
    return out;
  }

  /* ------------------------------------------------------------------ */
  /* 5. decrypt the defence engine                                      */
  /* ------------------------------------------------------------------ */
  var passSeed = MAN.core + '|' + MAN.site + '|' + MAN.pbkdf2.salt + '|' + BANNER;
  var vmKey = b64d(MAN.vm.k), vmNonce = b64d(MAN.vm.n), vmProg = b64d(MAN.vm.p);

  progress(12, 'unsealing defence engine…');

  function decryptEngine() {
    return digest(cat(vmKey, vmNonce)).then(function (seed) {
      var outer = vmX(b64d(BLOB), seed, vmProg, MAN.vm.r);
      var salt = outer.subarray(0, 16), iv = outer.subarray(16, 28), tag = outer.subarray(28, 44);
      var body = outer.subarray(44);
      return digest(u8(passSeed)).then(function (pass) {
        return SC.importKey('raw', pass, { name: 'PBKDF2' }, false, ['deriveKey']).then(function (pk) {
          return SC.deriveKey({ name: 'PBKDF2', salt: salt, iterations: MAN.pbkdf2.iter, hash: 'SHA-256' },
            pk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        }).then(function (key) {
          return SC.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, cat(body, tag));
        });
      }).then(function (buf) { return new Uint8Array(buf); });
    }).then(function (reversed) {
      return parseEngine(rev(reversed));
    });
  }

  function parseEngine(inner) {
    var magic = String.fromCharCode(inner[0], inner[1], inner[2], inner[3]);
    if (magic !== 'GVH1') throw new Error('bad engine header');
    var count = rd16(inner, 4);
    var plainLen = rd32le(inner, 6);
    var o = 10, jobs = [];
    for (var i = 0; i < count; i++) {
      var plen = rd32le(inner, o), clen = rd32le(inner, o + 4);
      var iv = inner.subarray(o + 8, o + 20);
      var tag = inner.subarray(o + 20, o + 36);
      var ct = inner.subarray(o + 36, o + 36 + clen);
      var meta = MAN.chunks[i];
      if (!meta) throw new Error('engine chunk metadata missing');
      jobs.push(decInner(meta, iv, ct, tag, i, plen));
      o += 36 + clen;
    }
    return Promise.all(jobs).then(function (list) {
      list.sort(function (a, b) { return a.i - b.i; });
      var b64 = '';
      for (var q = 0; q < list.length; q++) b64 += list[q].s;
      if (b64.length !== plainLen) throw new Error('engine length mismatch ' + b64.length + '!=' + plainLen);
      var bytes = b64d(b64);
      return digest(bytes).then(function (h) {
        if (hexOf(h) !== String(MAN.srcHash).toLowerCase()) throw new Error('engine checksum mismatch');
        return utf8(bytes);
      });
    });
  }
  function keyOf(b64Key) {
    return digest(b64d(b64Key));
  }
  function decInner(meta, iv, ct, tag, index, plen) {
    return keyOf(meta.k).then(function (k) { return gcm(k, iv, cat(ct, tag)); }).then(function (p) {
      var s = utf8(p);
      if (s.length !== plen) throw new Error('engine chunk truncated');
      return { i: index, s: s };
    });
  }

  /* ------------------------------------------------------------------ */
  /* 6. content chunks (one API call per AES key)                       */
  /* ------------------------------------------------------------------ */
  function baseURL() {
    return location.protocol + '//' + location.host + location.pathname;
  }
  function apiURL(api) {
    var n = hex(12);
    return mac(b64d(MAN.sess.k), u8(api + '|' + n)).then(function (sig) {
      var url = baseURL() + '?' + MAN.gw + '=' + encodeURIComponent(api) +
        '&' + MAN.pn + '=' + n + '&' + MAN.ps + '=' + hexOf(sig) +
        '&' + MAN.pt + '=' + encodeURIComponent(MAN.sess.t);
      return { u: url, n: n };
    });
  }
  function xhr(url) {
    return new Promise(function (resolve, reject) {
      var x = new XMLHttpRequest();
      x.open('GET', url, true);
      x.timeout = 25000;
      x.setRequestHeader('X-GVH-S', MAN.sess.t);
      x.setRequestHeader('Accept', 'application/json');
      x.onreadystatechange = function () {
        if (x.readyState !== 4) return;
        if (x.status >= 200 && x.status < 300) {
          try { resolve(JSON.parse(x.responseText)); } catch (e) { reject(new Error('bad-json')); }
        } else reject(new Error('http-' + x.status));
      };
      x.onerror = function () { reject(new Error('network')); };
      x.ontimeout = function () { reject(new Error('timeout')); };
      try { x.send(null); } catch (e) { reject(e); }
    });
  }
  function unseal(pack, api, nonce) {
    // server: hash('sha256', rawSessionKey . '|' . api . '|' . nonce . '|r')
    return digest(cat(b64d(MAN.sess.k), u8('|' + api + '|' + nonce + '|r'))).then(function (stream) {
      return JSON.parse(utf8(xorB(b64d(pack), stream)));
    });
  }
  function loadChunk(i, retry) {
    var api = MAN.content.apis[i];
    return apiURL(api).then(function (info) {
      return xhr(info.u).then(function (res) {
        if (!res || !res.p) throw new Error('sealed-payload-missing');
        return unseal(res.p, api, info.n);
      });
    }).then(function (obj) {
      if (!obj || obj.n !== i) throw new Error('chunk-order-violation');
      return keyOf(obj.k).then(function (k) {
        return gcm(k, b64d(obj.iv), cat(b64d(obj.ct), b64d(obj.tg)));
      });
    }).then(function (bytes) {
      return utf8(bytes);
    }).catch(function (err) {
      if (retry > 0) {
        return new Promise(function (r) { setTimeout(r, 320); }).then(function () { return loadChunk(i, retry - 1); });
      }
      throw err;
    });
  }

  progress(32, 'requesting chunk keys…');
  var total = MAN.content.n;
  var got = new Array(total), finished = 0, next = 0, parts = [], runners = [];
  var pool = Math.min(4, total);

  function pump() {
    if (next >= total) return Promise.resolve();
    var i = next++;
    return loadChunk(i, 2).then(function (text) {
      parts[i] = text;
      finished++;
      progress(32 + Math.round((finished / total) * 62), 'decrypting ' + finished + '/' + total + ' secure chunks…');
      return pump();
    });
  }
  for (var r = 0; r < pool; r++) runners.push(pump());

  decryptEngine().then(function (engineSrc) {
    if (!engineSrc || engineSrc.length < 200) throw new Error('engine-empty');
    return Promise.all(runners).then(function () {
      progress(96, 'assembling protected page…');
      var html = utf8(b64d(parts.join('')));
      if (MAN.hb && html.indexOf(MAN.hb) < 0) throw new Error('credit-missing');
      html = html.replace(/__GVH_A_([a-f0-9]{12,64})__/g, function (m, id) {
        return baseURL() + '?' + MAN.ap + '=' + id + '&' + MAN.pt + '=' + encodeURIComponent(MAN.sess.t);
      });
      var injection = '<scr' + 'ipt>' + engineSrc + '</scr' + 'ipt>';
      var closeAt = html.toLowerCase().lastIndexOf('</body>');
      var finalHtml = closeAt >= 0 ? (html.slice(0, closeAt) + injection + html.slice(closeAt)) : (html + '\n' + injection);
      try { W[MAN.guard] = 1; } catch (e) { }
      try { W.sessionStorage.setItem('gvh_render', String(START)); } catch (e) { }
      progress(100, 'shield online');
      try {
        D.open();
        D.write(finalHtml);
        D.close();
      } catch (e) {
        dead('This browser refused to render the sealed document.');
      }
    });
  }).catch(function (err) {
    var m = String(err && err.message || err);
    if (W.__GVH_DEBUG) { try { W.console.log('GVH-ERR', m); } catch (e) { } }
    var msg = 'The secure relay did not answer. This page only unlocks from its original server (PHP hosting required).';
    if (/http-403/.test(m)) msg = 'This session is not authorised. Reload the page from its original address.';
    if (/http-404/.test(m)) msg = 'Secure assets are missing on the server. Re-upload the generated files.';
    if (/checksum|mismatch|truncated|metadata|credit-missing/.test(m)) return creditPage();
    dead(msg);
  });

  // decoy traffic: fake key APIs are called too, so traffic analysis is useless
  setTimeout(function () {
    try {
      var fakes = MAN.fakes || [];
      for (var i = 0; i < 2 && fakes.length; i++) {
        (function (fav) {
          apiURL(fav).then(function (info) { return xhr(info.u); }).then(function () { }, function () { });
        })(fakes[(Math.random() * fakes.length) | 0]);
      }
    } catch (e) { }
  }, 60);

  progress(20, 'verifying shield signature…');

})();
