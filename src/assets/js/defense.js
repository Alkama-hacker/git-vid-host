/* ==========================================================================
 *  GVH SHIELD :: defence engine
 *  --------------------------------------------------------------------------
 *  This file is never shipped in readable form: it travels inside a five-layer
 *  client-key envelope (base64 -> 50 chunks -> per-chunk AES-256-GCM ->
 *  reverse -> PBKDF2-SHA256/AES-GCM -> GVH-VM) and is injected only after the
 *  page payload has been unlocked.
 *
 *  Design rules:
 *    - NO `debugger` loops / timing traps. Ever.
 *    - the host page must keep working: every listener is passive unless it
 *      protects a specific shortcut or gesture.
 *    - every detector is wrapped, nothing is allowed to throw into user code.
 * ========================================================================== */
(function () {
  'use strict';

  var CFG = @@CFG@@;
  var W = window, D = document, NAV = navigator;
  var DEAD = false, SCRIPT = D.currentScript || null;
  var BANNER = CFG.banner, DENY = CFG.deny, P = CFG.pages, FL = CFG.flags || {};
  var BRIDGE = null;
  try { BRIDGE = W.__GVH_BRIDGE__ || null; } catch (e) { BRIDGE = null; }
  var OWN = !!(BRIDGE && BRIDGE.k === CFG.hostKey);
  var UA = (NAV.userAgent || '');
  var DESKTOP = !/Mobi|Android|iPhone|iPad|iPod|Mobile Safari/i.test(UA);
  var MO = null, TIMERS = [], SCORE = 0, PROBE = 0, CHROME_OPEN = false;
  var LOADED = false, BOOT_AT = Date.now();

  /* ------------------------------------------------------------------ */
  /* page replacement                                                   */
  /* ------------------------------------------------------------------ */
  function paint(html) {
    try {
      D.open(); D.write(html); D.close();
      return;
    } catch (e) { }
    try {
      D.documentElement.innerHTML = html;
    } catch (e2) { }
  }

  function credit() {
    if (DEAD) return;
    DEAD = true;
    stopAll();
    paint(P.credit);
  }

  function kill(reason) {
    if (DEAD) return;
    DEAD = true;
    stopAll();
    try { if (W.console && W.console.clear) W.console.clear(); } catch (e) { }
    // clear the screen first: even when the redirect is blocked the visitor
    // must not be able to read the protected design
    try { D.documentElement.style.display = 'none'; } catch (e) { }
    // Inside the shield frame the *shell* owns the document: it wipes the
    // frame, paints the fallback and navigates the real address bar.
    if (OWN && BRIDGE && typeof BRIDGE.deny === 'function') {
      try { D.documentElement.innerHTML = ''; } catch (e) { }
      try { D.body.innerHTML = ''; } catch (e2) { }
      try { BRIDGE.deny(reason); return; } catch (e3) { }
    }
    var shown = false;
    var t = setTimeout(function () {
      if (!shown) { shown = true; paint(P.fallback); }
    }, 900);
    try {
      if (W.top !== W.self) {
        W.top.location.href = DENY;
      } else {
        W.location.replace(DENY);
      }
    } catch (e) {
      clearTimeout(t);
      if (!shown) { shown = true; paint(P.fallback); }
    }
  }

  function stopAll() {
    for (var i = 0; i < TIMERS.length; i++) { try { clearInterval(TIMERS[i]); } catch (e) { } }
    TIMERS = [];
    if (MO) { try { MO.disconnect(); } catch (e) { } MO = null; }
  }

  /* ------------------------------------------------------------------ */
  /* 0. credit banner integrity                                         */
  /* ------------------------------------------------------------------ */
  if (!SCRIPT || (SCRIPT.textContent || '').indexOf(BANNER) !== 0) {
    return credit();
  }
  if (W[CFG.guard] === 2) {
    // already running (double injection)
    return;
  }
  W[CFG.guard] = 2;

  /* ------------------------------------------------------------------ */
  /* 1. environment gates (hard signals -> immediate lock)              */
  /* ------------------------------------------------------------------ */
  // opaque origin == sandboxed by somebody else
  try { if (String(W.origin) === 'null') return kill('sandbox'); } catch (e) { return kill('sandbox'); }
  try { if (String(location.origin) === 'null') return kill('sandbox'); } catch (e) { return kill('sandbox'); }
  try {
    var FE = W.frameElement;
    if (FE && FE.getAttribute) {
      var FE_TAG = String(FE.tagName || '').toUpperCase();
      if (FE_TAG === 'IFRAME' && FE.hasAttribute('sandbox')) return kill('sandbox');
    }
  } catch (e2) { }
  if (FL.iframe && !OWN && W.top !== W.self) {
    return kill('frame');
  }
  // an outer document that re-parents our frame is an embed attempt
  if (!OWN && W.frameElement) { return kill('frame'); }
  if (NAV.webdriver === true) {
    return kill('automation');
  }
  if (/HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium|Nightmare|Electron\/|jsdom\/|WebDriver/i.test(UA)) {
    return kill('automation');
  }
  if (/curl\/|Wget\/|python-|Python-urllib|Go-http-client|node-fetch|axios\/|okhttp|libwww|scrapy|aiohttp|httpclient|requests\//i.test(UA)) {
    return kill('automation');
  }
  if (CFG.uaExtra) {
    try { if (new RegExp(CFG.uaExtra, 'i').test(UA)) return kill('ua'); } catch (e) { }
  }
  // desktop-extension mobile browsers (Kiwi / Lemur / Mises / Yandex alpha...)
  if (FL.devtools && /Kiwi|Lemur|Mises|Yandex\/|YaBrowser/i.test(UA)) {
    return kill('vm-devtools');
  }
  if (FL.webview) {
    var WEBVIEW_UA = /;\s*wv\)|Version\/4\.\d|FBAN|FBAV|FB_IAB|Instagram|Line\/|Snapchat|MicroMessenger|GSA\/|Twitter|LinkedInApp|Pinterest|WhatsApp|WebView|Electron\/|Cordova|Capacitor/i;
    var NATIVE = W.ReactNativeWebView || W.Android || W.AndroidBridge || W.__TAURI__ || W.__TAURI_IPC__ || W.cordova;
    var IOS_WEBVIEW = /iPhone|iPad|iPod/.test(UA) && /AppleWebKit/.test(UA) && !/Safari\//.test(UA);
    if (WEBVIEW_UA.test(UA) || NATIVE || IOS_WEBVIEW) {
      return kill('webview');
    }
  }

  /* ------------------------------------------------------------------ */
  /* 2. runtime hooks / debugging tools                                 */
  /* ------------------------------------------------------------------ */
  function globalsCheck() {
    if (DEAD) return;
    if (W.eruda || W.__eruda || W.ERUDA || W.vConsole || W.__vconsole) { return kill('devtools'); }
    if (W.callPhantom || W._phantom || W.__nightmare || W.phantom) { return kill('automation'); }
    if (W.domAutomation || W.domAutomationController || W.__selenium_unwrapped || W.__webdriver_evaluate ||
      W.__driver_evaluate || W.__fxdriver_evaluate || W._selenium || W.__selenium) {
      return kill('automation');
    }
    if (W.__REACT_DEVTOOLS_GLOBAL_HOOK__ || W.__VUE_DEVTOOLS_GLOBAL_HOOK__ || W.__SVELTE_DEVTOOLS__ || W.__NUXT__DEVTOOLS__) {
      return kill('devtools');
    }
    if (W.__nightmare || W._WEBDRIVER_ELEM_CACHE || W.__webdriver_script_fn || W.$chrome_asyncScriptInfo || W.$cdc_asdjflasutopfhvcZLmcfl_) {
      return kill('automation');
    }
    var ids = ['eruda', 'eruda-dev-tools', 'eruda-entry-btn', '__vconsole', 'vconsole', 'vconsole_btn'];
    for (var i = 0; i < ids.length; i++) {
      if (D.getElementById(ids[i])) { return kill('devtools'); }
    }
    try {
      var names = Object.getOwnPropertyNames(W);
      for (var j = 0; j < names.length; j++) {
        if (/^(cdc_|\$wdc_|__cdc|__puppeteer|__playwright|__nightmare)/.test(names[j])) {
          return kill('automation');
        }
      }
    } catch (e) { }
  }

  function nativeCheck() {
    if (DEAD || !FL.native) return;
    var natives = [];
    try {
      if (W.crypto && W.crypto.subtle && W.crypto.subtle.decrypt) natives.push(W.crypto.subtle.decrypt);
      if (W.crypto && W.crypto.getRandomValues) natives.push(W.crypto.getRandomValues);
      natives.push(Function.prototype.toString);
    } catch (e) { }
    for (var i = 0; i < natives.length; i++) {
      try {
        if (!/\[native code\]/.test(Function.prototype.toString.call(natives[i]))) {
          return kill('hooked');
        }
      } catch (e) { }
    }
  }

  function headlessCheck() {
    if (DEAD) return;
    var pts = 0;
    try {
      // WebGL renderer fingerprint
      var c = D.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (gl) {
        var dbg = gl.getExtension('WEBGL_debug_renderer_info');
        if (dbg) {
          var renderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '');
          if (/SwiftShader|llvmpipe|Mesa OffScreen|ANGLE \(Google, Vulkan.*SwiftShader|Software Rasterizer/i.test(renderer)) {
            return kill('headless');
          }
        }
      }
    } catch (e) { }
    try {
      if (DESKTOP && NAV.plugins && NAV.plugins.length === 0) pts++;
      if (NAV.languages && NAV.languages.length === 0) pts++;
      if (W.outerWidth === 0 || W.outerHeight === 0) pts++;
      if (!W.chrome && /Chrome\//.test(UA) && DESKTOP) pts++;
      if (NAV.hardwareConcurrency === 1) pts++;
      if (pts >= 3) return kill('headless');
    } catch (e) { }
  }


  /* ------------------------------------------------------------------ */
  /* 2b. hook / tamper detection                                        */
  /* ------------------------------------------------------------------ */
  /*  Every serious tool that inspects a page (extensions, devtools
      injectors, eruda-style consoles, automation frameworks) works by
      *replacing or wrapping built-ins*: Function.prototype.toString to hide
      itself, Object.defineProperty to trap property reads, XHR/fetch to read
      traffic, getAttribute/innerHTML to watch the DOM, crypto to steal keys.

      Detection trick: spawn a hidden same-origin frame - a fresh JS realm -
      and read the *true* source of each built-in with THAT realm's
      Function.prototype.toString. A wrapper is a different function object,
      so its real source differs; and a hook that fakes toString() in our
      realm cannot fake the answer produced by another realm's intrinsic.

      Two tiers:
        tier 1 (hard)  - built-ins that no legitimate page replaces.
        tier 2 (soft)  - built-ins that analytics/SPA code legitimately wraps;
                         only a *change after boot* counts, 3+ changes kill.
   */
  var CLEAN = null, TABLE = [], HARD = 0, SOFT = 0;

  var WATCH_HARD = [
    'Function.prototype.toString', 'Function.prototype.call',
    'Function.prototype.apply', 'Function.prototype.bind',
    'Object.defineProperty', 'Object.getOwnPropertyDescriptor',
    'Object.getOwnPropertyNames', 'Object.getPrototypeOf',
    'Object.defineProperties', 'Object.freeze',
    'Reflect.apply', 'Reflect.get', 'Reflect.defineProperty',
    'JSON.parse', 'JSON.stringify',
    'Document.prototype.createElement', 'Document.prototype.querySelector',
    'Document.prototype.querySelectorAll', 'Document.prototype.getElementById',
    'Document.prototype.write',
    'Element.prototype.getAttribute', 'Element.prototype.setAttribute',
    'Element.prototype.getElementsByTagName',
    'Node.prototype.appendChild', 'Node.prototype.removeChild',
    'Node.prototype.insertBefore', 'Node.prototype.replaceChild',
    'EventTarget.prototype.addEventListener',
    'EventTarget.prototype.removeEventListener',
    'EventTarget.prototype.dispatchEvent',
    'HTMLIFrameElement.prototype.contentWindow',
    'HTMLIFrameElement.prototype.contentDocument',
    'History.prototype.pushState', 'History.prototype.replaceState',
    'Storage.prototype.getItem', 'Storage.prototype.setItem',
    'MouseEvent.prototype.preventDefault'
  ];
  var WATCH_SOFT = [
    // surfaces that analytics/SPA code legitimately wraps -> only a change
    // *after* boot counts, and three of them at once is a red flag.
    'fetch', 'XMLHttpRequest.prototype.open', 'XMLHttpRequest.prototype.send',
    'XMLHttpRequest.prototype.setRequestHeader',
    'window.eval', 'eval', 'window.Function',
    'atob', 'btoa', 'URL.createObjectURL', 'window.open',
    'navigator.sendBeacon', 'Location.prototype.replace', 'Location.prototype.assign'
  ];


  function src(ts, fn) {
    try { return ts.call(fn); } catch (e) { return null; }
  }

  /* walk an own-descriptor chain so accessors are inspected without firing */
  function dig(win, path, gopd, gop) {
    var parts = String(path).split('.'), cur = win, i;
    for (i = 0; i < parts.length; i++) {
      if (cur == null) return null;
      var name = parts[i];
      if (name === 'window') { cur = win; continue; }
      var chain = cur, d = null, guard = 0;
      while (chain && guard++ < 24) {
        try { d = gopd(chain, name); } catch (e) { d = null; }
        if (d) break;
        try { chain = gop ? gop(chain) : null; } catch (e2) { chain = null; }
      }
      if (!d) return null;
      if (d.get || d.set) {
        if (i === parts.length - 1) return d.get || d.set;
        if (!d.get) return null;
        try { cur = d.get.call(cur); } catch (e3) { return null; }
        continue;
      }
      cur = d.value;
    }
    return cur;
  }

  function cleanRealm() {
    var f = null, w = null;
    try {
      f = D.createElement('iframe');
      f.setAttribute('data-gvh', '1');
      f.setAttribute('aria-hidden', 'true');
      f.setAttribute('tabindex', '-1');
      f.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:0;height:0;border:0;' +
        'opacity:0;pointer-events:none';
      (D.body || D.documentElement).appendChild(f);
      w = f.contentWindow;
    } catch (e) { return null; }
    if (!w || !w.Function || !w.Object) return null;
    var ts = w.Function.prototype.toString;
    // a fresh realm must own *different* intrinsic objects; if both realms
    // share them, someone rewired the frame (or we were sealed in a proxy)
    if (!ts || ts === W.Function.prototype.toString) return null;
    if (w.Object === W.Object || w.JSON === W.JSON) return null;
    return {
      w: w, f: f, ts: ts,
      gopd: w.Object.getOwnPropertyDescriptor,
      gop: w.Object.getPrototypeOf
    };
  }

  function buildWatch() {
    CLEAN = cleanRealm();
    if (!CLEAN) return;
    var list = [{ a: WATCH_HARD, t: 1 }, { a: WATCH_SOFT, t: 2 }];
    for (var l = 0; l < list.length; l++) {
      for (var i = 0; i < list[l].a.length; i++) {
        var p = list[l].a[i];
        var ref = dig(CLEAN.w, p, CLEAN.gopd, CLEAN.gop);
        if (!ref) continue;                       // not a built-in here: skip
        var truth = src(CLEAN.ts, ref);
        if (!truth) continue;
        var mine = dig(W, p, Object.getOwnPropertyDescriptor, Object.getPrototypeOf);
        TABLE.push({ p: p, t: list[l].t, truth: truth, base: mine ? src(CLEAN.ts, mine) : null });
      }
    }
  }

  function hookTick() {
    if (DEAD || !FL.hooks || !CLEAN) return;
    var hard = '', soft = 0, softFirst = '';
    for (var i = 0; i < TABLE.length; i++) {
      var it = TABLE[i];
      var fn = dig(W, it.p, Object.getOwnPropertyDescriptor, Object.getPrototypeOf);
      if (!fn) continue;
      var now = src(CLEAN.ts, fn);
      if (!now) continue;
      if (it.t === 1) {
        if (now !== it.truth) { hard = it.p; break; }
      } else if (it.base && now !== it.base) {
        soft++;
        if (!softFirst) softFirst = it.p;
      }
    }
    if (hard) { HARD++; return kill('hook:' + hard); }
    if (soft) { SOFT = soft; }
    if (soft >= 3) return kill('hooks:' + softFirst);
  }

  // the watch lists above are assigned here, so the scan is armed here too
  buildWatch();

  /* ------------------------------------------------------------------ */
  /* 3. DOM injection / bookmarklet detection                           */
  /* ------------------------------------------------------------------ */
  function sameOrigin(u) {
    try {
      var a = D.createElement('a');
      a.href = u;
      return a.protocol + '//' + a.host === location.protocol + '//' + location.host;
    } catch (e) {
      return false;
    }
  }

  function watchDom() {
    if (!FL.inject || !W.MutationObserver) return;
    try {
      MO = new W.MutationObserver(function (muts) {
        if (DEAD) return;
        // The website itself is still booting: never punish its own bootstrap.
        // The host page must keep working, so same-origin scripts/frames are
        // always allowed and everything is ignored until the page has loaded.
        var late = LOADED && (Date.now() - BOOT_AT) > 900;
        for (var i = 0; i < muts.length; i++) {
          var m = muts[i];
          if (m.type === 'attributes') {
            var t = m.target;
            if (!t || t.nodeType !== 1) continue;
            if (t === SCRIPT || t.hasAttribute('data-gvh')) continue;
            if (t.tagName === 'SCRIPT') return kill('inject');
            if (t.tagName === 'IFRAME' && FL.iframe) return kill('frame');
            if (late && t.getAttribute && /^javascript:/i.test(t.getAttribute('href') || '')) {
              return kill('inject');
            }
            continue;
          }
          var nodes = m.addedNodes || [];
          for (var j = 0; j < nodes.length; j++) {
            var n = nodes[j];
            if (!n || n.nodeType !== 1) continue;
            if (n.getAttribute && n.getAttribute('data-gvh') !== null) continue;
            var tag = n.tagName;
            if (tag === 'OBJECT' || tag === 'EMBED') return kill('inject');
            if (tag === 'SCRIPT') {
              if (FL.dynamic || !late) continue;
              var src = n.getAttribute('src') || '';
              if (src && sameOrigin(src)) continue;
              return kill('inject');
            }
            if (tag === 'IFRAME') {
              if (!FL.iframe || FL.dynamic || !late) continue;
              var isrc = n.getAttribute('src') || '';
              if (isrc && sameOrigin(isrc)) continue;
              return kill('frame');
            }
            try {
              if (n.querySelector && n.querySelector('object,embed')) {
                var bad = n.querySelector('object,embed');
                if (!bad.hasAttribute('data-gvh')) return kill('inject');
              }
            } catch (e) { }
          }
        }
      });
      MO.observe(D.documentElement, {
        childList: true, subtree: true, attributes: true,
        attributeFilter: ['contenteditable', 'src', 'href']
      });
    } catch (e) { }
  }

  /* ------------------------------------------------------------------ */
  /* 4. devtools heuristics (no debugger loop)                          */
  /* ------------------------------------------------------------------ */
  function devtoolsTick() {
    if (DEAD || !FL.devtools) return;
    try {
      // lazy console evaluation: the getter only runs when a console panel
      // actually formats the object (i.e. developer tools are open)
      var o = {};
      Object.defineProperty(o, 'x', {
        get: function () { PROBE++; return 'gvh'; },
        configurable: false
      });
      try { W.console.log('%c ', 'font-size:0;line-height:0', o); } catch (e) { }
      var dw = W.outerWidth - W.innerWidth;
      var dh = W.outerHeight - W.innerHeight;
      if (DESKTOP && (dw > 320 || dh > 260)) SCORE += 1;
      if (PROBE >= 1) {
        CHROME_OPEN = true;
        return kill('devtools');
      }
      if (SCORE >= 5) {
        CHROME_OPEN = true;
        return kill('devtools');
      }
    } catch (e) { }
  }

  /* ------------------------------------------------------------------ */
  /* 5. input guards                                                    */
  /* ------------------------------------------------------------------ */
  function isField(el) {
    if (!el || el.nodeType !== 1) return false;
    var t = el.tagName;
    return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el.isContentEditable === true;
  }

  function onContext(e) {
    if (!FL.rightclick) return;
    try { e.preventDefault(); } catch (x) { }
    try { e.stopPropagation(); } catch (x) { }
    return false;
  }
  function onSelect(e) {
    if (!FL.select) return;
    if (isField(e.target)) return;
    try { e.preventDefault(); } catch (x) { }
  }
  function onCopy(e) {
    if (!FL.select) return;
    if (isField(e.target) || isField(D.activeElement)) return;
    var sel = W.getSelection ? String(W.getSelection()) : '';
    if (sel) {
      try { e.preventDefault(); } catch (x) { }
      try { if (e.clipboardData) e.clipboardData.setData('text/plain', ''); } catch (x) { }
    }
  }
  function onDrag(e) {
    if (FL.select) { try { e.preventDefault(); } catch (x) { } }
  }
  function onKey(e) {
    if (!FL.shortcuts) return;
    var k = e.key || '', code = e.keyCode || e.which || 0;
    var c = e.ctrlKey || e.metaKey, s = e.shiftKey, a = e.altKey;
    var block = false, nuke = false;
    if (code === 123 || k === 'F12') { block = true; nuke = true; }
    if (c && s && (code === 73 || code === 74 || code === 67 || code === 75 || /^[ijck]$/i.test(k))) { block = true; nuke = true; }
    if (c && !s && !a && (code === 85 || k === 'u' || k === 'U')) { block = true; nuke = true; }
    if (e.metaKey && a && (code === 73 || code === 74 || code === 67 || code === 85 || /^[ijcu]$/i.test(k))) { block = true; nuke = true; }
    if (c && !s && !a && (code === 83 || code === 80 || k === 's' || k === 'S' || k === 'p' || k === 'P')) { block = true; }
    if (block) {
      try { e.preventDefault(); } catch (x) { }
      try { e.stopPropagation(); } catch (x) { }
      if (nuke) kill('devtools-shortcut');
    }
  }

  function installStyle() {
    try {
      var css = '';
      if (FL.select) {
        css += 'html,body{-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;' +
          '-webkit-touch-callout:none}img,a{-webkit-user-drag:none}' +
          'input,textarea,select,[contenteditable="true"]{-webkit-user-select:text;user-select:text}';
      }
      if (FL.print) {
        css += '@media print{html,body{display:none!important}body *{display:none!important}}';
      }
      if (!css) return;
      var st = D.createElement('style');
      st.setAttribute('data-gvh', '1');
      st.type = 'text/css';
      if (st.styleSheet) st.styleSheet.cssText = css;
      else st.appendChild(D.createTextNode(css));
      (D.head || D.documentElement).appendChild(st);
    } catch (e) { }
  }


  /* ------------------------------------------------------------------ */
  /* 5b. navigation: the page lives in a frame, links must not nest     */
  /* ------------------------------------------------------------------ */
  /*  Clicking a link inside the shield frame would load the next page
      *inside* the frame - a frame in a frame. Instead the link is promoted
      to the real window, exactly like a normal website. Same for forms:
      a POST is replayed from the outer document, so it stays a POST.
      Both handlers run in the bubble phase and bail out when the site's
      own code already handled the event, so site behaviour is untouched.
   */
  function absUrl(u) {
    try { return new W.URL(u, D.baseURI).href; } catch (e) { }
    try { var a = D.createElement('a'); a.href = u; return a.href; } catch (e2) { }
    return '';
  }

  function onLink(e) {
    if (DEAD || !OWN || !e || e.defaultPrevented || e.button) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var n = e.target;
    while (n && n.nodeType === 1 && n.tagName !== 'A') n = n.parentNode;
    if (!n || n.nodeType !== 1 || n.tagName !== 'A') return;
    if (n.hasAttribute('download')) return;
    var tgt = String(n.getAttribute('target') || '').toLowerCase();
    if (tgt && tgt !== '_self') return;
    var href = n.getAttribute('href') || '';
    if (!href || href.charAt(0) === '#') return;
    if (/^(javascript|mailto|tel|sms|blob|data|about):/i.test(href)) return;
    var abs = absUrl(href);
    if (!abs || !/^https?:/i.test(abs)) return;
    try { W.top.location.replace(abs); } catch (x) { return; }
    try { e.preventDefault(); } catch (x2) { }
  }

  function onSubmit(e) {
    if (DEAD || !OWN || !e || e.defaultPrevented) return;
    var f = e.target;
    if (!f || f.tagName !== 'FORM' || !BRIDGE) return;
    var abs = absUrl(f.getAttribute('action') || BRIDGE.base || location.href);
    if (!abs || !/^https?:/i.test(abs)) return;
    var method = String(f.getAttribute('method') || 'get').toLowerCase() === 'post' ? 'post' : 'get';
    try {
      var TD = W.top.document;
      var clone = TD.createElement('form');
      clone.method = method;
      clone.action = abs;
      clone.setAttribute('data-gvh', '1');
      clone.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:0;height:0';
      var els = f.elements || [];
      for (var i = 0; i < els.length; i++) {
        var el = els[i], name = el.name, type = String(el.type || '').toLowerCase();
        var tag = String(el.tagName || '').toUpperCase();
        if (!name || el.disabled) continue;
        if (type === 'file' || type === 'submit' || type === 'button' || type === 'image' || type === 'reset') continue;
        if ((type === 'checkbox' || type === 'radio') && !el.checked) continue;
        var value = el.value;
        if (tag === 'SELECT' && el.multiple) value = null;
        if (value == null) continue;
        var inp = TD.createElement('input');
        inp.type = 'hidden';
        inp.name = name;
        inp.value = String(value);
        clone.appendChild(inp);
      }
      (TD.body || TD.documentElement).appendChild(clone);
      clone.submit();
      var ref = clone;
      setTimeout(function () { try { ref.parentNode.removeChild(ref); } catch (x) { } }, 1500);
      try { e.preventDefault(); } catch (x2) { }
    } catch (x3) { }
  }

  /* ------------------------------------------------------------------ */
  /* 6. integrity loop                                                  */
  /* ------------------------------------------------------------------ */
  function integrityTick() {
    if (DEAD) return;
    try {
      if (!SCRIPT || !SCRIPT.parentNode || !D.documentElement.contains(SCRIPT)) {
        return credit();
      }
      if ((SCRIPT.textContent || '').indexOf(BANNER) !== 0) return credit();
      if (D.designMode === 'on') return kill('bookmarklet');
      var b = D.body;
      if (b && b.getAttribute('contenteditable') !== null) return kill('bookmarklet');
      if (D.documentElement.getAttribute('contenteditable') !== null) return kill('bookmarklet');
      globalsCheck();
      nativeCheck();
      hookTick();
      if (OWN) {
        var br = null;
        try { br = W.__GVH_BRIDGE__; } catch (e2) { br = null; }
        if (!br || br.k !== CFG.hostKey) return kill('frame-tamper');
      }
      if (FL.iframe && !OWN && W.top !== W.self) return kill('frame');
    } catch (e) { }
  }

  /* ------------------------------------------------------------------ */
  /* 7. wire it up                                                      */
  /* ------------------------------------------------------------------ */
  function markLoaded() {
    LOADED = true;
    BOOT_AT = Date.now();
  }
  if (D.readyState === 'complete') markLoaded();
  else W.addEventListener('load', markLoaded, false);

  function boot() {
    try {
      globalsCheck();
      nativeCheck();
      hookTick();
      if (OWN) {
        var br = null;
        try { br = W.__GVH_BRIDGE__; } catch (e2) { br = null; }
        if (!br || br.k !== CFG.hostKey) return kill('frame-tamper');
      }
      headlessCheck();
    } catch (e) { }

    if (FL.rightclick) {
      W.addEventListener('contextmenu', onContext, true);
    }
    if (FL.select) {
      W.addEventListener('selectstart', onSelect, true);
      W.addEventListener('copy', onCopy, true);
      W.addEventListener('cut', onCopy, true);
      W.addEventListener('dragstart', onDrag, true);
    }
    if (FL.shortcuts) {
      W.addEventListener('keydown', onKey, true);
    }
    if (FL.print) {
      try { W.addEventListener('beforeprint', function () { kill('print'); }); } catch (e) { }
    }
    installStyle();
    watchDom();
    if (OWN) {
      // bubble phase: site handlers run first and keep their preventDefault
      W.addEventListener('click', onLink, false);
      W.addEventListener('submit', onSubmit, false);
    }

    // a tiny invisible sentinel: removing it is a tamper signal
    try {
      var sentinel = D.createElement('div');
      sentinel.setAttribute('data-gvh', '1');
      sentinel.id = 'gvh-' + CFG.guard;
      sentinel.style.cssText = 'position:fixed;width:1px;height:1px;opacity:0;pointer-events:none;left:-9999px;top:-9999px';
      (D.body || D.documentElement).appendChild(sentinel);
    } catch (e) { }

    TIMERS.push(setInterval(integrityTick, 2600));
    TIMERS.push(setInterval(devtoolsTick, 3800));
    TIMERS.push(setInterval(globalsCheck, 5000));
    if (FL.hooks) {
      TIMERS.push(setInterval(hookTick, 1700));
      setTimeout(hookTick, 700);
    }
    setTimeout(devtoolsTick, 1200);
  }

  if (D.readyState === 'loading') {
    D.addEventListener('DOMContentLoaded', boot, false);
  } else {
    boot();
  }
})();
