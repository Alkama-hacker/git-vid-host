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
  if (FL.iframe && W.top !== W.self) {
    return kill('frame');
  }
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
    var BRIDGE = W.ReactNativeWebView || W.Android || W.AndroidBridge || W.__TAURI__ || W.__TAURI_IPC__ || W.cordova;
    var IOS_WEBVIEW = /iPhone|iPad|iPod/.test(UA) && /AppleWebKit/.test(UA) && !/Safari\//.test(UA);
    if (WEBVIEW_UA.test(UA) || BRIDGE || IOS_WEBVIEW) {
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
    if (W.__REACT_DEVTOOLS_GLOBAL_HOOK__ || W.__VUE_DEVTOOLS_GLOBAL_HOOK__) { return kill('devtools'); }
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
      if (FL.iframe && W.top !== W.self) return kill('frame');
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
    setTimeout(devtoolsTick, 1200);
  }

  if (D.readyState === 'loading') {
    D.addEventListener('DOMContentLoaded', boot, false);
  } else {
    boot();
  }
})();
