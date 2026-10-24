"""
GVH SHIELD :: build pipeline.

Turns a plain HTML page into a single sealed PHP front-controller:

  step 1  AI layout analysis (offline heuristics) - what can live server side
  step 2  visual filter - heavy media stays client-side (streamed, no lag)
  step 3  base64 the client payload
  step 4  split it into many chunks
  step 5  AES-256-GCM per chunk, one 50-char key per chunk, keys stay server side
  step 6  defence engine (right click / devtools / eruda / webview / bots / ...)
  step 7  high obfuscation of the defence engine + credit checker
  step 8  emit index.php + encrypted media vault

Only the Python standard library is used; all AES work is delegated to the PHP
helper (src/lib/crypt_build.php), which is also the runtime's crypto provider,
so there is exactly one implementation of every wire format.
"""
from __future__ import annotations

import base64
import hashlib
import html as html_mod
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urljoin, urlparse, unquote

from . import brand
from . import parser as H

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(os.path.dirname(HERE), "assets")
PHP_HELPER = os.path.join(HERE, "crypt_build.php")
TEMPLATES = os.path.join(ASSETS, "templates")

VERSION = "1.0.0"
GENERATOR = "GVH SHIELD %s" % VERSION


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _read(path, binary=False):
    with open(path, "rb" if binary else "r", encoding=None if binary else "utf-8") as fh:
        return fh.read()


def js_json(obj) -> str:
    """JSON that is always safe inside an inline <script>."""
    s = json.dumps(obj, ensure_ascii=False)
    return (s.replace("<", "\\u003c").replace(">", "\\u003e")
             .replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def esc(text) -> str:
    return html_mod.escape(str(text), quote=True)


def token_hex(nbytes=6):
    return secrets.token_hex(nbytes)


def rand_name(prefix="", nbytes=3):
    first = secrets.choice("abcdefghijklmnopqrstuvwxyz")
    return prefix + first + secrets.token_hex(nbytes)[0:]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


MIME_BY_EXT = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".webp": "image/webp", ".avif": "image/avif", ".svg": "image/svg+xml", ".ico": "image/x-icon",
    ".bmp": "image/bmp", ".mp4": "video/mp4", ".webm": "video/webm", ".ogv": "video/ogg",
    ".mov": "video/quicktime", ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg",
    ".m4a": "audio/mp4", ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
    ".otf": "font/otf", ".eot": "application/vnd.ms-fontobject", ".css": "text/css",
    ".js": "application/javascript", ".mjs": "application/javascript", ".json": "application/json",
    ".txt": "text/plain", ".pdf": "application/pdf", ".zip": "application/zip",
    ".webmanifest": "application/manifest+json", ".xml": "application/xml",
}

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp"}
VIDEO_EXT = {".mp4", ".webm", ".ogv", ".mov", ".m4v"}
AUDIO_EXT = {".mp3", ".wav", ".ogg", ".m4a", ".aac", ".flac"}

LOCAL_SCHEMES = ("file", "")
SKIP_SCHEMES = ("data", "mailto", "tel", "javascript", "blob", "about", "sms", "whatsapp", "intent", "chrome-extension")


def sniff_mime(path, data):
    low = path.lower()
    for ext, mime in MIME_BY_EXT.items():
        if low.endswith(ext):
            # verify a few magic numbers, fall back to extension anyway
            break
    head = data[:64]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] == b"%PDF":
        return "application/pdf"
    if head[4:8] == b"ftyp":
        return "video/mp4"
    if head[:4] == b"wOFF":
        return "font/woff"
    if head[:4] == b"wOF2":
        return "font/woff2"
    if head[:4] == b"OTTO":
        return "font/otf"
    if head[:5] == b"<svg " or head[:4] == b"<svg" or b"<svg" in head[:64]:
        return "image/svg+xml"
    if head[:4] == b"OggS":
        return "audio/ogg"
    if head[:3] == b"ID3":
        return "audio/mpeg"
    for ext, mime in MIME_BY_EXT.items():
        if low.endswith(ext):
            return mime
    return "application/octet-stream"


def kind_of(mime):
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("video/"):
        return "video"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("font/") or mime in ("application/font-woff", "application/vnd.ms-fontobject"):
        return "font"
    if mime == "text/css":
        return "css"
    if mime in ("application/javascript", "text/javascript"):
        return "js"
    return "other"


# --------------------------------------------------------------------------
# PHP crypto bridge
# --------------------------------------------------------------------------
class PhpBridge:
    def __init__(self, php_cmd=None, verbose=False):
        self.mode = os.environ.get("GVH_PHP_MODE", "native")
        self.php = php_cmd or os.environ.get("GVH_PHP") or "php"
        self.bridge = os.environ.get("GVH_PHP_BRIDGE") or os.path.join(
            os.path.dirname(os.path.dirname(HERE)), "tests", "phpwasm_cli.mjs")
        self.verbose = verbose

    def _cmd(self, inp, out):
        if self.mode == "wasm":
            node = os.environ.get("GVH_NODE", "node")
            return [node, self.bridge, "--script", PHP_HELPER, "--in", inp, "--out", out]
        return [self.php, PHP_HELPER, inp, out]

    def run(self, payload, timeout=900):
        tmp = tempfile.mkdtemp(prefix="gvhphp_")
        inp = os.path.join(tmp, "in.json")
        out = os.path.join(tmp, "out.json")
        try:
            with open(inp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
            cmd = self._cmd(inp, out)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            except FileNotFoundError:
                raise RuntimeError(
                    "PHP CLI not found. Install it first:\n"
                    "  Termux : pkg install php\n"
                    "  Debian : sudo apt install php-cli php-openssl\n"
                    "  Or set GVH_PHP=/path/to/php"
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError("PHP crypto helper timed out")
            if proc.returncode != 0 or not os.path.exists(out):
                err = (proc.stderr or proc.stdout or "").strip()
                if os.path.exists(out):
                    try:
                        doc = json.load(open(out, encoding="utf-8"))
                        err = doc.get("error") or err
                    except Exception:
                        pass
                raise RuntimeError("PHP crypto helper failed: %s" % err[:1200])
            with open(out, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            if not doc.get("ok", True):
                raise RuntimeError(doc.get("error", "PHP crypto helper error"))
            return doc
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def available(self):
        try:
            self.run({"op": "ping"}, timeout=180)
            return True, ""
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)


# --------------------------------------------------------------------------
# assets
# --------------------------------------------------------------------------
class Asset:
    __slots__ = ("id", "path", "name", "mime", "kind", "data", "delivery", "cipher",
                 "key", "iv", "refs", "why", "force_route")

    def __init__(self, aid, path, name, mime, kind, data, why=""):
        self.id = aid
        self.path = path
        self.name = name
        self.mime = mime
        self.kind = kind
        self.data = data
        self.delivery = "route"
        self.force_route = False
        self.cipher = {}
        self.key = ""
        self.iv = ""
        self.refs = 0
        self.why = why


class AssetStore:
    def __init__(self, site, base_dir, opts, log=None):
        self.site = site
        self.base_dir = base_dir
        self.opts = opts
        self.log = log or (lambda *a, **k: None)
        self.by_path = {}
        self.assets = []
        self.remote = []
        self.missing = []
        self.data_uris = 0
        self.skipped = []
        self.ap = opts.get("ap", "a")

    def aid(self, path):
        raw = (self.site + "|" + path).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:40]

    def _ensure(self, path, why=""):
        real = os.path.realpath(path)
        if real in self.by_path:
            a = self.by_path[real]
            a.refs += 1
            if why and why not in a.why:
                a.why = (a.why + "," + why).strip(",")
            return a
        try:
            with open(real, "rb") as fh:
                data = fh.read()
        except OSError:
            return None
        mime = sniff_mime(real, data)
        kind = kind_of(mime)
        a = Asset(self.aid(real), real, os.path.basename(real), mime, kind, data, why)
        a.refs = 1
        self.by_path[real] = a
        self.assets.append(a)
        return a

    def add_css(self, path, why="stylesheet"):
        real = os.path.realpath(path)
        if real in self.by_path:
            a = self.by_path[real]
            a.refs += 1
            return a
        try:
            with open(real, "rb") as fh:
                raw = fh.read()
            text = raw.decode("utf-8", "replace")
        except OSError:
            return None
        css_dir = os.path.dirname(real)

        def mapper(url):
            ref = self.resolve(url, css_dir)
            if ref is None:
                return None
            if ref[0] == "inline":
                return data_uri(ref[1])
            if ref[0] == "asset":
                a2 = ref[1]
                return "?%s=%s" % (self.ap, a2.id)
            return None

        text2 = H.rewrite_urls_in_css(text, mapper)
        text2 = re.sub(r"/\*[#@]\s*sourceMappingURL=[^*]*\*/", "", text2)
        data = text2.encode("utf-8")
        a = Asset(self.aid(real), real, os.path.basename(real), "text/css", "css", data, why)
        a.refs = 1
        self.by_path[real] = a
        self.assets.append(a)
        return a

    def add_js(self, path, why="script"):
        real = os.path.realpath(path)
        if real in self.by_path:
            a = self.by_path[real]
            a.refs += 1
            return a
        try:
            raw = open(real, "rb").read()
            text = raw.decode("utf-8", "replace")
        except OSError:
            return None
        text = re.sub(r"//[#@]\s*sourceMappingURL=\S+", "", text)
        data = text.encode("utf-8")
        a = Asset(self.aid(real), real, os.path.basename(real), "application/javascript", "js", data, why)
        a.refs = 1
        self.by_path[real] = a
        self.assets.append(a)
        return a

    def resolve(self, url, base_dir, force_route=False):
        """Return ('asset', Asset) | ('inline', Asset) | ('remote', url) | ('skip', url) | None."""
        if url is None:
            return None
        url = url.strip()
        if not url:
            return None
        low = url.lower()
        if low.startswith("data:"):
            self.data_uris += 1
            return ("skip", url)
        if low.startswith("#") or low.startswith("//") or re.match(r"^[a-z][a-z0-9+.-]*:", low):
            scheme = low.split(":", 1)[0]
            if scheme in ("http", "https"):
                self.remote.append(url)
                return ("remote", url)
            if scheme == "file":
                path = unquote(urlparse(url).path)
            elif scheme in SKIP_SCHEMES:
                return ("skip", url)
            else:
                self.remote.append(url)
                return ("remote", url)
        else:
            path = url.split("#", 1)[0].split("?", 1)[0]
            path = unquote(path)
            if not path:
                return None
            if path.startswith(("/", "\\")):
                path = path.lstrip("/\\")
            path = os.path.join(base_dir, path)

        real = os.path.realpath(path)
        base_real = os.path.realpath(self.base_dir)
        if not (real == base_real or real.startswith(base_real + os.sep)):
            self.missing.append(url)
            return ("skip", url)
        if not os.path.isfile(real):
            self.missing.append(url)
            return ("skip", url)
        ext = os.path.splitext(real)[1].lower()
        if ext == ".css":
            a = self.add_css(real)
        elif ext in (".js", ".mjs"):
            a = self.add_js(real)
        else:
            a = self._ensure(real)
        if a is None:
            self.missing.append(url)
            return ("skip", url)
        if force_route:
            a.force_route = True
            return ("asset", a)
        if a.kind == "image" and len(a.data) <= self.opts.get("inline_limit", 8192):
            return ("inline", a)
        return ("asset", a)

    def plan(self):
        """Decide inline (data: URI in the sealed payload) vs route (streamed
        from the vault).  Visual assets must stay client-side so a weak host
        never stutters on video/large images."""
        for a in self.assets:
            if a.kind == "image" and not a.force_route and len(a.data) <= self.opts.get("inline_limit", 8192):
                a.delivery = "inline"
            else:
                a.delivery = "route"

    def routed(self):
        return [a for a in self.assets if a.delivery == "route"]


def data_uri(asset):
    return "data:%s;base64,%s" % (asset.mime, b64(asset.data))


TOKEN_RE = re.compile(r"__GVH_A_([a-f0-9]{12,64})__")


# --------------------------------------------------------------------------
# options
# --------------------------------------------------------------------------
DEFAULTS = {
    "output": None,
    "asset_mode": "auto",
    "deny_url": "https://access-denied.wasmer.app/",
    "allow_crawlers": False,
    "allow_webview": False,
    "allow_dynamic": False,
    "allow_iframe": False,
    "allow_hooks": False,
    "allow_non_native": False,
    "allow_print": False,
    "allow_select": True,
    "allow_rightclick": True,
    "inline_limit": 8192,
    "keep_comments": False,
    "chunk_size": 16384,
    "force": False,
    "title": None,
    "ua_extra": None,
    "quiet": False,
    "crypto_chunks": 50,
    "pbkdf2_iter": 120000,
    "files_threshold": 1500000,
    "dry": False,
}


# --------------------------------------------------------------------------
# builder
# --------------------------------------------------------------------------
class Builder:
    def __init__(self, input_path, options=None, log=print):
        self.input = os.path.abspath(input_path)
        self.opt = dict(DEFAULTS)
        self.opt.update(options or {})
        self.log = log
        self.report = {
            "generator": GENERATOR,
            "engine": "GVH-AI 2.0 (offline layout heuristics)",
            "input": self.input,
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "steps": {},
            "warnings": [],
            "defenses": [],
        }
        self.site = "gvh_" + token_hex(6)
        self.ap = rand_name("", 3)
        self.gw = rand_name("", 3)
        self.pn = rand_name("", 3)
        self.ps = rand_name("", 3)
        self.pt = rand_name("", 3)
        self.opt["ap"] = self.ap
        self.ph_man = "__GVH_M_" + token_hex(6).upper() + "__"
        self.ph_tok = "__GVH_T_" + token_hex(6).upper() + "__"
        self.cookie = "gv_" + token_hex(3)
        self.guard = "g_" + token_hex(8)
        self.hostkey = "h_" + token_hex(8)
        self.data_dir = "vault_" + token_hex(4)
        self.mx = list(os.urandom(32))
        self.master = os.urandom(32)
        self.sign = os.urandom(32)
        self.core = "GVHCORE::" + token_hex(12).upper() + "::" + brand.SIGNATURE
        self.store = None
        self.php = None

    # -- util ---------------------------------------------------------
    def step(self, key, title, **data):
        self.report["steps"][key] = dict(title=title, **data)

    def warn(self, msg):
        self.report["warnings"].append(msg)

    # -- main ---------------------------------------------------------
    def build(self):
        t0 = time.time()
        raw = _read(self.input)
        if raw.startswith("\ufeff"):
            raw = raw.lstrip("\ufeff")
        base_dir = os.path.dirname(self.input)
        tokens = H.tokenize(raw)
        self.store = AssetStore(self.site, base_dir, self.opt, self.log)
        tokens = self._rewrite(tokens, base_dir)
        content = H.serialize(tokens)
        content = self._credit_comment(content)
        title = self.opt.get("title") or H.find_title(tokens) or os.path.splitext(os.path.basename(self.input))[0]
        self.report["title"] = title
        self.report["input_size"] = len(raw.encode("utf-8"))
        self.report["output_html_size"] = len(content.encode("utf-8"))

        # ---- AI analysis (step 1 + 2) ------------------------------
        self._analyze(raw, tokens, title)

        # ---- assets -------------------------------------------------
        self.store.plan()
        routed = self.store.routed()
        total_routed = sum(len(a.data) for a in routed)
        files_mode = self.opt["asset_mode"] == "files" or (
            self.opt["asset_mode"] == "auto" and
            (total_routed > self.opt["files_threshold"] or any(len(a.data) > self.opt["files_threshold"] for a in routed)))
        if self.opt["asset_mode"] == "embed":
            files_mode = False

        self.step("assets", "asset vault", routed=len(routed), inline=len([a for a in self.store.assets if a.delivery == "inline"]),
                  remote=len(set(self.store.remote)), bytes=total_routed, mode="files" if files_mode else "embed")

        # ---- engine -------------------------------------------------
        pages = self._pages()
        flags = {
            "select": bool(self.opt["allow_select"]),
            "rightclick": bool(self.opt["allow_rightclick"]),
            "shortcuts": True,
            "devtools": True,
            "bots": True,
            "webview": not self.opt["allow_webview"],
            "iframe": not self.opt["allow_iframe"],
            "inject": not self.opt["allow_dynamic"],
            "native": not self.opt["allow_non_native"],
            "hooks": not self.opt["allow_hooks"],
            "print": not self.opt["allow_print"],
            "dynamic": bool(self.opt["allow_dynamic"]),
        }
        defcfg = {
            "banner": brand.banner(),
            "hostKey": self.hostkey,
            "deny": self.opt["deny_url"],
            "guard": self.guard,
            "uaExtra": self.opt["ua_extra"] or "",
            "flags": flags,
            "pages": {"fallback": pages["fallback"], "credit": pages["credit"],
                      "offline": pages["offline"], "https": pages["https"]},
        }
        engine_src = brand.banner() + "\n" + _read(os.path.join(ASSETS, "js", "defense.js")).replace("@@CFG@@", js_json(defcfg))
        self.report["defenses"] = [k for k, v in flags.items() if v]
        self.step("defense", "defence engine", bytes=len(engine_src.encode("utf-8")),
                  modules=["right-click", "shortcut-key", "devtools-heuristic", "eruda/vconsole",
                           "bookmarklet/injection", "webview", "puppeteer/headless", "iframe",
                           "credit-banner", "native-hook", "print", "console-probe",
                           "hook/tamper-scan", "frame-isolation", "anti-embed"])

        if self.opt.get("dry"):
            # analysis-only pass (gvh inspect): no PHP, no output written
            b64len = len(base64.b64encode(content.encode("utf-8")))
            per = max(4, int(self.opt["chunk_size"]))
            est = max(1, -(-b64len // per))
            self.step("chunks", "content chunking (estimate)", chunks=est,
                      chunk_size=per, b64_bytes=b64len, estimated=True)
            self.step("keys", "per-chunk AES-256 keys (estimate)", keys=est + int(self.opt["crypto_chunks"]),
                      key_length=50, apis=est, decoy_apis=24, estimated=True)
            self.step("obfuscation", "engine envelope (estimate)",
                      engine_bytes=len(engine_src.encode("utf-8")), chunks=int(self.opt["crypto_chunks"]),
                      layers=["base64", "50 chunks", "AES-256-GCM per chunk", "binary reverse",
                              "PBKDF2-SHA256(120k)+AES-256-GCM", "GVH-VM ARX layer", "base64"])
            self.report["output"] = {"dir": None, "index": None, "index_bytes": 0,
                                     "files_mode": False, "vault_bytes": 0,
                                     "shell_bytes": 0, "content_bytes": 0}
            self.report["dry"] = True
            return self.report

        # ---- crypto batch ------------------------------------------
        self.php = PhpBridge(verbose=not self.opt["quiet"])
        ok, err = self.php.available()
        if not ok:
            raise RuntimeError(err)
        self.log("  · php crypto bridge online")

        ops = []
        routed_sorted = sorted(routed, key=lambda a: a.id)
        for a in routed_sorted:
            ops.append({"op": "asset", "data_b64": b64(a.data)})
        ops.append({"op": "content", "data_b64": b64(content.encode("utf-8")),
                    "chunk_size": int(self.opt["chunk_size"])})
        ops.append({"op": "bundle", "source_b64": b64(engine_src.encode("utf-8")),
                    "core": self.core, "site": self.site, "banner": brand.banner(),
                    "chunks": int(self.opt["crypto_chunks"]), "iter": int(self.opt["pbkdf2_iter"]),
                    "vmRounds": 2, "vmProg": 96})
        res = self.php.run({"op": "batch", "ops": ops})
        results = res["results"]
        ai = 0
        for a in routed_sorted:
            a.cipher = results[ai]["asset"]
            a.key = a.cipher["k"]
            a.iv = a.cipher["iv"]
            ai += 1
        content_chunks = results[ai]["chunks"]
        ai += 1
        bundle = results[ai]["bundle"]

        # ---- manifest + api map ------------------------------------
        salt = token_hex(8)
        api_names, api_map = [], {}
        for ch in content_chunks:
            name = hashlib.sha256((self.site + "|api|" + salt + "|" + str(ch["i"])).encode()).hexdigest()[:32]
            api_names.append(name)
            api_map[name] = {"n": ch["i"], "k": ch["k"], "iv": ch["iv"], "ct": ch["ct"], "tg": ch["tg"]}
        fakes = []
        for i in range(24):
            fakes.append(hashlib.sha256((self.site + "|fake|" + salt + "|" + str(i)).encode()).hexdigest()[:32])

        manifest = {
            "v": 2,
            "site": self.site,
            "core": self.core,
            "guard": self.guard,
            "vm": bundle["manifest"]["vm"],
            "pbkdf2": bundle["manifest"]["pbkdf2"],
            "chunks": bundle["manifest"]["chunks"],
            "srcHash": bundle["manifest"]["srcHash"],
            "content": {"n": len(content_chunks), "apis": api_names},
            "fakes": fakes,
            "gw": self.gw, "pn": self.pn, "ps": self.ps, "pt": self.pt, "ap": self.ap,
            "hb": brand.html_banner(),
        }
        self.step("chunks", "content chunking",
                  chunks=len(content_chunks), chunk_size=self.opt["chunk_size"],
                  b64_bytes=sum(ch["len"] for ch in content_chunks))
        self.step("keys", "per-chunk AES-256 keys", keys=len(content_chunks) + len(bundle["manifest"]["chunks"]),
                  key_length=50, apis=len(api_names), decoy_apis=len(fakes))
        self.step("obfuscation", "engine envelope",
                  engine_bytes=len(engine_src.encode("utf-8")), chunks=len(bundle["manifest"]["chunks"]),
                  layers=["base64", "50 chunks", "AES-256-GCM per chunk", "binary reverse",
                          "PBKDF2-SHA256(120k)+AES-256-GCM", "GVH-VM ARX layer", "base64"])

        # ---- assets map --------------------------------------------
        assets_cfg = {}
        for a in routed_sorted:
            entry = {"m": a.mime, "size": len(a.data), "k": a.key, "iv": a.iv, "name": a.name}
            if files_mode:
                fname = a.id + ".gvh"
                entry["file"] = fname
                assets_cfg[a.id] = entry
            else:
                entry["ct"] = a.cipher["ct_b64"]
                assets_cfg[a.id] = entry

        # ---- shell + pages ----------------------------------------
        shell = self._shell(title, pages, bundle["blob"], manifest)
        cfg = {
            "v": 2,
            "site": self.site,
            "cookie": self.cookie,
            "master": b64(self.master),
            "sign": b64(self.sign),
            "gw": self.gw, "pn": self.pn, "ps": self.ps, "pt": self.pt, "ap": self.ap,
            "shell": shell,
            "manifest": manifest,
            "api": api_map,
            "assets": assets_cfg,
            "mx": self.mx,
            "ph_man": self.ph_man,
            "ph_tok": self.ph_tok,
            "deny": self.opt["deny_url"],
            "files": files_mode,
            "data_dir": self.data_dir,
            "fb": pages["fallback"],
            "https": pages["https"],
            "offline": pages["offline"],
            "credit": pages["credit"],
            "block_bots": True,
            "allow_crawlers": bool(self.opt["allow_crawlers"]),
            "allow_iframe": bool(self.opt["allow_iframe"]),
            "host_key": self.hostkey,
            "rate": 600,
        }
        cfg_res = self.php.run({"op": "cfg", "cfg": cfg})
        cfg_blob = cfg_res["cfg"]
        php_src = _read(os.path.join(ASSETS, "template.php")).replace("@@CFG@@", cfg_blob)

        # ---- write output -----------------------------------------
        outdir = os.path.abspath(self.opt["output"] or (os.path.splitext(self.input)[0] + "-secured"))
        if os.path.exists(outdir) and os.listdir(outdir):
            if not self.opt["force"]:
                raise RuntimeError("Output folder not empty: %s (use --force)" % outdir)
        os.makedirs(outdir, exist_ok=True)
        index_path = os.path.join(outdir, "index.php")
        with open(index_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(php_src)
        if files_mode:
            vdir = os.path.join(outdir, self.data_dir)
            os.makedirs(vdir, exist_ok=True)
            for a in routed_sorted:
                with open(os.path.join(vdir, a.id + ".gvh"), "wb") as fh:
                    fh.write(base64.b64decode(a.cipher["ct_b64"]))
            with open(os.path.join(vdir, ".htaccess"), "w", encoding="utf-8") as fh:
                fh.write("Require all denied\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n")
            with open(os.path.join(vdir, "index.html"), "w", encoding="utf-8") as fh:
                fh.write("<!doctype html><title>404</title>")

        self.report["output"] = {
            "dir": outdir,
            "index": index_path,
            "index_bytes": os.path.getsize(index_path),
            "files_mode": files_mode,
            "vault_bytes": total_routed if files_mode else 0,
            "shell_bytes": len(shell.encode("utf-8")),
            "content_bytes": len(content.encode("utf-8")),
        }
        self.report["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.report["seconds"] = round(time.time() - t0, 2)
        # The audit report and the deployment notes live *next to* the output
        # folder, never inside it: everything inside the folder is uploaded and
        # therefore publicly readable.
        stem = outdir.rstrip("/\\")
        report_path = stem + ".report.json"
        deploy_path = stem + ".DEPLOY.txt"
        self.report["output"]["report"] = report_path
        self.report["output"]["deploy_notes"] = deploy_path
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(self.report, fh, ensure_ascii=False, indent=2)
        with open(deploy_path, "w", encoding="utf-8") as fh:
            fh.write(self._deploy_text(outdir, files_mode))
        return self.report

    # ------------------------------------------------------------------
    @staticmethod
    def _credit_comment(html):
        """Put the branded credit right after the doctype so it is the first
        thing anybody sees in "view-source", without breaking standards mode."""
        hb = brand.html_banner()
        m = re.match(r"(?is)\s*(<!doctype[^>]*>)\s*", html)
        if m:
            return html[:m.end()] + "\n" + hb + "\n" + html[m.end():]
        return hb + "\n" + html

    def _pages(self):
        def load(name):
            return _read(os.path.join(TEMPLATES, name))

        return {
            "fallback": load("fallback.html"),
            "credit": load("credit.html"),
            "offline": load("offline.html"),
            "https": load("https.html"),
            "splash": load("splash.html"),
        }

    def _rewrite(self, tokens, base_dir):
        """Rewrite asset references in place, strip server-side-only comments."""
        base_href = None
        for t in tokens:
            if t.kind == "start" and t.tag == "base" and t.get("href"):
                base_href = t.get("href")
        doc_base = base_dir
        if base_href and not re.match(r"^[a-z]+://", base_href, re.I):
            p = base_href.split("?", 1)[0].split("#", 1)[0]
            if p:
                p = p.lstrip("/")
                cand = os.path.realpath(os.path.join(base_dir, p or "."))
                if os.path.isdir(cand):
                    doc_base = cand

        def map_html(url):
            if not url:
                return None
            ref = self.store.resolve(url, doc_base)
            if ref is None:
                return None
            if ref[0] == "inline":
                return data_uri(ref[1])
            if ref[0] == "asset":
                a = ref[1]
                if a.kind == "image" and a.delivery == "inline":
                    return data_uri(a)
                return "__GVH_A_%s__" % a.id
            return None

        def map_asset(url):
            # never inline: used for srcset / style attributes where a data URI
            # would collide with the comma separated syntax
            ref = self.store.resolve(url, doc_base, force_route=True)
            if ref is None:
                return None
            if ref[0] == "asset":
                return "__GVH_A_%s__" % ref[1].id
            if ref[0] == "inline":
                return data_uri(ref[1])
            return None

        def map_css(url):
            ref = self.store.resolve(url, doc_base)
            if ref is None:
                return None
            if ref[0] == "inline":
                return data_uri(ref[1])
            if ref[0] == "asset":
                return "__GVH_A_%s__" % ref[1].id
            return None

        out = []
        inside = []
        comments_removed = 0
        stripped_maps = 0
        for t in tokens:
            if t.kind == "comment":
                if self.opt["keep_comments"] or re.match(r"^\s*\[if", t.data or ""):
                    out.append(t)
                else:
                    comments_removed += 1
                continue
            if t.kind == "start":
                tag = t.tag
                if tag in H.VOID_TAGS:
                    pass
                else:
                    inside.append(tag)
                self._rewrite_start(t, map_html, map_asset)
                out.append(t)
                continue
            if t.kind == "end":
                if inside and inside[-1] == t.tag:
                    inside.pop()
                out.append(t)
                continue
            if t.kind == "text" and inside and inside[-1] == "style":
                t.raw = H.rewrite_urls_in_css(t.raw, map_css)
                out.append(t)
                continue
            if t.kind == "text" and inside and inside[-1] == "script":
                before = t.raw
                t.raw = re.sub(r"//[#@]\s*sourceMappingURL=\S+", "", t.raw)
                if t.raw != before:
                    stripped_maps += 1
                out.append(t)
                continue
            out.append(t)

        self.step("ai", "layout analysis (step 1)",
                  comments_moved_server_side=comments_removed,
                  source_maps_removed=stripped_maps,
                  elements=len([t for t in tokens if t.kind == "start"]))
        return out

    def _rewrite_start(self, t, map_html, map_asset=None):
        tag = t.tag
        rel = (t.get("rel") or "").lower().split()
        if map_asset is None:
            map_asset = map_html
        style = t.get("style")
        if style and "url(" in style.lower():
            t.set("style", H.rewrite_urls_in_css(style, map_asset))
        if tag == "meta":
            name = (t.get("name") or "").lower()
            prop = (t.get("property") or "").lower()
            if name in ("generator", "author") or prop in ("article:author",):
                t.attrs = []
                t.kind = "text"
                t.raw = ""
                return
            if prop in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image"):
                new = map_html(t.get("content"))
                if new:
                    t.set("content", new)
            return

        pairs = []
        if tag == "img":
            pairs = ["src"]
            if t.get("srcset"):
                t.set("srcset", H.rewrite_srcset(t.get("srcset"), map_asset))
        elif tag in ("source",):
            pairs = ["src"]
            if t.get("srcset"):
                t.set("srcset", H.rewrite_srcset(t.get("srcset"), map_asset))
        elif tag in ("video", "audio", "track", "embed", "input"):
            pairs = ["src"]
            if tag == "video" and t.get("poster"):
                pairs.append("poster")
        elif tag == "object":
            pairs = ["data"]
        elif tag == "script":
            if t.get("src"):
                new = map_html(t.get("src"))
                if new:
                    t.set("src", new)
                    t.drop("integrity")
                    t.drop("crossorigin")
            return
        elif tag == "link":
            href = t.get("href")
            if not href:
                return
            wanted = any(r in ("stylesheet", "icon", "shortcut", "apple-touch-icon", "mask-icon",
                               "preload", "manifest", "modulepreload") for r in rel)
            if not wanted:
                return
            new = map_html(href)
            if new:
                t.set("href", new)
                t.drop("integrity")
                t.drop("crossorigin")
            return
        elif tag in ("image", "use"):
            for attr in ("href", "xlink:href"):
                v = t.get(attr)
                if v:
                    new = map_html(v)
                    if new:
                        t.set(attr, new)
            return
        elif tag in ("body", "table", "td", "th"):
            if t.get("background"):
                new = map_html(t.get("background"))
                if new:
                    t.set("background", new)
            return
        elif tag == "style":
            return
        else:
            return

        for attr in pairs:
            v = t.get(attr)
            if v:
                new = map_html(v)
                if new:
                    t.set(attr, new)

    def _analyze(self, raw, tokens, title):
        store = self.store
        store.plan()
        visual = []
        text_bytes = 0
        for a in store.assets:
            if a.kind in ("image", "video", "audio", "font"):
                visual.append({
                    "name": a.name,
                    "type": a.kind,
                    "mime": a.mime,
                    "bytes": len(a.data),
                    "decision": "client-side stream (vault)" if a.delivery == "route" else "inline data-uri",
                    "reason": self._visual_reason(a),
                })
        for t in tokens:
            if t.kind == "text":
                text_bytes += len(t.raw.encode("utf-8"))

        self.step("ai_visual", "visual filter (step 2)",
                  visual_assets=len(visual),
                  client_side=len([v for v in visual if v["decision"].startswith("client")]),
                  inlined=len([v for v in visual if v["decision"] == "inline data-uri"]),
                  bytes=sum(v["bytes"] for v in visual),
                  items=sorted(visual, key=lambda v: -v["bytes"])[:20])
        self.report["step1_server_candidates"] = {
            "markup_bytes": len(raw.encode("utf-8")) - text_bytes,
            "text_bytes": text_bytes,
            "inline_scripts": sum(1 for t in tokens if t.kind == "start" and t.tag == "script" and not t.get("src")),
            "inline_styles": sum(1 for t in tokens if t.kind == "start" and t.tag == "style"),
            "note": "HTML/CSS/inline JS never reach the browser as source: they are AES-256 sealed per chunk.",
        }
        self.report["step2_client_visual"] = {
            "assets": visual,
            "note": "video/large images/fonts stay client-side and are streamed from the vault so a weak host never lags.",
        }

        if store.remote:
            self.warn("%d external http(s) asset(s) cannot be sealed (CDN links stay public): %s"
                      % (len(set(store.remote)), ", ".join(sorted(set(store.remote))[:4])))
        if store.missing:
            self.warn("%d local asset(s) were not found on disk and were left untouched: %s"
                      % (len(set(store.missing)), ", ".join(sorted(set(store.missing))[:4])))
        if store.data_uris:
            self.warn("%d data: URI asset(s) are already inline and stay readable in the DOM." % store.data_uris)
        if re.search(r"<form[^>]+action=[\"']\s*[\"']", raw, re.I):
            self.warn("A form posts back to the same page: index.php will only re-render the sealed page. "
                      "Point form actions at a real backend endpoint.")
        if re.search(r"<a[^>]+href=[\"'][^\"']+\.html", raw, re.I):
            self.warn("Links to other local .html pages are not protected by this build. Run gvh on each page.")
        if not re.search(r"<meta[^>]+name=[\"']viewport", raw, re.I):
            self.warn("No <meta name=viewport> found; the sealed page may look zoomed out on phones.")
        self.report["warnings"].extend(self._seo_warnings())

    def _seo_warnings(self):
        out = []
        if not self.opt["allow_crawlers"]:
            out.append("Bots/crawlers are blocked by design: search engines will not index this page.")
        out.append("The page needs PHP + HTTPS (WebCrypto). Opening index.php from file:// or a static host shows the sealed page only.")
        return out

    @staticmethod
    def _visual_reason(a):
        if a.kind == "video":
            return "video streams with HTTP Range: keeping it client-side avoids host lag"
        if a.kind == "audio":
            return "audio streams client-side with Range support"
        if a.kind == "font":
            return "font stays a browser request so text paints instantly"
        if a.kind == "image":
            if a.delivery == "route":
                return "large image streamed from the encrypted vault (no base64 bloat, no lag)"
            return "small icon inlined to save a request"
        return "asset"

    def _shell(self, title, pages, blob, manifest):
        shell = pages["splash"]
        shell = shell.replace("{{TITLE}}", esc(title))
        boot = _read(os.path.join(ASSETS, "js", "boot.js"))
        pages_json = {"fallback": pages["fallback"], "credit": pages["credit"],
                      "offline": pages["offline"], "https": pages["https"]}
        boot = boot.replace("@@BANNER@@", js_json(brand.banner()))
        boot = boot.replace("@@DENY@@", js_json(self.opt["deny_url"]))
        boot = boot.replace("@@BLOB@@", blob)
        boot = boot.replace("@@MX@@", json.dumps(self.mx))
        boot = boot.replace("@@IFRAME@@", "false" if self.opt["allow_iframe"] else "true")
        boot = boot.replace("@@HOSTKEY@@", self.hostkey)
        boot = boot.replace("@@PAGES@@", js_json(pages_json))
        # keep the manifest placeholder for the PHP runtime
        boot = boot.replace("@@MANIFEST@@", self.ph_man)

        favicon = "data:,"
        for a in self.store.assets:
            if a.name.lower().endswith((".ico", ".png", ".svg")) and a.delivery == "route" and a.kind == "image":
                if "favicon" in a.name.lower() or a.name.lower().endswith(".ico"):
                    favicon = "?%s=%s&%s=%s" % (self.ap, a.id, self.pt, self.ph_tok)
                    break
        script = brand.banner() + "\n" + boot
        shell = shell.replace("{{FAVICON}}", esc(favicon))
        shell = shell.replace("@@SCRIPT@@", script)
        # top-of-file credit, visible when someone opens "view-source"
        html_credit = brand.html_banner()
        if "<!DOCTYPE" in shell[:200].upper():
            idx = shell.upper().index("<!DOCTYPE")
            end = shell.index(">", idx) + 1
            shell = shell[:end] + "\n" + html_credit + shell[end:]
        else:
            shell = html_credit + "\n" + shell
        return shell

    def _deploy_text(self, outdir, files_mode):
        lines = [
            "%s" % GENERATOR,
            "=" * 60,
            "",
            "UPLOAD ONLY WHAT IS INSIDE THE OUTPUT FOLDER:",
            "   - index.php (required)",
            "   - the vault_* folder when present (encrypted media)",
            "   Never upload this notes file or the .report.json audit file:",
            "   they are written next to the folder, outside the deploy set.",
            "",
            "1. Upload these files to a PHP 7.4+ host with HTTPS:",
            "   - index.php",
        ]
        if files_mode:
            lines.append("   - %s/  (encrypted media vault, keep the whole folder)" % self.data_dir)
        lines += [
            "",
            "2. Open https://your-domain/index.php",
            "   (make it the directory index: DirectoryIndex index.php)",
            "",
            "3. Requirements",
            "   - PHP 7.4+ with openssl + zlib (Termux: pkg install php)",
            "   - HTTPS is mandatory (WebCrypto is disabled on plain http)",
            "   - Do not rename index.php: the vault paths are relative",
            "",
            "4. What visitors can never get from the page source:",
            "   - your markup / CSS / inline JS (AES-256-GCM per chunk, keys behind APIs)",
            "   - your images / video / fonts (AES-256-CTR vault, streamed with Range)",
            "   - the defence engine (5-layer client-key envelope)",
            "",
            "5. Notes",
            "   - Search engines are blocked on purpose (anti-copy build).",
            "   - Forms must post to an external backend, not back to index.php.",
            "   - Client-side protection raises the bar, it is not DRM: anything a",
            "     browser can render, a determined human can eventually reconstruct.",
            "",
            "SECURED BY %s  |  DEV %s  |  %s" % (brand.CREDIT, brand.DEVELOPER, brand.DEV_USER),
            "",
        ]
        return "\n".join(lines)


# --------------------------------------------------------------------------
# one-shot API
# --------------------------------------------------------------------------
def build(input_path, **options):
    log = options.pop("log", print)
    return Builder(input_path, options, log=log).build()
