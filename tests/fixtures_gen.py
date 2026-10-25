"""Generate test fixture sites (no binaries committed to the repo)."""
import os
import struct
import zlib
import random
import shutil


def png(path, w, h, noise=False):
    raw = bytearray()
    rnd = random.Random(42)
    for y in range(h):
        raw.append(0)
        for x in range(w):
            if noise:
                raw += bytes((rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)))
            else:
                raw += bytes((20 + (x * 7) % 200, 30 + (y * 5) % 200, 180))
    comp = zlib.compress(bytes(raw), 9)
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    data = b"\x89PNG\r\n\x1a\n"
    data += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    data += chunk(b"IDAT", comp)
    data += chunk(b"IEND", b"")
    open(path, "wb").write(data)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def build_site(root, name, html, files=None):
    d = os.path.join(root, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)
    write(os.path.join(d, "index.html"), html)
    for rel, content in (files or {}).items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(content, bytes):
            open(p, "wb").write(content)
        else:
            write(p, content)
    return d


RICH_CSS = """
:root { --brand: #7c5cff; }
body { margin: 0; font-family: "TestFont", system-ui, sans-serif; background: #05070d; color: #e8ecff; }
.hero { background-image: url('bg.svg'); background-size: cover; padding: 48px 24px; }
.logo { background: url(logo-small.png) no-repeat; width: 32px; height: 32px; }
@font-face { font-family: "TestFont"; src: url("font.woff2") format("woff2"); }
h1 { color: var(--brand); }
.card { border: 1px solid #223; border-radius: 16px; padding: 20px; }
"""

RICH_JS = """
window.__richLoaded = true;
document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('js-status');
  if (el) el.textContent = 'external-js-ok';
});
"""

TRICKY = """<!doctype html>
<HTML>
<HEAD>
<META CHARSET="utf-8">
<META NAME="viewport" content="width=device-width,initial-scale=1">
<TITLE>Rich &amp; Tricky — পরীক্ষা</TITLE>
<LINK REL="stylesheet" HREF="assets/site.css">
<LINK rel="icon" href="assets/favicon.png">
<!-- this comment must move server-side -->
</HEAD>
<BODY background="assets/logo-small.png">
<DIV CLASS="hero">
  <H1 id="headline">Rich &amp; Tricky ★</H1>
  <P id="sub">বাংলা লেখা, emoji 😂 and &lt;entities&gt;</P>
  <div class="card">
    <img id="pic" src="assets/logo-small.png" srcset="assets/logo-small.png 1x, assets/logo-big.png 2x" alt="logo">
    <img id="big" src="assets/photo.png" alt="photo">
    <picture><source srcset="assets/photo.png" type="image/png"><img src="assets/logo-big.png" alt=""></picture>
    <svg width="40" height="40" viewBox="0 0 40 40"><image href="assets/logo-small.png" width="40" height="40"/></svg>
    <div id="js-status">no-js</div>
    <div id="inline-status">no-inline</div>
    <span style="background-image:url('assets/logo-small.png');display:inline-block;width:10px;height:10px"></span>
    <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==" alt="dot">
    <a href="https://example.org/">external link</a>
    <img src="https://cdn.example.org/remote.png" alt="remote">
  </div>
  <form action="/submit" method="post"><input name="q" value="hello"><textarea name="t">select me</textarea><button type="submit">Go</button></form>
</DIV>
<!--[if IE]><p>legacy</p><![endif]-->
<script>document.getElementById('inline-status').textContent='inline-ok';</script>
<script src="assets/site.js" integrity="sha384-abc" crossorigin="anonymous"></script>
</BODY>
</HTML>
"""

SIMPLE = open(os.path.join(os.path.dirname(__file__), "fixtures", "simple.html"), encoding="utf-8").read()

MEDIA = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Media Vault</title>
<style>body{margin:0;background:#000;color:#fff;font-family:system-ui}.box{padding:20px}</style></head>
<body>
<div class="box">
  <h1>Media test</h1>
  <video id="movie" controls poster="poster.png" width="480">
    <source src="movie.mp4" type="video/mp4">
  </video>
  <audio controls src="sound.mp3"></audio>
  <img src="poster.png" alt="poster">
</div>
</body></html>
"""

BIG = """<!doctype html><html><head><meta charset="utf-8"><title>Big page</title>
<style>body{font-family:system-ui;background:#101;color:#eee}.row{padding:2px}</style></head><body>
<h1>Big page</h1>
""" + "\n".join('<div class="row">row %d — the quick brown fox jumps over the lazy dog</div>' % i for i in range(12000)) + """
</body></html>"""

UNICODE = """<!doctype html><html><head><meta charset="utf-8"><title>ইউনিকোড টেস্ট 😂</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body><h1 id="t">বাংলা ইউনিকোড 🚀 日本語 العربية</h1><p id="p">emoji: 😂🥰☠️🎉 · symbols: ⟨GVH⟩ &amp; &lt;ok&gt;</p>
<script>document.getElementById('p').textContent += ' · js-ünicode-ok';</script></body></html>"""


def make_all(root):
    random.seed(1)
    sites = {}
    sites["simple"] = build_site(root, "simple", SIMPLE)
    files = {
        "assets/site.css": RICH_CSS,
        "assets/site.js": RICH_JS,
        "assets/bg.svg": '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="400"><rect width="800" height="400" fill="#1b2a6b"/><circle cx="200" cy="200" r="120" fill="#7c5cff" opacity=".6"/></svg>',
        "assets/font.woff2": b"wOF2" + os.urandom(2048),
        "assets/favicon.png": b"",
        "assets/logo-small.png": b"",
        "assets/logo-big.png": b"",
        "assets/photo.png": b"",
    }
    d = build_site(root, "rich", TRICKY, files)
    png(os.path.join(d, "assets/favicon.png"), 16, 16)
    png(os.path.join(d, "assets/logo-small.png"), 32, 32)
    png(os.path.join(d, "assets/logo-big.png"), 300, 300)
    png(os.path.join(d, "assets/photo.png"), 640, 480, noise=True)
    sites["rich"] = d
    d = build_site(root, "media", MEDIA, {"movie.mp4": b"", "poster.png": b"", "sound.mp3": b""})
    png(os.path.join(d, "poster.png"), 800, 450, noise=True)
    # fake but structurally plausible mp4 + mp3, 3 MB / 400 KB
    mp4 = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + os.urandom(3 * 1024 * 1024)
    open(os.path.join(d, "movie.mp4"), "wb").write(mp4)
    open(os.path.join(d, "sound.mp3"), "wb").write(b"ID3\x04\x00\x00\x00\x00\x00\x00" + os.urandom(400 * 1024))
    sites["media"] = d
    sites["big"] = build_site(root, "big", BIG)
    sites["unicode"] = build_site(root, "unicode", UNICODE)
    return sites


if __name__ == "__main__":
    import json
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gvh-sites"
    print(json.dumps(make_all(root)))
