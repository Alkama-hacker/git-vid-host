#!/usr/bin/env python3
"""
GVH SHIELD :: Termux-friendly HTML copy guard.

    gvh build page.html          -> page-secured/index.php
    gvh inspect page.html        -> AI layout report, no output
    gvh check page-secured/      -> lint + live HTTP smoke test
    gvh serve page-secured/      -> local PHP server (localhost = secure origin)
    gvh doctor                   -> environment check
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from lib import brand  # noqa: E402
from lib import builder as B  # noqa: E402

VERSION = B.VERSION


# ---------------------------------------------------------------------------
# pretty terminal
# ---------------------------------------------------------------------------
class C:
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    G = "\033[38;5;48m" if on else ""
    C = "\033[38;5;51m" if on else ""
    Y = "\033[38;5;220m" if on else ""
    R = "\033[38;5;203m" if on else ""
    M = "\033[38;5;177m" if on else ""
    D = "\033[38;5;245m" if on else ""
    B = "\033[1m" if on else ""
    X = "\033[0m" if on else ""


def say(msg="", color="", end="\n"):
    print("%s%s%s" % (color, msg, C.X if color else ""), end=end)


def logo():
    if not C.on:
        say("GVH SHIELD  v%s  ::  HTML COPY GUARD" % VERSION)
        return
    art = [
        "  ██████╗ ██╗   ██╗██╗   ██╗    ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ",
        " ██╔════╝ ██║   ██║██║   ██║    ██╔════╝██║  ██║██║██╔════╝██║     ██╔═══██╗",
        " ██║  ███╗██║   ██║██║   ██║    ███████╗███████║██║█████╗  ██║     ██║   ██║",
        " ██║   ██║╚██╗ ██╔╝██║   ██║    ╚════██║██╔══██║██║██╔══╝  ██║     ██║   ██║",
        " ╚██████╔╝ ╚████╔╝ ╚██████╔╝    ███████║██║  ██║██║███████╗███████╗╚██████╔╝",
        "  ╚═════╝   ╚═══╝   ╚═════╝     ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ",
    ]
    for line in art:
        say(line, C.M)
    say("  HTML COPY GUARD · AI LAYOUT SPLIT · AES-256 CHUNKS · ANTI-DEVTOOLS", C.D)
    say("  v%s   SECURED BY %s" % (VERSION, brand.CREDIT), C.D)
    say()


def rule(label=""):
    line = "─" * 64
    if label:
        say("%s %s %s" % (line[:6], label, line), C.D)
    else:
        say(line, C.D)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_build(args):
    inp = args.input
    if not os.path.isfile(inp):
        say("✖ file not found: %s" % inp, C.R)
        return 2
    if not args.quiet:
        logo()
        say("  input   : %s (%s)" % (os.path.abspath(inp), B.human(os.path.getsize(inp))), C.D)
        say("  output  : %s" % (args.output or (os.path.splitext(inp)[0] + "-secured/")), C.D)
        say()
    steps = [
        ("1/8", "AI layout analysis (what can live server side)"),
        ("2/8", "visual filter (video/images/fonts stay client side)"),
        ("3/8", "base64 conversion"),
        ("4/8", "chunk splitting"),
        ("5/8", "AES-256-GCM per chunk + per-chunk 50-char keys"),
        ("6/8", "defence engine (right-click / devtools / eruda / webview / bots)"),
        ("7/8", "high obfuscation (5 layers + credit checker)"),
        ("8/8", "PHP emission + encrypted vault"),
    ]
    if not args.quiet:
        for num, txt in steps:
            say("  [%s] %s" % (num, txt), C.C)
        say()
    opts = {
        "output": args.output,
        "asset_mode": args.asset_mode,
        "deny_url": args.deny_url,
        "allow_crawlers": args.allow_crawlers,
        "allow_webview": args.allow_webview,
        "allow_dynamic": args.allow_dynamic,
        "allow_iframe": args.allow_iframe,
        "allow_hooks": args.allow_hooks,
        "allow_non_native": args.allow_non_native,
        "allow_print": args.allow_print,
        "allow_select": not args.no_select,
        "allow_rightclick": not args.no_rightclick,
        "inline_limit": args.inline_limit,
        "keep_comments": args.keep_comments,
        "chunk_size": args.chunk_size,
        "force": args.force,
        "title": args.title,
        "ua_extra": args.ua_extra,
        "quiet": args.quiet,
    }
    t0 = time.time()
    try:
        rep = B.build(inp, log=(lambda *a: None) if args.quiet else (lambda m: say("  " + m, C.D)), **opts)
    except RuntimeError as exc:
        say("\n✖ %s" % exc, C.R)
        return 2
    dt = time.time() - t0
    out = rep["output"]
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0
    say()
    rule("BUILD COMPLETE")
    say("  ✔ output      : %s" % out["index"], C.G)
    say("  ✔ size        : %s  (shell %s + content %s)" % (
        B.human(out["index_bytes"]), B.human(out["shell_bytes"]), B.human(out["content_bytes"])), C.D)
    say("  ✔ chunks      : %d sealed content chunks · %d engine chunks" % (
        rep["steps"]["chunks"]["chunks"], rep["steps"]["obfuscation"]["chunks"]), C.D)
    say("  ✔ api keys    : %d (one AES-256 key per chunk) + %d decoys" % (
        rep["steps"]["keys"]["apis"], rep["steps"]["keys"]["decoy_apis"]), C.D)
    say("  ✔ media vault : %s" % ("files mode (streamed with Range)" if out["files_mode"] else "embedded in index.php"), C.D)
    say("  ✔ time        : %.2fs" % dt, C.D)
    say("  ✔ credit      : %s  ·  DEV %s · %s" % (brand.CREDIT, brand.DEVELOPER, brand.DEV_USER), C.G)
    if rep["warnings"]:
        say()
        rule("WARNINGS")
        for w in rep["warnings"]:
            say("  ! " + w, C.Y)
    say()
    if out.get("report"):
        say("  report      : %s (keep private, do not upload)" % out["report"], C.D)
    say("  next → gvh check %s" % out["dir"], C.C)
    say("        gvh serve %s   (open http://localhost:8080)" % out["dir"], C.C)
    return 0


def cmd_inspect(args):
    if not os.path.isfile(args.input):
        say("✖ file not found: %s" % args.input, C.R)
        return 2
    opts = {"output": args.output, "quiet": True, "asset_mode": "auto", "dry": True}
    try:
        rep = B.build(args.input, log=lambda *a: None, **opts)
    except RuntimeError as exc:
        say("✖ %s" % exc, C.R)
        return 2
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        logo()
        rule("AI LAYOUT ANALYSIS (step 1)")
        s1 = rep["step1_server_candidates"]
        say("  markup moved server side : %s" % B.human(s1["markup_bytes"]), C.G)
        say("  inline <script> blocks   : %d" % s1["inline_scripts"], C.D)
        say("  inline <style> blocks    : %d" % s1["inline_styles"], C.D)
        say("  comments hidden          : %d" % rep["steps"]["ai"]["comments_moved_server_side"], C.D)
        rule("VISUAL FILTER (step 2)")
        vis = rep["step2_client_visual"]["assets"]
        if not vis:
            say("  no local media found", C.D)
        for v in sorted(vis, key=lambda x: -x["bytes"])[:15]:
            say("  %-9s %-28s %8s  %s" % (v["type"], v["name"][:28], B.human(v["bytes"]), v["decision"]), C.C)
        rule("CHUNK / KEY PLAN (steps 3-5)")
        say("  content chunks : %d" % rep["steps"]["chunks"]["chunks"], C.D)
        say("  api endpoints  : %d real + %d fake" % (rep["steps"]["keys"]["apis"], rep["steps"]["keys"]["decoy_apis"]), C.D)
        rule("DEFENCE (step 6)")
        say("  " + " · ".join(rep["defenses"]), C.G)
        if rep["warnings"]:
            rule("WARNINGS")
            for w in rep["warnings"]:
                say("  ! " + w, C.Y)
        say("\n  analysis only: nothing was written. Run gvh build to seal the page.", C.D)
    return 0


def cmd_doctor(args):
    logo()
    ok = True
    py = sys.version_info
    say("  python   : %d.%d.%d %s" % (py.major, py.minor, py.micro, "✔" if py >= (3, 7) else "✖ (need 3.7+)"),
        C.G if py >= (3, 7) else C.R)
    ok = ok and py >= (3, 7)
    php = shutil.which(args.php or os.environ.get("GVH_PHP") or "php")
    if php:
        say("  php      : %s ✔" % php, C.G)
        try:
            ver = subprocess.run([php, "-r", "echo PHP_VERSION;"], capture_output=True, text=True, timeout=20).stdout.strip()
            exts = subprocess.run([php, "-r", "echo (int)extension_loaded('openssl'),' ',(int)extension_loaded('zlib');"],
                                  capture_output=True, text=True, timeout=20).stdout.strip()
            say("             version %s · openssl/zlib %s" % (ver, exts), C.D)
            if exts != "1 1":
                say("             ✖ openssl and zlib are required", C.R)
                ok = False
        except Exception as exc:  # noqa: BLE001
            say("             could not query php: %s" % exc, C.Y)
    else:
        say("  php      : ✖ not found", C.R)
        say("             Termux : pkg install php", C.Y)
        say("             Debian : sudo apt install php-cli", C.Y)
        ok = False
    node = shutil.which("node")
    say("  node     : %s (optional, only for the dev test-suite)" % (node or "not installed"), C.D)
    say("  platform : %s %s" % (sys.platform, os.uname().machine if hasattr(os, "uname") else ""), C.D)
    termux = "com.termux" in os.environ.get("PREFIX", "") or os.path.exists("/data/data/com.termux")
    say("  termux   : %s" % ("yes" if termux else "no"), C.D)
    say()
    if ok:
        say("  ✔ ready: gvh build page.html", C.G)
    else:
        say("  ✖ fix the items above first", C.R)
    return 0 if ok else 1


def _free_port(preferred=8080):
    for port in range(preferred, preferred + 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


def cmd_serve(args):
    php = shutil.which(args.php or "php")
    if not php:
        say("✖ PHP not found — pkg install php", C.R)
        return 2
    if not os.path.isdir(args.dir):
        say("✖ folder not found: %s" % args.dir, C.R)
        return 2
    port = args.port or _free_port(8080)
    host = args.host
    say("  serving %s" % os.path.abspath(args.dir), C.D)
    say("  → http://%s:%d/index.php" % ("localhost" if host in ("127.0.0.1", "0.0.0.0") else host, port), C.C)
    if host != "127.0.0.1":
        say("  note: WebCrypto needs https or localhost. Use localhost on this device.", C.Y)
    try:
        subprocess.call([php, "-S", "%s:%d" % (host, port), "-t", os.path.abspath(args.dir)])
    except KeyboardInterrupt:
        pass
    return 0


def cmd_check(args):
    d = os.path.abspath(args.dir)
    index = os.path.join(d, "index.php")
    if not os.path.isfile(index):
        say("✖ index.php not found in %s" % d, C.R)
        return 2
    logo()
    php = shutil.which(args.php or "php")
    if not php:
        say("✖ PHP not found — pkg install php", C.R)
        return 2
    say("  php -l …", C.D)
    lint = subprocess.run([php, "-l", index], capture_output=True, text=True)
    if lint.returncode != 0:
        say("  ✖ syntax: " + (lint.stdout + lint.stderr).strip(), C.R)
        return 1
    say("  ✔ syntax ok", C.G)
    port = _free_port(8090)
    proc = subprocess.Popen([php, "-S", "127.0.0.1:%d" % port, "-t", d],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        url = "http://127.0.0.1:%d/index.php" % port
        last = None
        for _ in range(40):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 13) Chrome/120 Mobile Safari/537.36"})
                with urllib.request.urlopen(req, timeout=3) as r:
                    body = r.read()
                    hdrs = dict(r.headers)
                    last = (r.status, body, hdrs)
                    break
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(0.15)
        if not isinstance(last, tuple):
            say("  ✖ server did not answer: %s" % last, C.R)
            return 1
        status, body, hdrs = last
        checks = []
        checks.append(("HTTP 200", status == 200))
        checks.append(("X-Frame-Options: DENY", hdrs.get("X-Frame-Options", "").upper() == "DENY"))
        checks.append(("CSP frame-ancestors", "frame-ancestors" in hdrs.get("Content-Security-Policy", "")))
        checks.append(("no-store", "no-store" in hdrs.get("Cache-Control", "")))
        checks.append(("credit banner", b"@SHACKER_ENCRYPTION_bot" in body))
        checks.append(("boot present", b"GVH SHIELD" in body or b"Decrypting secure layers" in body))
        checks.append(("sealed shell (not raw html)", b"Decrypting secure layers" in body))
        allok = True
        for name, ok in checks:
            allok = allok and ok
            say("  %s %s" % ("✔" if ok else "✖", name), C.G if ok else C.R)
        say("  payload: %s" % B.human(len(body)), C.D)
        return 0 if allok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except Exception:  # noqa: BLE001
            proc.kill()


def cmd_version(args):
    say("GVH SHIELD %s · SECURED BY %s · DEV %s · %s" % (VERSION, brand.CREDIT, brand.DEVELOPER, brand.DEV_USER))
    return 0


def interactive():
    logo()
    say("  Welcome! Let's seal an HTML page.", C.G)
    path = input("  HTML file: ").strip().strip("'\"")
    if not path:
        say("  cancelled", C.Y)
        return 1
    out = input("  Output folder [%s]: " % (os.path.splitext(path)[0] + "-secured")).strip()
    args = argparse.Namespace(
        input=path, output=out or None, asset_mode="auto",
        deny_url=B.DEFAULTS["deny_url"], allow_crawlers=False, allow_webview=False,
        allow_dynamic=False, allow_iframe=False, allow_non_native=False, allow_hooks=False,
        allow_print=False, no_select=False,
        no_rightclick=False, inline_limit=8192, keep_comments=False, chunk_size=16384,
        force=False, title=None, ua_extra=None, quiet=False, json=False)
    return cmd_build(args)


# ---------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(prog="gvh", description="GVH SHIELD — HTML copy guard for Termux/PHP",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="examples:\n  gvh build index.html\n  gvh inspect index.html\n"
                                       "  gvh serve index-secured\n  gvh check index-secured")
    p.add_argument("--php", help="path to the php binary (default: php)")
    sub = p.add_subparsers(dest="cmd")

    b = sub.add_parser("build", help="seal an HTML page into index.php")
    b.add_argument("input")
    b.add_argument("-o", "--output")
    b.add_argument("--asset-mode", choices=["auto", "embed", "files"], default="auto")
    b.add_argument("--deny-url", default=B.DEFAULTS["deny_url"], help="where detections are redirected")
    b.add_argument("--allow-crawlers", action="store_true", help="let search engine crawlers through")
    b.add_argument("--allow-webview", action="store_true", help="do not block in-app webviews")
    b.add_argument("--allow-dynamic", action="store_true", help="allow dynamically injected scripts/iframes (weaker)")
    b.add_argument("--allow-iframe", action="store_true", help="allow embedding this page in an iframe (staging/own site)")
    b.add_argument("--allow-non-native", action="store_true",
                   help="skip the [native code] check (emulators / test browsers)")
    b.add_argument("--allow-hooks", action="store_true",
                   help="skip the clean-realm hook/tamper scan (weaker)")
    b.add_argument("--allow-print", action="store_true", help="do not block printing")
    b.add_argument("--no-select", action="store_true", help="allow text selection/copy")
    b.add_argument("--no-rightclick", action="store_true", help="allow the context menu")
    b.add_argument("--inline-limit", type=int, default=8192, help="inline images up to N bytes (default 8192)")
    b.add_argument("--keep-comments", action="store_true", help="keep HTML comments (they become public)")
    b.add_argument("--chunk-size", type=int, default=16384, help="base64 chars per sealed chunk")
    b.add_argument("--title")
    b.add_argument("--ua-extra", help="extra regex of user agents to block")
    b.add_argument("--force", action="store_true")
    b.add_argument("--quiet", action="store_true")
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=cmd_build)

    i = sub.add_parser("inspect", help="AI layout report only")
    i.add_argument("input")
    i.add_argument("-o", "--output")
    i.add_argument("--json", action="store_true")
    i.set_defaults(func=cmd_inspect)

    d = sub.add_parser("doctor", help="check python/php/openssl")
    d.set_defaults(func=cmd_doctor)

    s = sub.add_parser("serve", help="serve a sealed folder locally")
    s.add_argument("dir")
    s.add_argument("-p", "--port", type=int, default=0)
    s.add_argument("--host", default="127.0.0.1")
    s.set_defaults(func=cmd_serve)

    c = sub.add_parser("check", help="lint + live smoke test")
    c.add_argument("dir")
    c.set_defaults(func=cmd_check)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=cmd_version)

    args = p.parse_args(argv)
    if not getattr(args, "cmd", None):
        if len(sys.argv) == 1 and sys.stdin.isatty():
            return interactive()
        p.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
