"""
SHACKER SECURITY :: the interactive terminal.

`gvh` with no arguments drops you inside the tool: a boot animation, a status
bar, and one question - *what do you want to secure?*. Everything else is
handled (detection, naming, encryption, project folder, deploy notes).

Design rules
  * English only, no emoji soup: the banner and the cards do the talking.
  * Every animation is skippable: `--no-anim` / `NO_COLOR` / a non-TTY stream
    prints the same information without the theatre.
  * Nothing here imports third-party packages: Termux has Python 3 and that is
    all this file needs.
"""
from __future__ import annotations

import getpass
import os
import shutil
import sys
import threading
import time

from . import brand
from . import vault as V
from .builder import human

VERSION = "1.1.0"
SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# ---------------------------------------------------------------------------
# terminal primitives
# ---------------------------------------------------------------------------
_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(n):
    return ("\033[38;5;%dm" % n) if _TTY else ""


class T:
    """Colours + cursor helpers (all no-ops when the output is not a terminal)."""
    on = _TTY
    anim = on and not os.environ.get("GVH_NO_ANIM")

    PINK = _c(211)
    CYAN = _c(45)
    VIOLET = _c(141)
    GREEN = _c(48)
    YELLOW = _c(220)
    RED = _c(203)
    DIM = _c(240)
    GREY = _c(246)
    WHITE = _c(255)
    BOLD = "\033[1m" if _TTY else ""
    X = "\033[0m" if _TTY else ""

    @staticmethod
    def w(text="", end="\n"):
        sys.stdout.write(text + end)
        sys.stdout.flush()


def clear():
    if T.on:
        sys.stdout.write("\033[2J\033[H\033[?25l")
        sys.stdout.flush()


def cursor(on=True):
    if T.on:
        sys.stdout.write("\033[?25h" if on else "\033[?25l")
        sys.stdout.flush()


def term_width(default=78):
    try:
        return max(56, min(92, shutil.get_terminal_size((76, 24)).columns))
    except Exception:
        return default


def type_out(text, delay=0.008, speedup=True):
    if not T.anim:
        T.w(text)
        return
    step = delay
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        if ch in "。.·":
            time.sleep(step * 6)
        elif ch in ",:;":
            time.sleep(step * 3)
        else:
            time.sleep(step)
    sys.stdout.write("\n")
    sys.stdout.flush()


def pause(seconds):
    if T.anim:
        time.sleep(seconds)


def gradient_line(text, lo=141, hi=45):
    """Colour a string character by character (violet -> cyan)."""
    if not T.on:
        return text
    out = []
    n = max(1, len(text) - 1)
    for i, ch in enumerate(text):
        c = int(lo + (hi - lo) * (i / n))
        out.append("\033[38;5;%dm%s" % (c, ch))
    return "".join(out) + T.X


# ---------------------------------------------------------------------------
# banner
# ---------------------------------------------------------------------------
WORDMARK = [
    "  ███████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ",
    "  ██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗",
    "  ███████╗███████║███████║██║     █████╔╝ █████╗  ██████╔╝",
    "  ╚════██║██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗",
    "  ███████║██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║",
    "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
]


def banner(subtitle="S E C U R I T Y", tagline="sealed files · encrypted websites · zero plaintext"):
    width = term_width()
    T.w()
    for i, line in enumerate(WORDMARK):
        if T.on:
            a = 160 + i * 8
            T.w("\033[38;5;%dm%s" % (a, line))
        else:
            T.w(line)
        if T.anim:
            time.sleep(0.045)
    T.w()
    if T.on:
        T.w("   " + "\033[38;5;%dm%s" % (245, "╭" + "─" * 62 + "╮"))
        pad = subtitle.center(62)
        T.w("   " + "\033[38;5;%dm│%s\033[38;5;%dm│" % (245, gradient_line(pad, 141, 45), 245))
        T.w("   " + "\033[38;5;%dm│%s\033[38;5;%dm│" % (245, tagline[:62].ljust(62), 245))
        T.w("   " + "\033[38;5;%dm%s" % (245, "╰" + "─" * 62 + "╯"))
        T.w()
        T.w("   " + "\033[38;5;%dmSECURED BY %s%s   \033[38;5;%dmDEV %s · %s" % (
            240, brand.CREDIT, "", 240, brand.DEVELOPER, brand.DEV_USER))
    else:
        T.w("   " + subtitle)
        T.w("   " + tagline)
        T.w("   SECURED BY %s · DEV %s · %s" % (brand.CREDIT, brand.DEVELOPER, brand.DEV_USER))
    T.w()
    if T.on:
        T.w("   " + "\033[38;5;%dm%s" % (238, "─" * min(66, width - 6)))
        T.w()


def boot(ctx, steps):
    """Fake-but-honest boot sequence: every line is a real check."""
    for label, ok, detail in steps:
        if T.anim:
            spin_for(0.18, label)
        if ok:
            tag = "%s  ✔  %s" % (T.GREEN, T.X)
            name = label
        else:
            tag = "%s  !  %s" % (T.YELLOW, T.X)
            name = label
        line = "   %s%-34s %s%s" % (tag, name, T.DIM, detail or "")
        if T.anim:
            T.w(line)
            time.sleep(0.05)
        else:
            T.w(line)
    T.w()


def spin_for(seconds, label="working"):
    """Spin for a fixed time (used in the boot sequence)."""
    if not T.anim:
        return
    end = time.time() + seconds
    i = 0
    while time.time() < end:
        sys.stdout.write("\r   %s%s%s  %-32s" % (T.VIOLET, SPIN[i % len(SPIN)], T.X, label))
        sys.stdout.flush()
        i += 1
        time.sleep(0.06)
    sys.stdout.write("\r" + " " * 78 + "\r")


class Spinner:
    """Live spinner with a status line, usable while real work happens."""

    def __init__(self, label, detail=""):
        self.label = label
        self.detail = detail
        self._stop = threading.Event()
        self._thread = None
        self.shown = False

    def set(self, label=None, detail=None):
        if label is not None:
            self.label = label
        if detail is not None:
            self.detail = detail

    def _run(self):
        frames = SPIN
        i = 0
        t0 = time.time()
        self.shown = True
        while not self._stop.is_set():
            el = time.time() - t0
            line = "   %s%s%s  %-44s %s%4.1fs%s" % (
                T.VIOLET, frames[i % len(frames)], T.X, self.label[:44], T.DIM, el, T.X)
            sys.stdout.write("\r" + line[:120])
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        if T.anim:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        if self._thread:
            self._stop.set()
            self._thread.join(timeout=1)
            sys.stdout.write("\r" + " " * 120 + "\r")
            sys.stdout.flush()
        return False


def bar(fraction, width=34, label=""):
    fraction = max(0.0, min(1.0, fraction))
    filled = int(round(fraction * width))
    if T.on:
        fill = gradient_line("█" * filled, 141, 45) if filled else ""
        rest = "\033[38;5;238m" + "░" * (width - filled) + T.X
    else:
        fill, rest = "#" * filled, "-" * (width - filled)
    return "   %s  %s%3d%%%s  %s%s" % (fill + rest, T.WHITE, int(fraction * 100), T.X,
                                       T.DIM, label[:40] + T.X)


# ---------------------------------------------------------------------------
# frames / cards
# ---------------------------------------------------------------------------
def rule(label="", width=None):
    width = width or term_width()
    if label:
        T.w("   " + T.DIM + "── " + T.X + T.BOLD + label + T.X + " " +
            T.DIM + "─" * max(0, width - len(label) - 9) + T.X)
    else:
        T.w("   " + T.DIM + "─" * (width - 6) + T.X)


def header(vault_root, engine_line="online"):
    width = min(term_width(), 80)
    inner = width - 8
    T.w("   " + T.DIM + "╭" + "─" * inner + "╮" + T.X)
    left = "  SHACKER SECURITY"
    right = "v%s  " % VERSION
    T.w("   " + T.DIM + "│" + T.X + T.BOLD + left + T.X +
        " " * max(1, inner - len(left) - len(right) - 1) + T.DIM + right + "│" + T.X)
    v = "  vault  " + _short_home(vault_root)
    e = "● " + engine_line + "  "
    if T.on:
        e = T.GREEN + e + T.X
    T.w("   " + T.DIM + "│" + T.X + T.GREY + v + T.X +
        " " * max(1, inner - len(v) - len(e.replace(T.GREEN, "").replace(T.X, ""))) + e + T.DIM + "│" + T.X)
    T.w("   " + T.DIM + "╰" + "─" * inner + "╯" + T.X)


def _short_home(path):
    home = os.path.expanduser("~")
    if path.startswith(home):
        return "~" + path[len(home):]
    return path


def card(title, rows, tone="ok"):
    width = min(term_width(), 76)
    inner = width - 8
    mark = {"ok": ("✔", T.GREEN), "info": ("◆", T.CYAN), "warn": ("!", T.YELLOW)}.get(tone, ("✔", T.GREEN))
    head = " %s %s " % (mark[0], title)
    T.w("   " + T.DIM + "╭─" + T.X + mark[1] + T.BOLD + head + T.X +
        T.DIM + "─" * max(0, inner - len(head) - 1) + "╮" + T.X)
    for key, value in rows:
        k = str(key).ljust(10)
        line = "  %s%s%s  %s" % (T.DIM, k, T.X, value)
        pad = max(0, inner - len(_plain(line)) - 1)
        T.w("   " + T.DIM + "│" + T.X + line + " " * pad + T.DIM + "│" + T.X)
    T.w("   " + T.DIM + "╰" + "─" * inner + "╯" + T.X)


def _plain(text):
    import re
    return re.sub(r"\033\[[0-9;]*m", "", str(text))


# ---------------------------------------------------------------------------
# prompts
# ---------------------------------------------------------------------------
def _hint_lines(hint):
    for line in str(hint).splitlines() or [""]:
        T.w("   " + T.VIOLET + "│" + T.X + "  " + T.DIM + line + T.X)


def ask(label, hint="", default=""):
    T.w()
    T.w("   " + T.VIOLET + "┌─[ " + T.X + T.BOLD + label + T.X + T.VIOLET + " ]" + T.X)
    if hint:
        _hint_lines(hint)
    prompt = "   " + T.VIOLET + "└─" + T.CYAN + "❯ " + T.X
    try:
        if default:
            value = input(prompt + T.DIM + "[" + default + "] " + T.X).strip()
        else:
            value = input(prompt).strip()
    except EOFError:
        return ""
    return value or default


def ask_secret(label, hint=""):
    T.w()
    T.w("   " + T.VIOLET + "┌─[ " + T.X + T.BOLD + label + T.X + T.VIOLET + " ]" + T.X)
    if hint:
        _hint_lines(hint)
    prompt = "   " + T.VIOLET + "└─" + T.CYAN + "❯ " + T.X
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        return ""


def confirm(label, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    prompt = ("   " + T.VIOLET + "❯ " + T.X + label + " " + T.DIM + suffix + " " + T.X)
    try:
        value = input(prompt).strip().lower()
    except EOFError:
        return default
    if not value:
        return default
    return value[0] in ("y", "1", "j", "s", "হ")


# ---------------------------------------------------------------------------
# the interactive session
# ---------------------------------------------------------------------------
def run(vault_root=None, php_cmd=None, no_anim=False, version=VERSION):
    if no_anim:
        T.anim = False
    root = V.ensure_root(vault_root or default_root())
    engine = V.VaultEngine(php_cmd=php_cmd)

    clear()
    banner()
    T.w("   " + T.DIM + "initialising secure session…" + T.X)
    ok, why = engine.available()
    steps = [
        ("python runtime", True, "3.%d · stdlib only" % (sys.version_info[1],)),
        ("crypto backend", ok, "php + openssl" if ok else "php not found — install it first"),
        ("vault folder", True, _short_home(root)),
        ("container format", True, "GVHVAULT1 · AES-256-GCM · PBKDF2-SHA256"),
        ("shield engine", True, "website sealer ready"),
    ]
    boot(root, steps)
    if not ok:
        card("PHP IS MISSING", [
            ("install", "pkg install php php-openssl"),
            ("verify", "php -m | grep openssl"),
            ("more", "docs/TERMUX-BN.md"),
        ], tone="warn")
        T.w()
        cursor(True)
        return 2

    cursor(True)
    while True:
        T.w()
        header(root, "online")
        T.w()
        type_out(T.GREY + "   drop a file, a folder or a .zip here — or type its path." + T.X, 0.004)
        T.w("   " + T.DIM + "   (q to quit)" + T.X)
        raw = ask("STEP 1 · TARGET", "· html / website folder → sealed index.php\n"
                                    "· any file / folder / zip   → encrypted vault")
        if not raw or raw.lower() in ("q", "quit", "exit"):
            break
        try:
            target = V.detect(raw)
        except FileNotFoundError:
            card("NOT FOUND", [("path", V.expand(raw))], tone="warn")
            T.w()
            type_out("   That path does not exist. Try dragging the file into the terminal.", 0.004)
            continue

        T.w()
        card("TARGET LOCKED", [
            ("path", _short_home(target.path)),
            ("type", target.kind),
            ("plan", target.detail),
            ("size", human(target.bytes)),
        ], tone="info")

        suggested = V.pretty_name()
        name = ask("STEP 2 · PROJECT NAME", "this becomes the folder name inside Shacker-Security",
                   suggested)
        project = V.safe_name(name, suggested)

        password = None
        if target.kind in ("file", "folder", "zip"):
            T.w()
            card("PASSWORD", [
                ("rule", "never stored on disk, never sent anywhere"),
                ("note", "lose it and the payload is gone for good"),
                ("tip", "long and boring beats short and clever"),
            ], tone="warn")
            while True:
                password = ask_secret("STEP 3 · VAULT PASSWORD", "minimum 4 characters")
                if len(password) < 4:
                    card("TOO SHORT", [("password", "needs at least 4 characters")], tone="warn")
                    continue
                again = ask_secret("STEP 3 · REPEAT PASSWORD")
                if again != password:
                    card("MISMATCH", [("repeat", "did not match, try again")], tone="warn")
                    continue
                break

        T.w()
        rule("WORKING")
        with Spinner("preparing…") as sp:
            def progress(msg, _sp=sp):
                _sp.set(msg)
                if not T.anim:
                    T.w("   · " + msg)
            try:
                result = V.secure(target, project, password, root, engine, progress=progress)
            except Exception as exc:  # noqa: BLE001
                sp.__exit__()
                card("FAILED", [("error", str(exc)[:120])], tone="warn")
                T.w()
                continue

        T.w()
        if result["kind"] == "website":
            card("SECURED · WEBSITE", [
                ("project", result["project"]),
                ("folder", _short_home(result["dir"])),
                ("index", "index.php · " + human(result["bytes"])),
                ("chunks", "%d sealed chunk(s)" % result["chunks"]),
                ("take", "upload the whole folder (PHP + HTTPS)"),
                ("keep", "AUDIT.json stays local"),
            ])
        else:
            card("SECURED · VAULT", [
                ("project", result["project"]),
                ("folder", _short_home(result["dir"])),
                ("payload", human(result["plain"]) + " → " + human(result["bytes"])),
                ("files", result["container"] + " + unlock.php"),
                ("chunks", "%d AES-256-GCM chunk(s)" % result["chunks"]),
                ("take", "upload both files, open unlock.php"),
            ])
        if result.get("warnings"):
            for w in result["warnings"][:4]:
                T.w("   " + T.YELLOW + "! " + T.X + T.DIM + w + T.X)
        T.w()
        T.w("   " + T.GREEN + "✔ done in %.2fs" % result["seconds"] + T.X +
            T.DIM + "  ·  " + _short_home(result["dir"]) + T.X)

        if confirm("secure another one?", True):
            T.w()
            continue
        break

    T.w()
    rule("SESSION CLOSED")
    T.w("   " + T.DIM + "vault: " + _short_home(root) + T.X)
    T.w("   " + T.DIM + "SECURED BY " + brand.CREDIT + " · DEV " + brand.DEVELOPER +
        " · " + brand.DEV_USER + T.X)
    T.w()
    pause(0.2)
    cursor(True)
    return 0


def default_root():
    return os.environ.get("GVH_VAULT") or os.path.join(os.path.expanduser("~"), "Shacker-Security")


# ---------------------------------------------------------------------------
# non-interactive helper (used by `gvh vault` and the tests)
# ---------------------------------------------------------------------------
def one_shot(path, project=None, password=None, vault_root=None, php_cmd=None,
             password_stdin=False):
    root = V.ensure_root(vault_root or default_root())
    engine = V.VaultEngine(php_cmd=php_cmd)
    ok, why = engine.available()
    if not ok:
        raise RuntimeError(why)
    target = V.detect(path)
    if target.kind in ("file", "folder", "zip") and not password:
        if password_stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            raise RuntimeError("this payload needs a password (--password or --password-stdin)")
    project = V.safe_name(project or V.pretty_name())
    return V.secure(target, project, password, root, engine)
