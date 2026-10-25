"""
GVH SHIELD :: Shacker Security vault.

Everything the interactive tool does with files, folders and zip archives:

  * decide what a path really is (website / file / folder / zip)
  * build a payload (folders are zipped first)
  * encrypt it with the PHP helper (AES-256-GCM, PBKDF2-SHA256, chunked)
  * write a self-contained `unlock.php` next to it
  * keep one tidy project folder per job inside `Shacker-Security/`

The container format and the crypto live in `src/lib/crypt_build.php` so the
instruction set is shared with the website sealer.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import zipfile

from . import brand
from .builder import PhpBridge, human

VAULT_MAGIC = b"GVHVAULT1\n"
CHUNK = 1024 * 1024
ITER = 150_000
WASM_LIMIT = 24 * 1024 * 1024          # base64 through the wasm bridge
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".next", ".venv", "venv", ".cache"}

ADJ = ["neon", "crimson", "silent", "lucky", "hidden", "iron", "velvet", "rapid",
       "shadow", "cyber", "cosmic", "midnight", "golden", "electric", "phantom",
       "frost", "ember", "solar", "lunar", "wild", "royal", "smoky", "turbo", "alpha"]
NOUN = ["fox", "comet", "tiger", "raven", "wolf", "falcon", "orchid", "panda",
        "cobra", "lynx", "otter", "harbor", "cipher", "rocket", "saber", "vortex",
        "ember", "nebula", "koi", "jaguar", "moth", "pixel", "quartz", "zephyr"]


# ---------------------------------------------------------------------------
# naming
# ---------------------------------------------------------------------------
def pretty_name(rng=None) -> str:
    import random
    r = rng or random
    return "%s-%s-%04x" % (r.choice(ADJ), r.choice(NOUN), r.randrange(0x10000))


def unique_name(root: str, rng=None) -> str:
    for _ in range(200):
        name = pretty_name(rng)
        if not os.path.exists(os.path.join(root, name)):
            return name
    return "project-%d" % int(time.time())


def safe_name(text: str, fallback="project") -> str:
    keep = []
    for ch in (text or "").strip().lower():
        if ch.isalnum():
            keep.append(ch)
        elif ch in " -_.:": 
            keep.append("-")
    out = "".join(keep).strip("-._")
    while "--" in out:
        out = out.replace("--", "-")
    return (out[:40] or fallback)


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------
class Target:
    __slots__ = ("path", "kind", "label", "detail", "bytes")

    def __init__(self, path, kind, label, detail, size):
        self.path = path
        self.kind = kind          # website | folder-site | file | folder | zip
        self.label = label
        self.detail = detail
        self.bytes = size

    def as_dict(self):
        return {"path": self.path, "kind": self.kind, "label": self.label,
                "detail": self.detail, "bytes": self.bytes}


def _tree_size(path: str, limit=200_000) -> int:
    total = 0
    count = 0
    for base, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            try:
                total += os.path.getsize(os.path.join(base, name))
            except OSError:
                pass
            count += 1
            if count > limit:
                return total
    return total


def expand(path: str) -> str:
    """Turn ~, quotes and drag&drop escapes into a clean absolute path."""
    p = (path or "").strip().strip("'\"")
    p = p.replace("\\ ", " ")
    p = os.path.expandvars(os.path.expanduser(p))
    return os.path.abspath(p)


def detect(raw_path: str) -> Target:
    path = expand(raw_path)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if os.path.isdir(path):
        index = None
        for cand in ("index.html", "index.htm", "Index.html", "INDEX.HTML"):
            full = os.path.join(path, cand)
            if os.path.isfile(full):
                index = full
                break
        size = _tree_size(path)
        if index:
            return Target(index, "folder-site", index, "website folder → index.html sealed", size)
        return Target(path, "folder", os.path.basename(path.rstrip(os.sep)) or "folder",
                      "folder → zipped, then encrypted", size)
    size = os.path.getsize(path)
    lower = path.lower()
    if lower.endswith((".html", ".htm")):
        return Target(path, "website", os.path.basename(path), "web page → sealed index.php", size)
    if lower.endswith(".zip"):
        return Target(path, "zip", os.path.basename(path), "zip archive → encrypted vault", size)
    return Target(path, "file", os.path.basename(path), "file → encrypted vault", size)


# ---------------------------------------------------------------------------
# crypto bridge
# ---------------------------------------------------------------------------
class VaultEngine:
    def __init__(self, php_cmd=None, log=None):
        self.bridge = PhpBridge(php_cmd=php_cmd)
        self.log = log or (lambda *a: None)
        self.mode = self.bridge.mode

    def available(self):
        return self.bridge.available()

    # -- seal ---------------------------------------------------------
    def seal(self, payload_path: str, password: str, name: str, kind: str,
             workdir: str, progress=None) -> dict:
        size = os.path.getsize(payload_path)
        out_path = os.path.join(workdir, "container.bin")
        req = {
            "op": "vault_seal",
            "password": password,
            "name": name,
            "kind": kind,
            "iter": ITER,
            "chunk": CHUNK,
        }
        if self.mode != "wasm":
            # native PHP reads/writes files itself: no base64, no memory spike
            req["in_path"] = payload_path
            req["out_path"] = out_path
            if progress:
                progress("encrypting %s with AES-256-GCM" % human(size))
            res = self.bridge.run(req)
            if not os.path.exists(out_path):
                raise RuntimeError("encryption produced no output")
            return {"path": out_path, "bytes": os.path.getsize(out_path), "meta": res["vault"]["meta"]}

        if size > WASM_LIMIT:
            raise RuntimeError(
                "The test bridge can only seal up to %s; install PHP "
                "(pkg install php) to encrypt bigger payloads." % human(WASM_LIMIT))
        import base64
        with open(payload_path, "rb") as fh:
            data = base64.b64encode(fh.read()).decode("ascii")
        if progress:
            progress("encrypting %s with AES-256-GCM" % human(size))
        res = self.bridge.run(dict(req, data_b64=data))
        container = res["vault"]["container_b64"]
        if isinstance(container, str):
            container = base64.b64decode(container)
        with open(out_path, "wb") as fh:
            fh.write(container)
        return {"path": out_path, "bytes": res["vault"]["bytes"], "meta": res["vault"]["meta"]}

    # -- open (used by tests / `gvh unlock`) --------------------------
    def open(self, container_path: str, password: str, out_path: str) -> dict:
        if self.mode != "wasm":
            res = self.bridge.run({
                "op": "vault_open", "password": password,
                "vault_path": container_path, "out_path": out_path,
            })
            return res["vault"]
        import base64
        with open(container_path, "rb") as fh:
            blob = base64.b64encode(fh.read()).decode("ascii")
        res = self.bridge.run({"op": "vault_open", "password": password, "vault_b64": blob})
        data = base64.b64decode(res["vault"]["data_b64"])
        with open(out_path, "wb") as fh:
            fh.write(data)
        return res["vault"]

    def info(self, container_path: str) -> dict:
        if self.mode != "wasm":
            return self.bridge.run({"op": "vault_info", "vault_path": container_path})["vault"]["meta"]
        import base64
        with open(container_path, "rb") as fh:
            blob = base64.b64encode(fh.read()).decode("ascii")
        return self.bridge.run({"op": "vault_info", "vault_b64": blob})["vault"]["meta"]


# ---------------------------------------------------------------------------
# payload preparation
# ---------------------------------------------------------------------------
def make_payload(target: Target, workdir: str) -> tuple[str, str, str]:
    """Return (payload_path, original_name, vkind)."""
    if target.kind == "file":
        return target.path, os.path.basename(target.path), "file"
    if target.kind == "zip":
        return target.path, os.path.basename(target.path), "zip"

    if target.kind == "folder":
        name = os.path.basename(target.path.rstrip(os.sep)) or "folder"
        zpath = os.path.join(workdir, safe_name(name) + ".zip")
        base = os.path.dirname(target.path.rstrip(os.sep))
        count = 0
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for cur, dirs, files in os.walk(target.path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for f in sorted(files):
                    full = os.path.join(cur, f)
                    try:
                        zf.write(full, os.path.relpath(full, base))
                        count += 1
                    except OSError:
                        pass
        return zpath, name + ".zip", "folder"

    raise RuntimeError("unsupported target: %s" % target.kind)


# ---------------------------------------------------------------------------
# project folders
# ---------------------------------------------------------------------------
def ensure_root(root: str) -> str:
    root = os.path.abspath(os.path.expanduser(root))
    os.makedirs(root, exist_ok=True)
    readme = os.path.join(root, "README.txt")
    if not os.path.exists(readme):
        with open(readme, "w", encoding="utf-8") as fh:
            fh.write(
                "SHACKER SECURITY  ·  GVH SHIELD storage\n"
                "============================================================\n\n"
                "Every job gets its own folder here:\n\n"
                "  <pretty-name>/\n"
                "      website  → index.php  (+ vault_* if it had big media)\n"
                "                 upload the whole folder to a PHP host\n"
                "      file/zip → <name>.gvhe + unlock.php\n"
                "                 upload both, open unlock.php, type the password\n\n"
                "project.txt   what was sealed, when and how big (safe to upload)\n"
                "AUDIT.json    local notes / report - NEVER upload this file\n\n"
                "SECURED BY %s  ·  DEV %s  ·  %s\n"
                % (brand.CREDIT, brand.DEVELOPER, brand.DEV_USER))
    return root


def project_dir(root: str, name: str) -> str:
    path = os.path.join(root, name)
    os.makedirs(path, exist_ok=True)
    return path


def write_project_card(path: str, info: dict) -> str:
    lines = [
        "SHACKER SECURITY  ·  project card",
        "=" * 52,
        "",
        "  project   : %s" % info.get("project", ""),
        "  kind      : %s" % info.get("kind", ""),
        "  source    : %s" % info.get("source", ""),
        "  made      : %s" % info.get("made", ""),
        "  original  : %s" % info.get("original", ""),
        "  payload   : %s" % human(info.get("size", 0)),
        "  sealed    : %s" % human(info.get("sealed", 0)),
        "",
    ]
    if info.get("kind") == "website":
        lines += [
            "HOW TO USE",
            "  1. upload the whole folder to a PHP 7.2+ host (HTTPS required)",
            "  2. open https://yourdomain/  - the page unlocks in the browser",
            "  3. never upload AUDIT.json",
            "",
        ]
    else:
        lines += [
            "HOW TO USE",
            "  1. upload %s and unlock.php to the same folder on a PHP host"
            % info.get("container", "the .gvhe file"),
            "  2. open https://yourdomain/unlock.php",
            "  3. type the password - the file downloads and decrypts in memory",
            "  4. keep the password somewhere safe: it is NOT stored anywhere",
            "",
        ]
    lines += [
        "UPLOAD THESE",
        "  " + (info.get("container") or "index.php") +
        ("  + unlock.php" if info.get("kind") != "website" else "  (+ the vault_* folder if shown)"),
        "",
        "KEEP PRIVATE  (never upload)",
        "  AUDIT.json      local build report",
        "  project.txt     this card",
        "",
        "NOTE",
        "  AES-256-GCM · PBKDF2-SHA256 (%d rounds) · %d chunks"
        % (ITER, max(1, -(-info.get("size", 0) // CHUNK))),
        "",
        "SECURED BY %s  ·  DEV %s  ·  %s" % (brand.CREDIT, brand.DEVELOPER, brand.DEV_USER),
        "",
    ]
    out = os.path.join(path, "project.txt")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return out


def write_audit(path: str, data: dict) -> str:
    out = os.path.join(path, "AUDIT.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return out


def ledger(root: str, entry: dict):
    path = os.path.join(root, "projects.json")
    rows = []
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                rows = json.load(fh)
        except Exception:
            rows = []
    rows.append(entry)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# unlock.php
# ---------------------------------------------------------------------------
UNLOCK_TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "assets", "templates", "unlock.php.txt")


def render_unlock(meta: dict, container_name: str) -> str:
    with open(UNLOCK_TEMPLATE, encoding="utf-8") as fh:
        tpl = fh.read()
    repl = {
        "@@CREDIT@@": brand.CREDIT,
        "@@DEV@@": brand.DEVELOPER,
        "@@DEV_USER@@": brand.DEV_USER,
        "@@BANNER@@": brand.banner(),
        "@@CONTAINER@@": container_name,
        "@@NAME@@": meta.get("name", "payload.bin"),
        "@@KIND@@": meta.get("kind", "file"),
        "@@SIZE@@": str(int(meta.get("size", 0))),
        "@@MADE@@": meta.get("made", ""),
        "@@ITER@@": str(int(meta.get("iter", ITER))),
        "@@SIZE_HUMAN@@": human(int(meta.get("size", 0))),
    }
    for k, v in repl.items():
        tpl = tpl.replace(k, str(v))
    return tpl


# ---------------------------------------------------------------------------
# high level job
# ---------------------------------------------------------------------------
def secure(target: Target, project: str, password: str | None, root: str,
           engine: VaultEngine, progress=None, website_opts=None) -> dict:
    """Do the actual work and return a result dict used by the UI."""
    progress = progress or (lambda *a, **k: None)
    project = safe_name(project, "project") or pretty_name()
    pdir = project_dir(root, project)
    started = time.time()
    total_payload = 0

    if target.kind in ("website", "folder-site"):
        from . import builder as B
        progress("analysing the layout (server-side split)…")
        opts = dict(website_opts or {})
        opts.update({"output": pdir, "force": True, "quiet": True})
        progress("sealing chunks with per-chunk AES-256 keys…")
        rep = B.build(target.path, log=lambda *a: None, **opts)
        total_payload = rep["output"]["content_bytes"]
        info = {
            "project": project,
            "kind": "website",
            "source": target.path,
            "original": os.path.basename(target.path),
            "size": rep["output"]["index_bytes"],
            "sealed": rep["output"]["index_bytes"],
            "made": time.strftime("%Y-%m-%d %H:%M:%S"),
            "container": "index.php",
        }
        for extra in ("report.json", "DEPLOY.txt"):
            src = "%s.%s" % (pdir, extra)
            if os.path.isfile(src):
                shutil.move(src, os.path.join(pdir, extra))
        card = write_project_card(pdir, info)
        audit = write_audit(pdir, {"type": "website", "report": rep})
        files = sorted(os.listdir(pdir))
        result = {
            "project": project,
            "dir": pdir,
            "kind": "website",
            "index": rep["output"]["index"],
            "bytes": rep["output"]["index_bytes"],
            "vault_files": rep["output"]["files_mode"],
            "warnings": rep["warnings"],
            "card": card,
            "audit": audit,
            "files": files,
            "seconds": round(time.time() - started, 2),
            "chunks": rep["steps"]["chunks"]["chunks"],
        }
        ledger(root, {"project": project, "kind": "website", "made": info["made"],
                      "bytes": result["bytes"], "source": target.path})
        return result

    progress("packing %s…" % target.label)
    work = tempfile.mkdtemp(prefix="gvhvault_")
    try:
        payload, original, vkind = make_payload(target, work)
        total_payload = os.path.getsize(payload)
        progress("deriving the key (PBKDF2-SHA256 · %d rounds)…" % ITER)

        sealed = engine.seal(payload, password or "", original, vkind, work,
                             progress=lambda m: progress(m))
        container_name = safe_name(project, "vault") + ".gvhe"
        dest = os.path.join(pdir, container_name)
        shutil.move(sealed["path"], dest)

        progress("writing unlock.php…")
        with open(os.path.join(pdir, "unlock.php"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_unlock(sealed["meta"], container_name))

        info = {
            "project": project,
            "kind": vkind,
            "source": target.path,
            "original": original,
            "size": total_payload,
            "sealed": sealed["bytes"],
            "made": time.strftime("%Y-%m-%d %H:%M:%S"),
            "container": container_name,
        }
        card = write_project_card(pdir, info)
        audit = write_audit(pdir, {"type": "vault", "meta": sealed["meta"], "source": target.path})
        result = {
            "project": project,
            "dir": pdir,
            "kind": vkind,
            "container": container_name,
            "bytes": sealed["bytes"],
            "plain": total_payload,
            "card": card,
            "audit": audit,
            "files": sorted(os.listdir(pdir)),
            "seconds": round(time.time() - started, 2),
            "chunks": max(1, -(-total_payload // CHUNK)),
            "warnings": [],
        }
        ledger(root, {"project": project, "kind": vkind, "made": info["made"],
                      "bytes": sealed["bytes"], "source": target.path})
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
