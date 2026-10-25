"""
GVH :: tolerant HTML tokenizer / rewriter.

We intentionally do NOT use a tree builder: protecting a page must preserve the
author's markup byte-for-byte wherever we do not need to touch it.  A token
stream lets us rewrite only the attributes that point at assets and keeps
inline <script>/<style> bodies untouched.

Python 3.8+, standard library only (works on Termux).
"""
from __future__ import annotations

import html as _html
import re
from html.parser import HTMLParser

VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr", "keygen", "command",
}

RAW_TEXT_TAGS = {"script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes"}


class Token:
    __slots__ = ("kind", "tag", "attrs", "selfclose", "raw", "data")

    def __init__(self, kind, tag=None, attrs=None, selfclose=False, raw="", data=None):
        self.kind = kind            # text | start | end | comment | doctype | decl | raw
        self.tag = tag
        self.attrs = attrs or []    # list[list[str, str|None]]
        self.selfclose = selfclose
        self.raw = raw
        self.data = data

    def get(self, name, default=None):
        name = name.lower()
        for k, v in self.attrs:
            if k.lower() == name:
                return v
        return default

    def set(self, name, value):
        name_l = name.lower()
        for pair in self.attrs:
            if pair[0].lower() == name_l:
                pair[1] = value
                return
        self.attrs.append([name, value])

    def drop(self, name):
        name_l = name.lower()
        self.attrs = [p for p in self.attrs if p[0].lower() != name_l]

    def has_class(self, cls):
        v = self.get("class") or ""
        return cls in v.split()

    def clone(self):
        return Token(self.kind, self.tag, [list(a) for a in self.attrs],
                     self.selfclose, self.raw, self.data)


def _attr_escape(value):
    return (value.replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


class _Tok(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.tokens = []
        # stack of tags we are inside of (for raw-text detection we rely on
        # HTMLParser's CDATA mode, which is already correct for script/style)
        self.stack = []

    # -- token building -------------------------------------------------
    def _attrs_list(self, attrs):
        out = []
        for k, v in attrs:
            out.append([k, v])
        return out

    def handle_starttag(self, tag, attrs):
        raw = self.get_starttag_text() or ""
        self.tokens.append(Token("start", tag.lower(), self._attrs_list(attrs), False, raw))
        if tag.lower() not in VOID_TAGS:
            self.stack.append(tag.lower())

    def handle_startendtag(self, tag, attrs):
        raw = self.get_starttag_text() or ""
        self.tokens.append(Token("start", tag.lower(), self._attrs_list(attrs), True, raw))

    def handle_endtag(self, tag):
        self.tokens.append(Token("end", tag.lower(), None, False, "</%s>" % tag))
        if self.stack and self.stack[-1] == tag.lower():
            self.stack.pop()

    def handle_data(self, data):
        self.tokens.append(Token("text", raw=data))

    def handle_entityref(self, name):
        self.tokens.append(Token("text", raw="&%s;" % name))

    def handle_charref(self, name):
        self.tokens.append(Token("text", raw="&#%s;" % name))

    def handle_comment(self, data):
        self.tokens.append(Token("comment", raw="<!--%s-->" % data, data=data))

    def handle_decl(self, decl):
        self.tokens.append(Token("decl", raw="<!%s>" % decl, data=decl))

    def unknown_decl(self, data):
        self.tokens.append(Token("decl", raw="<![%s]>" % data, data=data))

    def handle_pi(self, data):
        self.tokens.append(Token("decl", raw="<?%s>" % data, data=data))


def tokenize(src: str):
    p = _Tok()
    p.feed(src)
    p.close()
    return p.tokens


_SAFE_ATTR_NAME = re.compile(r"^[A-Za-z_:][A-Za-z0-9_.:-]*$")


def serialize(tokens) -> str:
    out = []
    for t in tokens:
        if t.kind == "text" or t.kind == "comment" or t.kind == "decl":
            out.append(t.raw)
        elif t.kind == "end":
            out.append("</%s>" % t.tag)
        elif t.kind == "start":
            parts = ["<", t.tag]
            for k, v in t.attrs:
                if not k or not _SAFE_ATTR_NAME.match(k):
                    continue
                if v is None:
                    parts.append(" %s" % k)
                else:
                    parts.append(' %s="%s"' % (k, _attr_escape(v)))
            if t.selfclose:
                parts.append(" /")
            parts.append(">")
            out.append("".join(parts))
        else:
            out.append(t.raw)
    return "".join(out)


def text_content(tokens) -> str:
    """Visible-ish text, used by the analyser to estimate content weight."""
    buf = []
    skip = 0
    for t in tokens:
        if t.kind == "start" and t.tag in ("script", "style"):
            skip += 1
        elif t.kind == "end" and t.tag in ("script", "style"):
            skip = max(0, skip - 1)
        elif t.kind == "text" and not skip:
            buf.append(t.raw)
    return _html.unescape("".join(buf))


def find_title(tokens):
    inside = False
    for t in tokens:
        if t.kind == "start" and t.tag == "title":
            inside = True
            continue
        if t.kind == "end" and t.tag == "title":
            return ""
        if inside and t.kind == "text":
            return _html.unescape(t.raw).strip()
    return ""


def find_meta(tokens, name=None, prop=None):
    for t in tokens:
        if t.kind == "start" and t.tag == "meta":
            if name is not None and (t.get("name") or "").lower() == name.lower():
                return t.get("content")
            if prop is not None and (t.get("property") or "").lower() == prop.lower():
                return t.get("content")
    return None


def rewrite_urls_in_css(css: str, mapper) -> str:
    """
    Rewrite url(...) and @import "..." references using mapper(url) -> new url.
    Data URIs are preserved.
    """
    def _url_repl(m):
        quote = m.group(1) or ""
        url = m.group(2).strip()
        if not url or url.startswith("data:"):
            return m.group(0)
        new = mapper(url)
        if new is None or new == url:
            return m.group(0)
        q = quote or '"'
        return "url(%s%s%s)" % (q, new, q)

    css = re.sub(r"url\(\s*(['\"]?)([^'\")]*?)\1\s*\)", _url_repl, css, flags=re.I)

    def _import_repl(m):
        quote = m.group(1)
        url = m.group(2).strip()
        if not url or url.startswith("data:"):
            return m.group(0)
        new = mapper(url)
        if new is None or new == url:
            return m.group(0)
        return "@import %s%s%s" % (quote, new, quote)

    css = re.sub(r"@import\s+(['\"])([^'\"]+)\1", _import_repl, css, flags=re.I)
    return css


def rewrite_srcset(value: str, mapper):
    """srcset is a comma separated candidate list.

    A data: URI may legally contain commas, so commas are only treated as
    separators once the candidate has a descriptor (whitespace) or when the
    candidate is not a data: URI.  Everything this tool emits is a plain URL.
    """
    if not value:
        return value
    chunks = []
    cur = ""
    for ch in value:
        if ch == "," and not (cur.strip().lower().startswith("data:") and " " not in cur.strip() and "\t" not in cur.strip()):
            chunks.append(cur)
            cur = ""
            continue
        cur += ch
    chunks.append(cur)
    out = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        bits = chunk.split()
        url = bits[0]
        if url.lower().startswith("data:"):
            out.append(chunk)
            continue
        new = mapper(url)
        if new:
            bits[0] = new
            out.append(" ".join(bits))
        else:
            out.append(chunk)
    return ", ".join(out)


