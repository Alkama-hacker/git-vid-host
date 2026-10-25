"""GVH SHIELD credit banner (single source of truth)."""

BRAND_NAME = "GVH SHIELD"
CREDIT = "@SHACKER_ENCRYPTION_bot"
DEVELOPER = "Shacker"
DEV_USER = "@Haki_xmw"
SIGNATURE = "GVH::SHACKER::7F3A-91C2-D00D-BEEF"

INNER = 70


def _row(text="", pad=" "):
    body = text
    if len(body) < INNER:
        body = body + pad * (INNER - len(body))
    return " * ║" + body[:INNER] + "║"


def _sep(ch="═"):
    return " * ╠" + ch * INNER + "╣"


def _top():
    return " * ╔" + "═" * INNER + "╗"


def _bottom():
    return " * ╚" + "═" * INNER + "╝"


def _center(text):
    left = max(0, (INNER - len(text)) // 2)
    return _row(" " * left + text)


def banner() -> str:
    lines = [
        "/*!",
        _top(),
        _center("██  G V H   S H I E L D  ██"),
        _center("SEALED  ·  ENCRYPTED  ·  PROTECTED"),
        _sep(),
        _row("  SECURED BY   :  " + CREDIT),
        _row("  DEVELOPER    :  " + DEVELOPER),
        _row("  DEV USERNAME :  " + DEV_USER),
        _row("  SIGNATURE    :  ⟨" + SIGNATURE + "⟩"),
        _sep(),
        _row("  [!] EDITING OR REMOVING THIS CREDIT WILL BREAK THIS WEBSITE."),
        _row("  [!] THIS CREDIT IS CRYPTOGRAPHICALLY BOUND TO THE DECRYPTOR."),
        _row("  [!] DO NOT REMOVE. DO NOT RENAME. DO NOT RE-UPLOAD EDITED."),
        _bottom(),
        " */",
    ]
    return "\n".join(lines)


def html_banner() -> str:
    """The same credit as an HTML comment (for people reading page source)."""
    body = banner()
    body = body.replace("/*!", "", 1).rsplit("*/", 1)[0]
    stripped = []
    for line in body.strip("\n").splitlines():
        line = line.strip()
        if line.startswith("* "):
            line = line[2:]
        elif line == "*":
            line = ""
        stripped.append(line)
    return "<!--\n" + "\n".join(stripped) + "\n-->"


if __name__ == "__main__":
    print(banner())
    print(html_banner())
