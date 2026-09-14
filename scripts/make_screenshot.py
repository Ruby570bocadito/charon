#!/usr/bin/env python3
"""Genera docs/assets/charon-demo.png a partir de salidas REALES de charon.

Uso: python3 scripts/make_screenshot.py [dir-demos] [salida.png]

Cada demo es la salida (con colores ANSI) de:
  charon enum --users jdoe,aesuser,legacy,nopreauth,ghost-inexistente -r LAB.LOCAL --port 1088
  charon kerberoast --spn mssql/srv01.lab.local -u jdoe -p ... -r LAB.LOCAL --port 1088
  charon asreproast --users nopreauth -r LAB.LOCAL --port 1088

Las líneas de hash se recortan visualmente (los textos completos viven en
traces/). El resto se pinta tal cual emitió la herramienta.
"""
import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SIZE = 15
LINE_H = 22
PAD = 26
WIDTH = 1040
BAR_H = 34

BG = (24, 27, 34)
BAR = (33, 37, 46)
FG = (201, 209, 217)
MUTED = (125, 133, 144)
PROMPT = (63, 185, 80)

ANSI = {
    30: (62, 66, 77), 31: (248, 81, 73), 32: (63, 185, 80), 33: (210, 153, 34),
    34: (88, 166, 255), 35: (188, 140, 255), 36: (57, 197, 207), 37: (201, 209, 217),
    90: (94, 102, 115), 91: (255, 123, 114), 92: (111, 212, 121), 93: (230, 178, 74),
    94: (121, 184, 255), 95: (205, 165, 255), 96: (98, 218, 229), 97: (235, 240, 245),
}

SECTIONS = [
    ("charon enum --users jdoe,aesuser,legacy,nopreauth,ghost-inexistente "
     "-r LAB.LOCAL --port 1088", "demo-enum.txt", False),
    ("charon kerberoast --spn mssql/srv01.lab.local -u jdoe -p "
     "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022 "
     "-r LAB.LOCAL --port 1088", "demo-kerb.txt", True),
    ("charon asreproast --users nopreauth -r LAB.LOCAL --port 1088", "demo-asrep.txt", True),
]

CMD_COLS = 94  # ancho máximo de línea de comando antes de partir

TOKEN = re.compile(r"\x1b\[([0-9;]*)m")


def wrap_cmd(cmd: str):
    """Parte el comando en líneas de <= CMD_COLS con sangría de continuación."""
    words, lines, cur = cmd.split(), [], ""
    for w in words:
        cand = f"{cur} {w}".strip()
        if len(cand) > CMD_COLS and cur:
            lines.append(cur)
            cur = "  " + w
        else:
            cur = cand
    if cur:
        lines.append(cur)
    return lines


def parse_line(raw: str):
    """Línea ANSI -> [(texto, color, bold)] con estado entre tokens."""
    spans, pos, color, bold = [], 0, FG, False
    for m in TOKEN.finditer(raw):
        if m.start() > pos:
            spans.append((raw[pos:m.start()], color, bold))
        for code in [int(c) for c in (m.group(1) or "0").split(";")]:
            if code == 0:
                color, bold = FG, False
            elif code == 1:
                bold = True
            elif code == 39:
                color = FG
            elif code in ANSI:
                color = ANSI[code]
        pos = m.end()
    if pos < len(raw):
        spans.append((raw[pos:], color, bold))
    return [(t, c, b) for t, c, b in spans if t]


def truncate_spans(spans, limit):
    """Recorta una línea compuesta a `limit` caracteres visibles."""
    out, used = [], 0
    for text, color, bold in spans:
        if used >= limit:
            return out
        room = limit - used
        if len(text) > room:
            out.append((text[:room] + "\u2026", color, bold))
            return out
        out.append((text, color, bold))
        used += len(text)
    return out


def render(demo_dir: Path, out_path: Path):
    reg = ImageFont.truetype(FONT_REG, SIZE)
    bold = ImageFont.truetype(FONT_BOLD, SIZE)

    blocks = []
    for cmd, fname, cut in SECTIONS:
        cmd_lines = wrap_cmd(cmd)
        lines = [("cmd", [("charon@lab:~$ ", PROMPT, True), (cmd_lines[0], FG, False)])]
        for cont in cmd_lines[1:]:
            lines.append(("cmd", [(" " * 14, PROMPT, False), (cont, FG, False)]))
        for raw in (demo_dir / fname).read_text().splitlines():
            plain = TOKEN.sub("", raw).lstrip()
            if not plain:
                lines.append(("out", []))
                continue
            spans = parse_line(raw)
            if cut and plain.startswith("$krb5"):
                spans = truncate_spans(spans, 78)
                spans.append(("  [hash recortado]", MUTED, False))
            lines.append(("out", spans))
        blocks.append(lines)

    n_lines = sum(len(b) for b in blocks) + len(blocks) - 1
    height = BAR_H + PAD * 2 + n_lines * LINE_H
    img = Image.new("RGB", (WIDTH, height), BG)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, WIDTH, BAR_H], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 20, BAR_H // 2 - 6, 26 + i * 20, BAR_H // 2 + 6], fill=c)
    title = "charon \u2014 LAB.LOCAL @ MIT krb5 1.21.3 (127.0.0.1:1088)"
    tw = d.textlength(title, font=reg)
    d.text(((WIDTH - tw) / 2, (BAR_H - SIZE) / 2 - 1), title, font=reg, fill=MUTED)

    y = BAR_H + PAD
    for bi, block in enumerate(blocks):
        for kind, spans in block:
            if kind == "out" and not spans:
                y += LINE_H
                continue
            x = PAD
            for text, color, is_bold in spans:
                font = bold if is_bold else reg
                d.text((x, y), text, font=font, fill=color)
                x += d.textlength(text, font=font)
            y += LINE_H
        if bi < len(blocks) - 1:
            y += LINE_H

    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path, optimize=True)
    print(f"OK {out_path} ({WIDTH}x{height})")


if __name__ == "__main__":
    demo_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp")
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("docs/assets/charon-demo.png")
    render(demo_dir, out)
