#!/usr/bin/env python3
"""Genera docs/assets/charon-demo.gif a partir de salidas REALES de charon.

Uso: python3 scripts/make_gif.py [dir-demos] [salida.gif]

Mismo principio que make_screenshot.py (la pareja para el PNG): cada línea
que aparece en el GIF es la salida tal cual de una ejecución real contra el
KDC MIT del lab (los hashes se recortan visualmente; el texto completo vive
en traces/ y en el dataset). La animación es una terminal: el comando se
"teclea", la salida aparece línea a línea y la pantalla avanza al siguiente
comando — una demo real, no un mockup.
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).parent))
from make_screenshot import (  # noqa: E402
    ANSI, BG, BAR, BAR_H, FG, MUTED, PROMPT, TOKEN, parse_line, truncate_spans,
)

FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SIZE = 15
LINE_H = 22
PAD = 26
WIDTH = 1040

# Paleta del GIF: menos colores que el PNG para mantener el fichero pequeño.
GIF_COLORS = 128

# Ritmo (ms por fotograma): tecleo rápida, salida línea a línea, pausa
# al terminar cada pantalla para que se pueda leer.
TYPE_MS = 45
TYPE_CHARS = 10       # caracteres nuevos por fotograma al teclear
LINE_MS = 120         # entre líneas de salida
HOLD_MS = 2400        # pausa final de cada pantalla
FIRST_HOLD_MS = 3200  # fotograma inicial (portada del GIF)

TITLE = "charon — LAB.LOCAL @ MIT krb5 1.21.3 (127.0.0.1:1088 · DELEG.LAB:1190)"

# Cada pantalla: (comando mostrado, fichero de salida real, recortar hashes,
# mostrar solo las primeras N líneas de la salida [None = todas]).
SCREENS = [
    ("charon enum --users jdoe,aesuser,legacy,nopreauth,ghost-inexistente "
     "-r LAB.LOCAL --port 1088", "demo-enum.txt", False, None),
    ("charon kerberoast --spn mssql/srv01.lab.local -u jdoe -p "
     "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022 "
     "-r LAB.LOCAL --port 1088", "demo-kerb.txt", True, None),
    ("charon as --user jdoe -p \u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022 "
     "-r LAB.LOCAL --port 1088 --renewable --ccache jdoe.ccache",
     "demo-as.txt", False, 3),
    ("charon ccache --file jdoe.ccache", "demo-ccache.txt", False, None),
    ("charon s4u2proxy --user service/1 --keytab service1.keytab "
     "--impersonate user --to service/1 --to-keytab service1.keytab "
     "--rbcd -r DELEG.LAB --port 1190", "demo-rbcd.txt", False, None),
]

CMD_COLS = 94


def wrap_cmd(cmd: str):
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


def out_lines(demo_dir: Path, fname: str, cut: bool, head: int | None):
    """Salida real -> lista de líneas [(texto, color, bold)]."""
    lines = []
    for raw in (demo_dir / fname).read_text().splitlines():
        plain = TOKEN.sub("", raw).lstrip()
        if not plain:
            lines.append([])
            continue
        spans = parse_line(raw)
        if cut and plain.startswith("$krb5"):
            spans = truncate_spans(spans, 78)
            spans.append(("  [hash recortado]", MUTED, False))
        lines.append(spans)
    if head is not None:
        lines = lines[:head]
    return lines


def draw_terminal(height: int, rows: list[list[tuple[str, tuple, bool]]], cursor_at: int | None):
    """Pinta la terminal completa: barra de título + filas dadas."""
    img = Image.new("RGB", (WIDTH, height), BG)
    d = ImageDraw.Draw(img)
    reg = ImageFont.truetype(FONT_REG, SIZE)
    bold = ImageFont.truetype(FONT_BOLD, SIZE)

    d.rectangle([0, 0, WIDTH, BAR_H], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 20, BAR_H // 2 - 6, 26 + i * 20, BAR_H // 2 + 6], fill=c)
    tw = d.textlength(TITLE, font=reg)
    d.text(((WIDTH - tw) / 2, (BAR_H - SIZE) / 2 - 1), TITLE, font=reg, fill=MUTED)

    y = BAR_H + PAD
    for ri, spans in enumerate(rows):
        x = PAD
        for text, color, is_bold in spans:
            font = bold if is_bold else reg
            d.text((x, y), text, font=font, fill=color)
            x += d.textlength(text, font=font)
        if cursor_at is not None and ri == len(rows) - 1:
            # Cursor de bloque al final de la última línea (efecto tecleo).
            cx = x + 2
            d.rectangle([cx, y + 2, cx + 9, y + SIZE + 2], fill=FG)
        y += LINE_H
    return img


def quantize(img: Image.Image) -> Image.Image:
    return img.convert("RGB").quantize(colors=GIF_COLORS, method=Image.MEDIANCUT, dither=Image.NONE)


def main():
    demo_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/charon-demo")
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("docs/assets/charon-demo.gif")

    # Prepara las pantallas: filas fijas por pantalla (comando completo +
    # salida completa) para calcular la altura estable del lienzo.
    screens = []
    for cmd, fname, cut, head in SCREENS:
        cmd_lines = wrap_cmd(cmd)
        outl = out_lines(demo_dir, fname, cut, head)
        screens.append((cmd_lines, outl))

    max_rows = 0
    for cmd_lines, outl in screens:
        max_rows = max(max_rows, len(cmd_lines) + len(outl) + 1)  # + línea prompt vacía
    height = BAR_H + PAD * 2 + max_rows * LINE_H

    frames: list[Image.Image] = []
    durations: list[int] = []

    for cmd_lines, outl in screens:
        # 1) tecleo del comando (con cursor de bloque): se recorren las
        # líneas del comando avanzando TYPE_CHARS por fotograma.
        total = sum(len(l) for l in cmd_lines)
        typed_n = 0
        while typed_n < total:
            typed_n = min(typed_n + TYPE_CHARS, total)
            rows, remaining = [], typed_n
            for li, full in enumerate(cmd_lines):
                take = min(remaining, len(full))
                shown = full[:take]
                remaining -= take
                if li == 0:
                    rows.append([("charon@lab:~$ ", PROMPT, True), (shown, FG, False)])
                elif shown or take:
                    rows.append([(" " * 14, PROMPT, False), (shown, FG, False)])
                if remaining <= 0:
                    break
            frames.append(quantize(draw_terminal(height, rows, len(rows) - 1)))
            durations.append(TYPE_MS)
        # 2) fotograma del comando completo, sin cursor (breve).
        rows = [[("charon@lab:~$ ", PROMPT, True), (cmd_lines[0], FG, False)]]
        for cont in cmd_lines[1:]:
            rows.append([(" " * 14, PROMPT, False), (cont, FG, False)])
        frames.append(quantize(draw_terminal(height, rows, None)))
        durations.append(220)
        # 3) salida línea a línea.
        shown = list(rows)
        for spans in outl:
            shown.append(spans if spans else [])
            frames.append(quantize(draw_terminal(height, [r for r in shown if r], None)))
            durations.append(LINE_MS)
        # 4) pausa final de la pantalla.
        frames.append(quantize(draw_terminal(height, [r for r in shown if r], None)))
        durations.append(HOLD_MS)

    out.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        out,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    kb = out.stat().st_size // 1024
    print(f"OK {out} ({WIDTH}x{height}, {len(frames)} fotogramas, {kb} KB)")


if __name__ == "__main__":
    main()
