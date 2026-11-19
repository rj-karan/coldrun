"""Write the man page and the bash, zsh and fish completions from the CLI itself.

Run ``uv run python packaging/generate.py`` after changing a command or flag;
``tests/unit/test_packaging.py`` fails while the committed files are stale.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer.main
from typer._completion_shared import get_completion_script

from coldrun.cli import app

HERE = Path(__file__).resolve().parent
ORDER = ("run", "scan", "deps", "doctor", "cache")
COMPLETIONS = {"bash": "coldrun.bash", "zsh": "_coldrun", "fish": "coldrun.fish"}


def _roff(text: str) -> str:
    """Escape text for a man page line."""
    text = text.replace("\\", "\\e").replace("-", "\\-")
    return "\\&" + text if text[:1] in {".", "'"} else text


def _command(name: str, cmd: object) -> list[str]:
    params = getattr(cmd, "params", [])
    args = " ".join(p.name.upper() for p in params if p.param_type_name == "argument")
    out = [f'.SS "coldrun {name}{" " + args if args else ""}"', _roff(cmd.help or "")]
    for p in params:
        if p.param_type_name != "option":
            continue
        flag = ", ".join(_roff(o) for o in p.opts)
        value = "" if p.is_flag else " \\fIVALUE\\fR"
        out += [".TP", f".B {flag}{value}", _roff(p.help or "")]
    for sub, child in getattr(cmd, "commands", {}).items():
        out += [".TP", f".B coldrun {name} {sub}", _roff(child.help or "")]
    return out


def man_page() -> str:
    """The roff source of ``coldrun(1)``."""
    root = typer.main.get_command(app)
    lines = [
        '.TH COLDRUN 1 "" "coldrun" "User Commands"',
        ".SH NAME",
        "coldrun \\- " + _roff((root.help or "").rstrip(".").lower()),
        ".SH SYNOPSIS",
        ".B coldrun",
        "\\fICOMMAND\\fR [\\fIOPTIONS\\fR] \\fISOURCE\\fR [\\-\\- \\fISCRIPT ARGS\\fR]",
        ".SH DESCRIPTION",
        "coldrun fetches a script into quarantine, works out its language and",
        "dependencies, vets the script and its dependencies, then runs it in a",
        "sandbox with no network, no home directory and a read\\-only root unless",
        "you allow more. The sandbox is the protection; the scan is the warning.",
        ".SH COMMANDS",
    ]
    for name in ORDER:
        lines += _command(name, root.commands[name])
    lines += [
        ".SH EXIT STATUS",
        "The script's own exit code, except:",
        ".TP",
        ".B 2",
        "usage error, or the source could not be fetched or recognised",
        ".TP",
        ".B 100",
        "refused by vetting (high risk without \\-\\-force, or medium risk declined)",
        ".TP",
        ".B 101",
        "the sandbox could not be set up; run \\fBcoldrun doctor\\fR",
        ".TP",
        ".B 102",
        "dependencies could not be resolved or installed",
        ".SH FILES",
        ".TP",
        ".I ~/.cache/coldrun/",
        "quarantine directories and cached dependency environments",
        ".TP",
        ".I ~/.config/coldrun/config.toml",
        "configuration",
        ".SH SEE ALSO",
        ".BR bwrap (1),",
        ".BR podman (1)",
        ".PP",
        "https://github.com/rj\\-karan/coldrun",
    ]
    return "\n".join(lines) + "\n"


def outputs() -> dict[Path, str]:
    """Every generated file and its content."""
    files = {HERE / "man" / "coldrun.1": man_page()}
    for shell, name in COMPLETIONS.items():
        script = get_completion_script(
            prog_name="coldrun", complete_var="_COLDRUN_COMPLETE", shell=shell
        )
        files[HERE / "completions" / name] = script.rstrip("\n") + "\n"
    return files


if __name__ == "__main__":
    for path, text in outputs().items():
        path.write_text(text)
        sys.stdout.write(f"wrote {path.relative_to(HERE.parent)}\n")
