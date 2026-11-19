"""Allow ``python -m coldrun``."""

from __future__ import annotations

from coldrun.cli import app

app(prog_name="coldrun")  # same name, and completion variable, as the installed command
