"""Typer application for the ``coldrun`` command.

This module wires command-line options to the pipeline and holds no logic of
its own. Commands are added here as the milestones land.
"""

from __future__ import annotations

import typer
from rich.console import Console

from coldrun import __version__
from coldrun import doctor as doctor_mod

app = typer.Typer(
    name="coldrun",
    help="Fetch, vet and sandbox any downloaded script in one command.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"coldrun {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Fetch, vet and sandbox any downloaded script in one command."""


@app.command()
def doctor() -> None:
    """Check bwrap, podman, uv and kernel support, and say how to fix what is missing."""
    results = doctor_mod.run_checks()
    doctor_mod.render(results, Console(highlight=False))
    raise typer.Exit(code=1 if doctor_mod.has_failures(results) else 0)


if __name__ == "__main__":  # pragma: no cover
    app()
