"""Typer application for the ``muzzle`` command.

This module wires command-line options to the pipeline and holds no logic of
its own. Commands are added here as the milestones land.
"""

from __future__ import annotations

import typer

from muzzle import __version__

app = typer.Typer(
    name="muzzle",
    help="Fetch, vet and sandbox any downloaded script in one command.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"muzzle {__version__}")
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


if __name__ == "__main__":  # pragma: no cover
    app()
