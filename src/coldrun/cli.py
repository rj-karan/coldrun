"""Typer application for the ``coldrun`` command.

This module wires command-line options to the pipeline and holds no logic of
its own. Commands are added here as the milestones land.
"""

from __future__ import annotations

from pathlib import Path

import typer

from coldrun import __version__
from coldrun import doctor as doctor_mod
from coldrun import pipeline as pipeline_mod
from coldrun.report import make_console
from coldrun.sandbox import NetPolicy

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
    doctor_mod.render(results, make_console())
    raise typer.Exit(code=1 if doctor_mod.has_failures(results) else 0)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    source: str = typer.Argument(..., help="Local path, http(s) URL or GitHub blob URL."),
    net: NetPolicy = typer.Option(
        NetPolicy.NONE, "--net", help="Network policy inside the sandbox.", case_sensitive=False
    ),
    rw: list[Path] = typer.Option([], "--rw", help="Mount one host path read-write; repeatable."),
    out: Path = typer.Option(
        Path("./coldrun-out"), "--out", help="Where files the script writes are copied on exit."
    ),
    backend: str | None = typer.Option(None, "--backend", help="Force a sandbox backend: bwrap."),
    lang: str | None = typer.Option(None, "--lang", help="Override type detection."),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation on medium risk."),
    force: bool = typer.Option(False, "--force", help="Run despite a high-risk verdict."),
) -> None:
    """Fetch, vet, sandbox and run SOURCE. Everything after -- goes to the script."""
    if net is NetPolicy.ALLOW:
        typer.echo("--net allow needs --allow-host, which arrives in v0.4.0 (#26).", err=True)
        raise typer.Exit(code=2)
    opts = pipeline_mod.RunOptions(
        source=source,
        args=list(ctx.args),
        net=net,
        rw=rw,
        out=out,
        backend=backend,
        lang=lang,
        yes=yes,
        force=force,
    )
    raise typer.Exit(code=pipeline_mod.run(opts, make_console(stderr=True)))


if __name__ == "__main__":  # pragma: no cover
    app()
