"""Typer application for the ``coldrun`` command.

This module wires command-line options to the pipeline and holds no logic of
its own. Commands are added here as the milestones land.
"""

from __future__ import annotations

from pathlib import Path

import typer

from coldrun import __version__
from coldrun import cache as cache_mod
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


JSON_HELP = (
    "Print one JSON document on stdout (docs/report.schema.json); human output goes to stderr."
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


cache_app = typer.Typer(help="Manage cached dependency environments.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")


@cache_app.command("list")
def cache_list() -> None:
    """Show cached environments: key, runner, packages, size."""
    console = make_console()
    envs = cache_mod.list_envs()
    if not envs:
        console.print(f"no cached environments in {cache_mod.envs_root()}")
        return
    for env in envs:
        pkgs = ", ".join(env["packages"]) or "none"
        size = env["bytes"] // (1024 * 1024)
        console.print(f"{env['key']}  {env['runner']}  {size} MiB  {pkgs}")


@cache_app.command("clean")
def cache_clean() -> None:
    """Delete every cached environment."""
    make_console().print(f"removed {cache_mod.clean()} cached environment(s)")


@app.command()
def deps(
    source: str = typer.Argument(..., help="Local path, http(s) URL or GitHub blob URL."),
    lang: str | None = typer.Option(None, "--lang", help="Override type detection."),
    as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
) -> None:
    """Print the resolved dependencies of SOURCE without installing or running anything."""
    code = pipeline_mod.deps(source, lang, make_console(stderr=as_json), as_json=as_json)
    raise typer.Exit(code=code)


@app.command()
def scan(
    source: str = typer.Argument(..., help="Local path, http(s) URL or GitHub blob URL."),
    lang: str | None = typer.Option(None, "--lang", help="Override type detection."),
    as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
) -> None:
    """Vet SOURCE and print the findings and verdict without building a sandbox or running it."""
    code = pipeline_mod.scan(source, lang, make_console(stderr=as_json), as_json=as_json)
    raise typer.Exit(code=code)


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
    allow_host: list[str] = typer.Option(
        [], "--allow-host", help="Permit one HOST[:PORT]; repeatable; implies --net allow."
    ),
    listen: list[int] = typer.Option(
        [], "--listen", help="Forward one host port into the sandbox for callbacks; repeatable."
    ),
    rw: list[Path] = typer.Option([], "--rw", help="Mount one host path read-write; repeatable."),
    out: Path = typer.Option(
        Path("./coldrun-out"), "--out", help="Where files the script writes are copied on exit."
    ),
    backend: str | None = typer.Option(None, "--backend", help="Force a sandbox backend: bwrap."),
    lang: str | None = typer.Option(None, "--lang", help="Override type detection."),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation on medium risk."),
    force: bool = typer.Option(False, "--force", help="Run despite a high-risk verdict."),
    as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
) -> None:
    """Fetch, vet, sandbox and run SOURCE. Everything after -- goes to the script."""
    if allow_host and net is NetPolicy.NONE:
        net = NetPolicy.ALLOW
    if (net is NetPolicy.ALLOW) != bool(allow_host):
        typer.echo(
            "--net allow and --allow-host go together; --net full ignores the list.", err=True
        )
        raise typer.Exit(code=2)
    if listen and net is NetPolicy.FULL:
        typer.echo(
            "--listen is not needed with --net full: the script can bind the port.", err=True
        )
        raise typer.Exit(code=2)
    opts = pipeline_mod.RunOptions(
        source=source,
        args=list(ctx.args),
        net=net,
        allow_hosts=allow_host,
        listen=listen,
        rw=rw,
        out=out,
        backend=backend,
        lang=lang,
        yes=yes,
        force=force,
        json=as_json,
    )
    raise typer.Exit(code=pipeline_mod.run(opts, make_console(stderr=True)))


if __name__ == "__main__":  # pragma: no cover
    app()
