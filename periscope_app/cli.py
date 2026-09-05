"""CLI for periscope."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

import json

from .banner import PERISCOPE_BANNER
from .snapshot import check_scope, diff_snapshot, take_snapshot
from .store import add_program, list_programs

console = Console()


def _banner() -> None:
    console.print(f"[bold cyan]{PERISCOPE_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD scope snapshots."""


@main.command("add")
@click.argument("name")
@click.argument("url_or_file", required=False)
@click.option("--h1", is_flag=True, help="Treat name as H1 handle.")
def add_cmd(name: str, url_or_file: str | None, h1: bool) -> None:
    """Add a tracked program."""
    if h1:
        add_program(name, name, "h1")
    elif url_or_file:
        source_type = "url" if url_or_file.startswith(("http://", "https://")) else "file"
        add_program(name, url_or_file, source_type)
    else:
        raise click.UsageError("url-or-file is required unless --h1 is used")
    console.print(f"[green]Tracking[/green] {name}")


@main.command("check")
@click.argument("target")
@click.argument("program")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-вердикт (контракт пайплайна)")
def check_cmd(target: str, program: str, as_json: str | None) -> None:
    """🔴 Авторизационный гейт: в scope ли цель. code 0 можно · 1 СТОП · 2 неизвестно (не тестировать)."""
    d = check_scope(target, program)
    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    цвет = {"in-scope": "green", "out-of-scope": "red"}.get(d["verdict"], "yellow")
    console.print(f"Цель [bold]{d['host']}[/bold] · программа {program}: "
                  f"[{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")
    raise SystemExit(d["code"])


@main.command("snap")
@click.argument("name")
def snap_cmd(name: str) -> None:
    """Take a fresh snapshot."""
    path = take_snapshot(name)
    console.print(f"[green]Snapshot[/green] {path}")


@main.command("diff")
@click.argument("name")
def diff_cmd(name: str) -> None:
    """Show snapshot diff."""
    text, path = diff_snapshot(name)
    console.print(Markdown(text))
    console.print(f"[dim]Saved to {path}[/dim]")


@main.command("list")
def list_cmd() -> None:
    """List tracked programs."""
    table = Table(title="Tracked Programs")
    table.add_column("Name")
    table.add_column("Source Type")
    table.add_column("Source")
    for program in list_programs():
        table.add_row(program["name"], program["source_type"], program["source"])
    console.print(table)


@main.command("watch")
@click.argument("name")
@click.option("--interval", default="24h", show_default=True)
def watch_cmd(name: str, interval: str) -> None:
    """Print a cron-style watch hint."""
    console.print(
        f"Add to cron manually: periscope snap {name} && periscope diff {name}  # interval {interval}"
    )


if __name__ == "__main__":
    main()
