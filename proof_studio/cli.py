"""proof-studio command line: run tamper scenarios, list them, build vectors."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from . import __version__
from .report import render_json, render_text
from .runner import run_manifest
from .scenarios import KINDS, VECTOR_FILENAMES, build_vector, load_manifest


def write_vectors(out: Path) -> None:
    """Write the planted-failure vector files (deterministic; safe to re-run)."""
    out.mkdir(parents=True, exist_ok=True)
    for kind in KINDS:
        (out / VECTOR_FILENAMES[kind]).write_text(build_vector(kind), encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "failures" / "scenarios.yml"
DEFAULT_VECTORS = REPO_ROOT / "tests" / "failures"


@click.group()
@click.version_option(__version__, prog_name="proof-studio")
def main() -> None:
    """Tamper-scenario studio around rigforge: author, run and verify planted failures."""


@main.command()
@click.option("--manifest", type=click.Path(path_type=Path), default=DEFAULT_MANIFEST, show_default=True)
@click.option("--vectors", type=click.Path(path_type=Path), default=DEFAULT_VECTORS, show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Machine-readable report.")
def run(manifest: Path, vectors: Path, as_json: bool) -> None:
    """Rebuild the vectors from their builders, verify each one, and fail on any
    expectation that is not met."""
    write_vectors(vectors)
    results = run_manifest(manifest, vectors)
    click.echo(render_json(results) if as_json else render_text(results))
    if not all(r.matched for r in results):
        sys.exit(1)


@main.command("list")
@click.option("--manifest", type=click.Path(path_type=Path), default=DEFAULT_MANIFEST, show_default=True)
def list_scenarios(manifest: Path) -> None:
    """List the scenarios in a manifest."""
    for sc in load_manifest(manifest):
        click.echo(f"{sc.file:<28} {sc.kind:<24} expect={sc.expect:<7} claim=phase {sc.claim_phase} {sc.claim_name!r}")


@main.command("build-vectors")
@click.option("--out", type=click.Path(path_type=Path), default=DEFAULT_VECTORS, show_default=True)
def build_vectors(out: Path) -> None:
    write_vectors(out)
    for kind in KINDS:
        click.echo(f"wrote {out / VECTOR_FILENAMES[kind]}")


if __name__ == "__main__":
    main()
