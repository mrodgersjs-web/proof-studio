"""Tests for proof_studio.cli."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from proof_studio.cli import main
from proof_studio.scenarios import KINDS, VECTOR_FILENAMES, build_vector

REPO_ROOT = Path(__file__).resolve().parents[1]
FAILURES = REPO_ROOT / "tests" / "failures"


def test_run_builds_and_verifies():
    res = CliRunner().invoke(main, ["run"])
    assert res.exit_code == 0, res.output
    assert "ALL EXPECTATIONS MET" in res.output
    assert "false-done-caught rate 1.00" in res.output


def test_run_json_report_shape():
    res = CliRunner().invoke(main, ["run", "--json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["summary"]["all_matched"] is True
    assert len(payload["results"]) == 4
    assert {r["outcome"] for r in payload["results"]} == {"clean", "caught"}


def test_list_shows_every_scenario():
    res = CliRunner().invoke(main, ["list"])
    assert res.exit_code == 0, res.output
    for name in VECTOR_FILENAMES.values():
        assert name in res.output


def test_build_vectors_output_matches_committed_bytes(tmp_path):
    res = CliRunner().invoke(main, ["build-vectors", "--out", str(tmp_path)])
    assert res.exit_code == 0, res.output
    for kind in KINDS:
        name = VECTOR_FILENAMES[kind]
        assert (tmp_path / name).read_text() == (FAILURES / name).read_text(), f"{name} drifted from the committed vector"


def test_run_exit_code_on_a_broken_manifest(tmp_path):
    manifest = tmp_path / "scenarios.yml"
    manifest.write_text(
        "scenarios:\n"
        "  - file: clean_build.json\n    kind: control\n    expect: reject\n"
        "    claim: {phase: 1, name: demo build}\n"
    )
    res = CliRunner().invoke(main, ["run", "--manifest", str(manifest), "--vectors", str(FAILURES)])
    assert res.exit_code == 1
    assert "MISMATCH" in res.output
