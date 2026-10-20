"""CI configuration invariants for proof-studio."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(wf: dict):
    return wf.get("on", wf.get(True))  # PyYAML reads bare `on:` as boolean True


def test_ci_runs_on_push_and_pull_request_with_read_only_permissions():
    wf = _load("ci.yml")
    triggers = _triggers(wf)
    assert "push" in triggers and "pull_request" in triggers
    assert wf["permissions"] == {"contents": "read"}


def test_ci_matrix_covers_the_supported_python_range():
    matrix = _load("ci.yml")["jobs"]["studio"]["strategy"]["matrix"]
    assert matrix["python-version"] == ["3.11", "3.12", "3.13"]
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.11"' in pyproject


def test_ci_runs_the_suite_the_vectors_and_the_vendored_core():
    wf = _load("ci.yml")
    studio_steps = " ".join(s.get("run", "") for s in wf["jobs"]["studio"]["steps"] if isinstance(s, dict))
    assert "pytest" in studio_steps and "--cov" in studio_steps
    assert "proof-studio run" in studio_steps
    assert "core" in wf["jobs"]  # the vendored rigforge suite keeps running too


def test_smoke_workflow_runs_the_real_gate():
    wf = _load("smoke.yml")
    run_lines = " ".join(s.get("run", "") for s in wf["jobs"]["smoke"]["steps"] if isinstance(s, dict))
    assert "scripts/smoke.sh" in run_lines
    smoke = (REPO_ROOT / "scripts" / "smoke.sh").read_text(encoding="utf-8")
    assert "proof-studio run" in smoke


def test_mcp_server_has_no_hardcoded_home_path():
    server = (REPO_ROOT / "mcp" / "server.py").read_text(encoding="utf-8")
    assert "Path.home()" not in server
    assert "Developer/" not in server
    assert "RIG_LOOP" in server
