"""Tests for proof-studio packaging metadata."""

from __future__ import annotations

from importlib import metadata
from pathlib import Path

import proof_studio

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_installed_version_and_pyproject_agree():
    assert metadata.version("proof-studio") == proof_studio.__version__ == "1.0.0"


def test_console_script_is_installed():
    scripts = {ep.name for ep in metadata.entry_points(group="console_scripts")}
    assert "proof-studio" in scripts


def test_vendored_core_is_present_and_named_in_pyproject():
    assert (REPO_ROOT / "packages" / "rigforge" / "rigforge" / "proof.py").is_file()
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.11"' in pyproject
