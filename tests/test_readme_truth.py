"""README truth lint for proof-studio."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

BANNED_WORDS = [
    "unlock", "empower", "synergy", "leverage", "disrupt", "hustle",
    "utilize", "iterate", "optimize", "1000x", "novel-to-the-world",
    "first in the world",
]

REQUIRED = [
    "## Why this exists",
    "## What it proves",
    "## Quickstart",
    "## How it works",
    "## Project layout",
    "## Development",
    "## License",
    "Built by Mike Rodgers",
]


def test_readme_has_no_banned_marketing_words():
    lowered = README.lower()
    found = [w for w in BANNED_WORDS if re.search(rf"\b{re.escape(w)}\b", lowered)]
    assert found == []


def test_readme_has_no_machine_paths_or_stale_packages():
    assert "/Users/" not in README
    assert "~/Developer" not in README
    assert "deterministic-build-starter" not in README  # not a real path in this repo


def test_readme_names_rigforge_as_the_core_library():
    assert "rigforge" in README
    assert "core library" in README


def test_readme_required_sections():
    for section in REQUIRED:
        assert section in README, f"missing section: {section}"
