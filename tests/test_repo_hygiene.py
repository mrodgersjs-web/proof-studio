"""Repository hygiene invariants (GHUP polish wave, 2026-10-19).

Asserts, from the files on disk, the repo-health items a stranger's tooling
checks first: CODEOWNERS ownership, the copilot instructions file, the README
badge/footer/clone target, and workflow timeouts with no `continue-on-error`.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
REPO = "proof-studio"


def test_codeowners_owns_everything():
    text = (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert "* @mrodgersjs-web" in text


def test_copilot_instructions_shape():
    p = REPO_ROOT / ".github" / "copilot-instructions.md"
    text = p.read_text(encoding="utf-8")
    assert 0 < p.stat().st_size <= 8000, f"copilot-instructions.md is {p.stat().st_size} bytes"
    assert any(word in text for word in ("pytest", "smoke", "npm test"))


def test_readme_badge_footer_and_clone_target():
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "github/actions/workflow/status" in text
    assert "rodgersintelligence.com" in text
    assert any(word in text for word in ("pytest", "smoke", "npm test", "node --test"))
    for line in text.splitlines():
        if "git clone" in line:
            assert f"mrodgersjs-web/{REPO}" in line, f"clone must target this repo: {line}"


def test_workflows_have_timeouts_and_no_continue_on_error():
    paths = sorted(WORKFLOWS.glob("*.yml"))
    assert paths, "no workflows found"
    for path in paths:
        wf = yaml.safe_load(path.read_text(encoding="utf-8"))
        raw = path.read_text(encoding="utf-8")
        assert "continue-on-error" not in raw, f"{path.name} uses continue-on-error"
        for job_name, job in wf.get("jobs", {}).items():
            assert job.get("timeout-minutes"), f"{path.name}:{job_name} has no timeout-minutes"


def test_test_job_runs_on_push_to_main():
    wf = yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))
    triggers = wf.get("on", wf.get(True))
    assert "push" in triggers and "pull_request" in triggers
    assert wf["jobs"], "ci.yml must keep real jobs"
