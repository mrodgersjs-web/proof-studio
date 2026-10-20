"""Tests for proof_studio.runner."""

from __future__ import annotations

from pathlib import Path

import yaml

import pytest

from proof_studio.runner import ScenarioResult, run_manifest, run_scenario, summarize
from proof_studio.scenarios import Scenario, load_manifest

REPO_ROOT = Path(__file__).resolve().parents[1]
FAILURES = REPO_ROOT / "tests" / "failures"
MANIFEST = FAILURES / "scenarios.yml"


@pytest.fixture()
def vectors_dir(tmp_path):
    from proof_studio.cli import write_vectors

    write_vectors(tmp_path)
    return tmp_path


def test_manifest_run_summary_counts(vectors_dir):
    results = run_manifest(MANIFEST, vectors_dir)
    summary = summarize(results)
    assert summary["all_matched"] is True
    assert summary["scenarios"] == 4
    assert summary["forgeries"] == 3
    assert summary["caught"] == 3
    assert summary["wrongly_blocked"] == 0
    assert summary["false_done_caught_rate"] == 1.0
    assert summary["false_pass_rate"] == 0.0
    assert summary["accuracy"] == 1.0


def test_per_kind_outcomes(vectors_dir):
    by_kind = {r.scenario.kind: r for r in run_manifest(MANIFEST, vectors_dir)}
    assert by_kind["control"].outcome == "clean"
    assert by_kind["tampered_artifact_hash"].outcome == "caught"
    assert by_kind["forged_signature"].outcome == "caught"
    assert by_kind["replay"].outcome == "caught"
    # The forgeries fail on different checks.
    assert by_kind["tampered_artifact_hash"].integrity_ok is True
    assert by_kind["tampered_artifact_hash"].signature_ok is False
    assert by_kind["replay"].integrity_ok and by_kind["replay"].signature_ok
    assert by_kind["replay"].claim_ok is False


def test_mismatched_expectation_reports_mismatch(tmp_path, vectors_dir):
    # Swap the control row's expectation to "reject" and re-run.
    rows = yaml.safe_load(MANIFEST.read_text())
    rows["scenarios"][0]["expect"] = "reject"
    flipped = tmp_path / "scenarios.yml"
    flipped.write_text(yaml.safe_dump(rows))
    results = run_manifest(flipped, vectors_dir)
    summary = summarize(results)
    assert summary["all_matched"] is False
    assert results[0].matched is False
    assert results[0].actual == "accept"  # the verifier is right, the row is wrong


def test_outcome_classifier_labels_mislabelled_rows(vectors_dir):
    # The outcome classifier is the regression detector: a forgery the verifier
    # accepts must read as missed_forgery even if the manifest row is mislabelled.
    scenario = Scenario(
        file="tampered_artifact_hash.json",
        kind="tampered_artifact_hash",
        expect="accept",
        claim_phase=1,
        claim_name="demo build",
    )
    result = ScenarioResult(
        scenario=scenario,
        actual="accept",
        matched=True,
        integrity_ok=True,
        signature_ok=True,
        claim_ok=True,
        detail="synthetic: verifier accepted a forgery",
    )
    assert result.outcome == "missed_forgery"

    # The same vector under the real manifest.
    real = run_scenario(
        Scenario(
            file="tampered_artifact_hash.json",
            kind="tampered_artifact_hash",
            expect="reject",
            claim_phase=1,
            claim_name="demo build",
        ),
        vectors_dir,
    )
    assert real.outcome == "caught" and real.matched is True


def test_missing_vector_reports_mismatch(tmp_path):
    scenario = Scenario(file="absent.json", kind="control", expect="accept", claim_phase=1, claim_name="x")
    result = run_scenario(scenario, tmp_path)
    assert result.matched is False
    assert "vector missing" in result.detail


def test_manifest_shapes_add_up():
    scenarios = load_manifest(MANIFEST)
    assert [s.expect for s in scenarios].count("accept") == 1
    assert [s.expect for s in scenarios].count("reject") == 3
