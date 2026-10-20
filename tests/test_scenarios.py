"""Tests for proof_studio.scenarios."""

from __future__ import annotations

from pathlib import Path

import pytest

from proof_studio.runner import verify_packet
from proof_studio.scenarios import (
    DEMO_MATERIAL,
    KINDS,
    VECTOR_FILENAMES,
    build_vector,
    honest_packet,
    load_manifest,
)
from rigforge.proof import ProofPacket

REPO_ROOT = Path(__file__).resolve().parents[1]
FAILURES = REPO_ROOT / "tests" / "failures"


def test_manifest_covers_every_kind_and_matches_documented_names():
    scenarios = load_manifest(FAILURES / "scenarios.yml")
    assert {s.kind for s in scenarios} == set(KINDS)
    documented = {"clean_build.json", "tampered_artifact_hash.json", "forged_signature_no_key.json", "replay_attack.json"}
    assert {s.file for s in scenarios} == documented == set(VECTOR_FILENAMES.values())


def test_manifest_rejects_bad_rows(tmp_path):
    bad = tmp_path / "scenarios.yml"
    bad.write_text("scenarios:\n  - file: x.json\n    kind: teleport\n    expect: accept\n    claim: {phase: 1, name: x}\n")
    with pytest.raises(ValueError, match="unknown kind"):
        load_manifest(bad)
    bad.write_text("scenarios: []\n")
    with pytest.raises(ValueError, match="non-empty"):
        load_manifest(bad)


def test_vector_builders_are_deterministic():
    for kind in KINDS:
        assert build_vector(kind) == build_vector(kind)


def test_tampered_vector_integrity_and_signature_checks():
    packet = ProofPacket.model_validate_json(build_vector("tampered_artifact_hash"))
    assert packet.verify_integrity() is True  # the re-forged hash fools naive checks
    assert packet.verify_signature(DEMO_MATERIAL) is False


def test_forged_signature_vector_fails_signature_check():
    packet = ProofPacket.model_validate_json(build_vector("forged_signature"))
    assert packet.verify_integrity() is True
    assert packet.verify_signature(DEMO_MATERIAL) is False


def test_control_vector_checks_for_its_own_claim():
    packet = ProofPacket.model_validate_json(build_vector("control"))
    verdict, integrity_ok, signature_ok, claim_ok = verify_packet(packet, 1, "demo build")
    assert (verdict, integrity_ok, signature_ok, claim_ok) == ("accept", True, True, True)


def test_replay_vector_binds_to_its_own_claim_only():
    packet = ProofPacket.model_validate_json(build_vector("replay"))
    assert packet.verify_signature(DEMO_MATERIAL) is True
    assert packet.matches_claim(2, "later build") is False
    verdict, _, _, claim_ok = verify_packet(packet, 2, "later build")
    assert verdict == "reject" and claim_ok is False


def test_honest_packet_fields():
    packet = honest_packet()
    assert packet.verify_signature(DEMO_MATERIAL) is True
    assert packet.phase == 1 and packet.name == "demo build"
