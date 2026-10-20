"""Tamper scenarios: the manifest format and deterministic vector builders.

A scenario names one ProofPacket JSON vector plus the claim it is submitted
against and the verdict the verifier must reach. Vector builders are
deterministic (fixed timestamp, fixed artifact bytes), so regenerating the
committed vectors produces identical bytes.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ._signing import reforge, seal
from ._vendor import ensure_rigforge

ensure_rigforge()

from rigforge.proof import ArtifactRecord, GateOutcome, ProofPacket  # noqa: E402

# Demo and forger material: synthetic sequential byte patterns (32 bytes
# each). Public test fixtures so the committed vectors verify offline; real
# deployments keep signing material outside the repo (docs/public-boundary.md).
DEMO_MATERIAL = bytes(range(32))
FORGER_MATERIAL = bytes(range(32, 64))
FIXED_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
ARTIFACT_PATH = "build.out"
ARTIFACT_BODY = b"proof-studio demo build output\n"
BACKDOOR_BODY = b"backdoored build output\n"
KINDS = ("control", "tampered_artifact_hash", "forged_signature", "replay")
# Filenames match the vector list documented in tests/failures/README.md.
VECTOR_FILENAMES = {
    "control": "clean_build.json",
    "tampered_artifact_hash": "tampered_artifact_hash.json",
    "forged_signature": "forged_signature_no_key.json",
    "replay": "replay_attack.json",
}


@dataclass(frozen=True)
class Scenario:
    """One row of the scenario manifest."""

    file: str
    kind: str
    expect: str  # "accept" | "reject"
    claim_phase: int
    claim_name: str
    description: str = ""

    @property
    def is_forgery(self) -> bool:
        # A vector's nature comes from its kind, not from its expected verdict.
        return self.kind != "control"


def load_manifest(path: Path) -> list[Scenario]:
    """Read a scenario manifest (YAML) and validate its rows."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rows = raw.get("scenarios") if isinstance(raw, dict) else raw
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{path}: manifest must contain a non-empty 'scenarios' list")
    scenarios = []
    for i, row in enumerate(rows):
        try:
            sc = Scenario(
                file=str(row["file"]),
                kind=str(row["kind"]),
                expect=str(row["expect"]),
                claim_phase=int(row["claim"]["phase"]),
                claim_name=str(row["claim"]["name"]),
                description=str(row.get("description", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{path}: scenario row {i} is malformed: {exc}") from exc
        if sc.kind not in KINDS:
            raise ValueError(f"{path}: scenario row {i} has unknown kind {sc.kind!r}")
        if sc.expect not in ("accept", "reject"):
            raise ValueError(f"{path}: scenario row {i} has unknown expect {sc.expect!r}")
        scenarios.append(sc)
    return scenarios


# ── Deterministic vector builders ─────────────────────────────────────────


def honest_packet(name: str = "demo build", phase: int = 1) -> ProofPacket:
    """A genuine packet: one artifact, one passing gate, sealed with the demo material."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        artifact_file = base / ARTIFACT_PATH
        artifact_file.write_bytes(ARTIFACT_BODY)
        artifact = ArtifactRecord.from_path(artifact_file, base=base)
    packet = ProofPacket(
        phase=phase,
        name=name,
        sealed_at=FIXED_TIME,
        verifier="proof-studio",
        evidence="demo build sealed",
        artifacts=[artifact],
        gates=[GateOutcome(name="tests", passed=True, detail="demo gate")],
    )
    return seal(packet, DEMO_MATERIAL)


def _packet_json(packet: ProofPacket) -> str:
    return json.dumps(packet.model_dump(mode="json"), indent=2) + "\n"


def build_vector(kind: str) -> str:
    """Return the JSON text of one planted-failure vector.

    control                 honest packet, must be accepted
    tampered_artifact_hash  artifact hash swapped and packet hash re-forged
    forged_signature        signature made without the demo material
    replay                  valid packet, submitted against a newer claim
                            (the claim lives in the manifest, not the file)
    """
    if kind == "control":
        return _packet_json(honest_packet())
    honest = honest_packet()
    if kind == "tampered_artifact_hash":
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            artifact_file = base / ARTIFACT_PATH
            artifact_file.write_bytes(BACKDOOR_BODY)
            swapped = ArtifactRecord.from_path(artifact_file, base=base)
        forged = honest.model_copy(update={"artifacts": [swapped]})
        # Re-forge the packet hash so naive integrity passes; the signature is
        # still bound to the original hash and cannot be re-made without the demo material.
        return _packet_json(reforge(forged))
    if kind == "forged_signature":
        # Same payload and packet hash, but sealed with the forger material: the
        # verifier only accepts packets sealed with the demo material.
        return _packet_json(seal(honest, FORGER_MATERIAL))
    if kind == "replay":
        return _packet_json(honest)
    raise ValueError(f"unknown vector kind: {kind!r}")
