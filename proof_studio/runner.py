"""Run tamper scenarios against the real rigforge verifier.

The verification policy is the strict one: the packet must pass integrity,
its HMAC signature must verify against the demo key, and it must match the
claim it is submitted against (phase and name). A scenario matches when the
verifier reaches the verdict the manifest expects.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

from ._vendor import ensure_rigforge

ensure_rigforge()

from rigforge.proof import ProofPacket  # noqa: E402

from .scenarios import DEMO_MATERIAL, Scenario, load_manifest  # noqa: E402


@dataclass(frozen=True)
class ScenarioResult:
    scenario: Scenario
    actual: str  # "accept" | "reject"
    matched: bool
    integrity_ok: bool
    signature_ok: bool
    claim_ok: bool
    detail: str

    @property
    def outcome(self) -> str:
        # Classified by what the vector really is versus what the verifier did,
        # so a regression shows up as missed_forgery even if a manifest row is
        # mislabelled.
        if self.scenario.is_forgery:
            return "caught" if self.actual == "reject" else "missed_forgery"
        return "clean" if self.actual == "accept" else "wrongly_blocked"

    def as_dict(self) -> dict:
        d = asdict(self)
        d["outcome"] = self.outcome
        return d


def verify_packet(packet: ProofPacket, claim_phase: int, claim_name: str) -> tuple[str, bool, bool, bool]:
    """Apply the strict policy; return (verdict, integrity_ok, signature_ok, claim_ok)."""
    integrity_ok = packet.verify_integrity()
    signature_ok = packet.verify_signature(DEMO_MATERIAL)
    claim_ok = packet.matches_claim(claim_phase, claim_name)
    verdict = "accept" if (integrity_ok and signature_ok and claim_ok) else "reject"
    return verdict, integrity_ok, signature_ok, claim_ok


def run_scenario(scenario: Scenario, vectors_dir: Path) -> ScenarioResult:
    path = Path(vectors_dir) / scenario.file
    if not path.is_file():
        return ScenarioResult(
            scenario=scenario,
            actual="reject",
            matched=False,
            integrity_ok=False,
            signature_ok=False,
            claim_ok=False,
            detail=f"vector missing: {path}",
        )
    packet = ProofPacket.load(path)
    actual, integrity_ok, signature_ok, claim_ok = verify_packet(
        packet, scenario.claim_phase, scenario.claim_name
    )
    failed = [
        name
        for name, ok in (("integrity", integrity_ok), ("signature", signature_ok), ("claim binding", claim_ok))
        if not ok
    ]
    return ScenarioResult(
        scenario=scenario,
        actual=actual,
        matched=actual == scenario.expect,
        integrity_ok=integrity_ok,
        signature_ok=signature_ok,
        claim_ok=claim_ok,
        detail="rejected on: " + ", ".join(failed) if failed else "all checks passed",
    )


def run_manifest(manifest_path: Path, vectors_dir: Path) -> list[ScenarioResult]:
    return [run_scenario(sc, vectors_dir) for sc in load_manifest(manifest_path)]


def summarize(results: list[ScenarioResult]) -> dict:
    forgeries = [r for r in results if r.scenario.is_forgery]
    controls = [r for r in results if not r.scenario.is_forgery]
    caught = [r for r in forgeries if r.actual == "reject"]
    wrongly_blocked = [r for r in controls if r.actual == "reject"]
    return {
        "scenarios": len(results),
        "forgeries": len(forgeries),
        "caught": len(caught),
        "controls": len(controls),
        "wrongly_blocked": len(wrongly_blocked),
        "false_done_caught_rate": (len(caught) / len(forgeries)) if forgeries else 0.0,
        "false_pass_rate": (len(wrongly_blocked) / len(controls)) if controls else 0.0,
        "accuracy": (sum(1 for r in results if r.matched) / len(results)) if results else 0.0,
        "all_matched": all(r.matched for r in results),
    }
