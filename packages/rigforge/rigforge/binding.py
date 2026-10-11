"""
Replay binding: signed project identity + per-run challenge (schema 1.3.0).

Before 1.3.0 a valid signed packet could be replayed in two ways that the
phase/name claim check cannot see:

1. **Cross-project replay** — a packet copied from another project that uses
   the same signing key.
2. **Stale same-phase replay** — an older valid packet from an earlier run of
   the same phase.

The protocol that closes both:

* Before a run, the *caller* (CI job, human, or the cockpit server) issues a
  random challenge for one phase: ``rigforge challenge issue N``. The caller
  keeps the value. The issuer store in ``.rigforge/challenges.json`` records it
  as ``open`` so the sealer can refuse un-issued or already-used challenges.
* The sealer seals with ``rigforge seal N --challenge <nonce>``. The packet
  carries ``binding = {project_id, challenge}`` inside the hashed, HMAC-signed
  payload. The challenge is marked ``consumed``.
* The verifier runs ``rigforge verify --require-binding --expect-project <id>
  --expect-challenge N=<nonce>`` (or ``--expectations <file>``). The expected
  values come from the caller, never from the packet and never from the
  project directory the agent can write. ``--require-binding`` implies
  ``--require-signature``: an unsigned binding is self-asserted, since anyone
  can edit it and recompute the plain hash.

Legacy packets (no binding) pass only with the explicit ``--allow-unbound``
opt-in, which is refused together with ``--require-binding``.

What this does NOT stop: anyone who holds the signing key can seal any
binding they like. HMAC proves "someone with the key sealed this", not who.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rigforge.proof import ProofBinding, ProofPacket


CHALLENGE_STORE_PATH = Path(".rigforge") / "challenges.json"
# Placeholder project names that cannot identify a project. Sealing a binding
# with one of these would make every default project look identical.
PLACEHOLDER_PROJECT_IDS = frozenset({"", "rigforge-project"})
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_\-]{16,200}$")


class BindingError(ValueError):
    """Raised when a challenge or expectation is malformed or unusable."""


def new_challenge() -> str:
    """A fresh 192-bit url-safe nonce (32 characters)."""
    return secrets.token_urlsafe(24)


def validate_challenge(value: str) -> str:
    value = (value or "").strip()
    if not _CHALLENGE_RE.match(value):
        raise BindingError(
            "challenge must be 16-200 characters of [A-Za-z0-9_-] "
            "(issue one with `rigforge challenge issue <phase>`)."
        )
    return value


def validate_project_id(value: str | None) -> str:
    value = (value or "").strip()
    if value in PLACEHOLDER_PROJECT_IDS:
        raise BindingError(
            f"project id {value!r} is a placeholder and cannot identify a project; "
            "set `project:` in rigforge.yaml to a unique name."
        )
    return value


# ── Issuer store (sealer-side bookkeeping, never trusted by verify) ─────


class ChallengeStore:
    """Issued challenges for one project: ``open`` until sealed, then ``consumed``.

    The store lets ``seal`` refuse a challenge that was never issued, was issued
    for a different phase or project, or was already used. ``verify`` never
    reads it: the agent under verification can write this file.
    """

    def __init__(self, root: Path):
        self.path = Path(root) / CHALLENGE_STORE_PATH

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        data = json.loads(self.path.read_text() or "[]")
        if not isinstance(data, list):
            raise BindingError(f"{self.path} is not a JSON list")
        return data

    def _save(self, rows: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(rows, indent=2))
        os.replace(tmp, self.path)

    def issue(self, phase: int, project_id: str) -> str:
        project_id = validate_project_id(project_id)
        challenge = new_challenge()
        rows = self._load()
        rows.append({
            "phase": phase,
            "project_id": project_id,
            "challenge": challenge,
            "status": "open",
            "issued_at": datetime.now(timezone.utc).isoformat(),
        })
        self._save(rows)
        return challenge

    def consume(self, phase: int, project_id: str, challenge: str) -> None:
        challenge = validate_challenge(challenge)
        rows = self._load()
        for row in rows:
            if not hmac.compare_digest(str(row.get("challenge", "")), challenge):
                continue
            if row.get("status") != "open":
                raise BindingError("challenge was already used for a seal (reused nonce).")
            if int(row.get("phase", 0)) != phase:
                raise BindingError(
                    f"challenge was issued for phase {row.get('phase')}, not phase {phase}."
                )
            if row.get("project_id") != project_id:
                raise BindingError(
                    f"challenge was issued for project {row.get('project_id')!r}, "
                    f"not {project_id!r}."
                )
            row["status"] = "consumed"
            row["consumed_at"] = datetime.now(timezone.utc).isoformat()
            self._save(rows)
            return
        raise BindingError("challenge was never issued for this project.")


def bind_for_seal(root: Path, phase: int, project_id: str, challenge: str) -> ProofBinding:
    """Consume an issued challenge and return the binding to seal."""
    project_id = validate_project_id(project_id)
    ChallengeStore(root).consume(phase, project_id, challenge)
    return ProofBinding(project_id=project_id, challenge=challenge)


# ── Verifier-side expectations (caller-owned) ───────────────────────────


@dataclass
class ReplayExpectations:
    """What the verifier expects, sourced independently of the packets.

    ``require`` = strict mode: every sealed phase must carry a binding that
    matches both the expected project and an expected challenge.
    ``allow_unbound`` = legacy opt-in: packets without a binding are reported
    but not failed. The two are mutually exclusive.
    """

    project_id: str | None = None
    challenges: dict[int, str] = field(default_factory=dict)
    require: bool = False
    allow_unbound: bool = False

    @property
    def active(self) -> bool:
        return (self.require or self.allow_unbound or self.project_id is not None
                or bool(self.challenges))

    def validate(self) -> None:
        if self.require and self.allow_unbound:
            raise BindingError("--allow-unbound cannot be combined with strict verification.")
        if self.require and self.project_id is None:
            raise BindingError(
                "strict verification needs a trusted project id: pass --expect-project "
                "or an --expectations file with project_id."
            )
        if self.require and not self.challenges:
            raise BindingError(
                "strict verification needs at least one trusted challenge: pass "
                "--expect-challenge N=<nonce> for each phase sealed in this run."
            )
        if self.project_id is not None:
            self.project_id = validate_project_id(self.project_id)
        seen: dict[str, int] = {}
        for phase, value in self.challenges.items():
            value = validate_challenge(value)
            self.challenges[phase] = value
            if value in seen:
                raise BindingError(
                    f"the same challenge is expected for phases {seen[value]} and {phase} "
                    "(reused nonce); issue one challenge per phase per run."
                )
            seen[value] = phase


def parse_expect_challenge(items: tuple[str, ...] | list[str]) -> dict[int, str]:
    """Parse repeated ``N=<nonce>`` CLI values."""
    out: dict[int, str] = {}
    for item in items:
        phase_s, sep, value = item.partition("=")
        if not sep or not phase_s.strip().isdigit():
            raise BindingError(f"--expect-challenge must look like N=<nonce>, got {item!r}")
        phase = int(phase_s)
        if not 1 <= phase <= 7:
            raise BindingError(f"--expect-challenge phase must be 1-7, got {phase}")
        if phase in out:
            raise BindingError(f"--expect-challenge given twice for phase {phase}")
        out[phase] = value.strip()
    return out


def load_expectations_file(path: Path) -> tuple[str | None, dict[int, str]]:
    """Read a caller-owned ``{"project_id": ..., "challenges": {"N": ...}}`` file."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise BindingError("expectations file must be a JSON object")
    challenges_raw = data.get("challenges") or {}
    if not isinstance(challenges_raw, dict):
        raise BindingError("expectations 'challenges' must map phase -> challenge")
    challenges = parse_expect_challenge([f"{k}={v}" for k, v in challenges_raw.items()])
    project_id = data.get("project_id")
    return (str(project_id) if project_id is not None else None), challenges


def check_binding(
    packet: ProofPacket, phase: int, exp: ReplayExpectations
) -> tuple[list[str], dict[str, Any]]:
    """Compare one packet's signed binding with independent expectations.

    Returns ``(errors, report)``. Never reads expectations from the packet.
    """
    report: dict[str, Any] = {"bound": packet.binding is not None}
    errors: list[str] = []
    if packet.binding is None:
        report["legacy_unbound"] = True
        if not exp.allow_unbound:
            errors.append(
                f"Phase {phase}: packet has no replay binding (no project id or challenge "
                f"signed in); re-seal with `rigforge seal {phase} --challenge <nonce>`, "
                "or accept it as untrusted legacy with non-strict `verify --allow-unbound`."
            )
        return errors, report

    b = packet.binding
    report["project_id"] = b.project_id
    if exp.project_id is not None:
        project_ok = hmac.compare_digest(b.project_id.encode(), exp.project_id.encode())
        report["project_ok"] = project_ok
        if not project_ok:
            errors.append(
                f"Phase {phase}: packet was sealed for project {b.project_id!r}, "
                f"not {exp.project_id!r} (cross-project replay)."
            )
    expected = exp.challenges.get(phase)
    if expected is None:
        report["challenge_ok"] = None
        if exp.require:
            errors.append(
                f"Phase {phase}: no trusted challenge was supplied for this phase "
                f"(--expect-challenge {phase}=<nonce>); cannot rule out a stale packet."
            )
    else:
        challenge_ok = hmac.compare_digest(b.challenge.encode(), expected.encode())
        report["challenge_ok"] = challenge_ok
        if not challenge_ok:
            errors.append(
                f"Phase {phase}: packet challenge does not match the one issued for "
                "this run (stale or replayed proof)."
            )
    return errors, report


# ── One verify routine for CLI + cockpit ────────────────────────────────


def verify_proofs(
    ctx,
    *,
    strict: bool = False,
    require_signature: bool = False,
    signing_key: bytes | None = None,
    expectations: ReplayExpectations | None = None,
) -> dict[str, Any]:
    """Verify every sealed phase: schema, integrity, claim, signature, binding.

    ``expectations`` must already be validated. When it is active, every
    sealed phase is checked against it; when ``expectations.require`` is set
    the caller must also pass ``require_signature=True`` (the CLI and the
    cockpit enforce this).
    """
    from rigforge.harness import PHASES

    exp = expectations or ReplayExpectations()
    phase_reports: list[dict] = []
    sealed_phases: list[int] = []
    errors: list[str] = []
    warnings: list[str] = []
    seen_challenges: dict[str, int] = {}

    for p, name in PHASES.items():
        path = ctx.proof_file(p)
        if not path.exists():
            phase_reports.append({"phase": p, "name": name, "sealed": False})
            continue
        try:
            packet = ProofPacket.load(path)
        except Exception as exc:  # noqa: BLE001
            phase_reports.append({"phase": p, "name": name, "sealed": True, "error": str(exc)})
            errors.append(f"Phase {p}: schema invalid — {exc}")
            continue
        sealed_phases.append(p)
        integrity = packet.verify_integrity()
        signature_ok: bool | None = None
        if signing_key is not None and packet.signature:
            signature_ok = packet.verify_signature(signing_key)
        report: dict[str, Any] = {
            "phase": p,
            "name": name,
            "sealed": True,
            "verifier": packet.verifier,
            "artifact_count": len(packet.artifacts),
            "integrity_ok": integrity,
            "signed": bool(packet.signature),
            "signature_ok": signature_ok,
        }
        # A signature covers packet_sha256, so it proves nothing about the body
        # unless the hash is also re-checked: integrity is part of every
        # signature-requiring mode.
        if (strict or exp.require or require_signature) and not integrity \
                and packet.schema_version != "0.0.0":
            errors.append(f"Phase {p}: integrity hash mismatch.")
        if packet.schema_version != "0.0.0" and not packet.matches_claim(p, name):
            errors.append(
                f"Phase {p}: packet was sealed for phase {packet.phase} "
                f"{packet.name!r}, not phase {p} {name!r} (replayed proof)."
            )
        if signature_ok is False:
            # An invalid signature is never acceptable, in any mode.
            errors.append(f"Phase {p}: signature does not verify.")
        elif require_signature and not packet.signature:
            errors.append(f"Phase {p}: proof packet is not signed.")
        # Binding is checked in every mode; only the expectations vary.
        b_errors, b_report = check_binding(packet, p, exp)
        errors.extend(b_errors)
        report["binding"] = b_report
        if b_report.get("legacy_unbound") and exp.allow_unbound:
            warnings.append(f"Phase {p}: UNTRUSTED legacy packet without replay binding "
                            "accepted (--allow-unbound); replay is not ruled out.")
        if packet.binding is not None:
            prior = seen_challenges.get(packet.binding.challenge)
            if prior is not None:
                errors.append(
                    f"Phase {p}: packet reuses the challenge of phase {prior} (reused nonce)."
                )
            seen_challenges[packet.binding.challenge] = p
        phase_reports.append(report)

    if exp.challenges:
        for p in sorted(set(exp.challenges) - set(sealed_phases)):
            errors.append(
                f"Phase {p}: a challenge was issued for this run but no packet is sealed "
                "(missing proof)."
            )
    if strict and sealed_phases:
        expected = list(range(1, max(sealed_phases) + 1))
        gaps = sorted(set(expected) - set(sealed_phases))
        if gaps:
            errors.append(f"phase-order gaps (strict): missing {gaps}")
    if not exp.require and sealed_phases:
        if exp.allow_unbound:
            warnings.append(
                "UNTRUSTED (--allow-unbound): integrity and signatures checked, but replay "
                "is not ruled out; no caller expectations were supplied."
            )
        else:
            errors.append(
                "no trusted expectations: stale or cross-project replay cannot be ruled out. "
                "Pass --expect-project ID --expect-challenge N=NONCE (strict), or "
                "--allow-unbound to accept the packets as untrusted."
            )

    return {
        "ok": not errors,
        "strict": strict,
        "binding_checked": exp.require,
        "trusted": exp.require and not errors,
        "binding_required": exp.require,
        "phases": phase_reports,
        "errors": errors,
        "warnings": warnings,
    }
