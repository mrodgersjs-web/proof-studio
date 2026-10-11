"""Replay binding (schema 1.3.0): signed project id + per-run challenge.

Every attack below uses REAL sealed, signed packets and the real CLI / cockpit
code paths. Expectations always come from the test acting as the caller,
never from the packet under test.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from rigforge.binding import (
    BindingError,
    ChallengeStore,
    ReplayExpectations,
    check_binding,
    parse_expect_challenge,
)
from rigforge.cli import main
from rigforge.config import DEFAULT_SIGNING_KEY_PATH
from rigforge.proof import ProofBinding, ProofPacket

SHARED_KEY = "shared-key-for-two-projects-0123456789"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def _shared_key(monkeypatch):
    # Both projects in a test sign with ONE key: the worst case for replay.
    monkeypatch.setenv("RIGFORGE_SIGNING_KEY", SHARED_KEY)


def _mkproject(base: Path, name: str, runner: CliRunner) -> Path:
    root = (base / name)
    root.mkdir()
    root = root.resolve()
    (root / "pyproject.toml").write_text(f"[project]\nname='{name}'\n")
    (root / "rigforge").mkdir()
    (root / "contracts" / "v1").mkdir(parents=True)
    assert runner.invoke(main, ["--cwd", str(root), "init"]).exit_code == 0
    cfg = root / "rigforge.yaml"
    lines = [f"project: {name}" if ln.startswith("project:") else ln
             for ln in cfg.read_text().splitlines()]
    cfg.write_text("\n".join(lines) + "\n")
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "evidence.txt").write_text(f"evidence for {name}\n")
    return root


def _cli(runner, root: Path, *args: str):
    return runner.invoke(main, ["--cwd", str(root), *args])


def _issue(runner, root: Path, phase: int) -> str:
    res = _cli(runner, root, "challenge", "issue", str(phase))
    assert res.exit_code == 0, res.output
    return res.output.strip()


def _seal(runner, root: Path, phase: int, challenge: str | None = None):
    args = ["seal", str(phase), "--artifact", str(root / "docs" / "evidence.txt")]
    if challenge is not None:
        args += ["--challenge", challenge]
    return _cli(runner, root, *args)


def _verify(runner, root: Path, *args: str):
    res = _cli(runner, root, "--json", "verify", *args)
    payload = json.loads(res.output) if res.output.lstrip().startswith("{") else None
    return res, payload


def _proof(root: Path, phase: int) -> Path:
    return next(root.rglob(f"phase{phase}_proof.json"))


@pytest.fixture
def alpha(tmp_path, runner):
    return _mkproject(tmp_path, "alpha", runner)


@pytest.fixture
def beta(tmp_path, runner):
    return _mkproject(tmp_path, "beta", runner)


# ── positive paths ──────────────────────────────────────────────────────


def test_same_project_current_run_passes_cli(runner, alpha):
    n1 = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, n1).exit_code == 0
    packet = ProofPacket.load(_proof(alpha, 1))
    assert packet.schema_version == "1.3.0"
    assert packet.binding == ProofBinding(project_id="alpha", challenge=n1)
    res, payload = _verify(runner, alpha, "--strict", "--require-binding",
                           "--expect-project", "alpha", "--expect-challenge", f"1={n1}")
    assert res.exit_code == 0, res.output
    assert payload["ok"] is True and payload["binding_required"] is True
    phase1 = payload["phases"][0]
    assert phase1["signature_ok"] is True
    assert phase1["binding"] == {"bound": True, "project_id": "alpha",
                                 "project_ok": True, "challenge_ok": True}


def test_expectations_file_positive_path(runner, alpha, tmp_path):
    n1 = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, n1).exit_code == 0
    exp = tmp_path / "caller-expectations.json"  # outside the project dir
    exp.write_text(json.dumps({"project_id": "alpha", "challenges": {"1": n1}}))
    res, payload = _verify(runner, alpha, "--require-binding", "--expectations", str(exp))
    assert res.exit_code == 0 and payload["ok"] is True


# ── attacks that must FAIL CLOSED ───────────────────────────────────────


def test_same_key_cross_project_replay_rejected(runner, alpha, beta):
    na = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, na).exit_code == 0
    nb = _issue(runner, beta, 1)
    assert _seal(runner, beta, 1, nb).exit_code == 0
    # Copy alpha's genuine, same-key signed packet over beta's.
    shutil.copy(_proof(alpha, 1), _proof(beta, 1))
    res, payload = _verify(runner, beta, "--require-binding", "--expect-project", "beta",
                           "--expect-challenge", f"1={nb}")
    assert res.exit_code == 1
    phase1 = payload["phases"][0]
    assert phase1["signature_ok"] is True  # the packet itself is genuine
    assert any("sealed for project 'alpha', not 'beta'" in e for e in payload["errors"])
    # Even with alpha's own challenge as the expectation, the project id fails.
    res, payload = _verify(runner, beta, "--require-binding", "--expect-project", "beta",
                           "--expect-challenge", f"1={na}")
    assert res.exit_code == 1
    assert any("cross-project replay" in e for e in payload["errors"])


def test_before_fix_shape_same_key_cross_project_passes_without_binding(runner, alpha, beta):
    """Documents the pre-1.3 gap: the old flags alone still accept the copy.

    This is why --require-binding exists; it is not a regression.
    """
    assert _seal(runner, alpha, 1).exit_code == 0
    assert _seal(runner, beta, 1).exit_code == 0
    shutil.copy(_proof(alpha, 1), _proof(beta, 1))
    res, payload = _verify(runner, beta, "--strict", "--require-signature")
    assert res.exit_code == 0
    assert any("replay binding not checked" in w for w in payload["warnings"])


def test_stale_same_phase_packet_rejected(runner, alpha, tmp_path):
    n1 = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, n1).exit_code == 0
    old = tmp_path / "run1.json"
    shutil.copy(_proof(alpha, 1), old)
    n2 = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, n2).exit_code == 0
    shutil.copy(old, _proof(alpha, 1))  # put the run-1 packet back
    res, payload = _verify(runner, alpha, "--strict", "--require-binding",
                           "--expect-project", "alpha", "--expect-challenge", f"1={n2}")
    assert res.exit_code == 1
    assert payload["phases"][0]["signature_ok"] is True
    assert any("stale or replayed proof" in e for e in payload["errors"])


def test_altered_binding_scope_breaks_signature(runner, alpha, beta):
    nb = _issue(runner, beta, 1)
    na = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, na).exit_code == 0
    # Attacker without the key rewrites the binding to beta and re-hashes.
    forged = ProofPacket.load(_proof(alpha, 1)).model_copy(
        update={"binding": ProofBinding(project_id="beta", challenge=nb)}
    )
    forged = forged.model_copy(update={"packet_sha256": forged.compute_hash()})
    assert forged.verify_integrity() is True
    target = beta / "proofs"
    target.mkdir(exist_ok=True)
    dest = beta / _proof(alpha, 1).relative_to(alpha)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(forged.model_dump(mode="json")))
    res, payload = _verify(runner, beta, "--require-binding", "--expect-project", "beta",
                           "--expect-challenge", f"1={nb}")
    assert res.exit_code == 1
    assert any("signature does not verify" in e for e in payload["errors"])


def test_unsigned_binding_is_refused_under_require_binding(runner, alpha):
    n1 = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, n1).exit_code == 0
    path = _proof(alpha, 1)
    unsigned = ProofPacket.load(path).model_copy(update={"signature": ""})
    path.write_text(json.dumps(unsigned.model_dump(mode="json")))
    res, payload = _verify(runner, alpha, "--require-binding", "--expect-project", "alpha",
                           "--expect-challenge", f"1={n1}")
    assert res.exit_code == 1
    assert any("not signed" in e for e in payload["errors"])


def test_reused_challenge_refused_at_seal(runner, alpha):
    n1 = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, n1).exit_code == 0
    res = _seal(runner, alpha, 1, n1)
    assert res.exit_code == 2
    assert "reused nonce" in res.output


def test_unissued_and_wrong_phase_challenges_refused_at_seal(runner, alpha):
    res = _seal(runner, alpha, 1, "self-made-nonce-not-issued-0001")
    assert res.exit_code == 2 and "never issued" in res.output
    n2 = _issue(runner, alpha, 2)
    res = _seal(runner, alpha, 1, n2)
    assert res.exit_code == 2 and "issued for phase 2" in res.output


def test_reused_nonce_across_phases_rejected_at_verify(runner, alpha):
    n1 = _issue(runner, alpha, 1)
    res = _cli(runner, alpha, "--json", "verify", "--require-binding",
               "--expect-project", "alpha",
               "--expect-challenge", f"1={n1}", "--expect-challenge", f"2={n1}")
    assert res.exit_code == 2 and "reused nonce" in res.output


def test_missing_challenge_expectation_fails_closed(runner, alpha):
    n1 = _issue(runner, alpha, 1)
    assert _seal(runner, alpha, 1, n1).exit_code == 0
    res, payload = _verify(runner, alpha, "--require-binding", "--expect-project", "alpha")
    assert res.exit_code == 1
    assert any("no trusted challenge" in e for e in payload["errors"])


def test_missing_expected_project_is_usage_error(runner, alpha):
    res = _cli(runner, alpha, "verify", "--require-binding")
    assert res.exit_code == 2 and "--expect-project" in res.output


def test_missing_nonce_in_packet_fails_closed(runner, alpha):
    assert _seal(runner, alpha, 1).exit_code == 0  # sealed without --challenge
    res, payload = _verify(runner, alpha, "--require-binding", "--expect-project", "alpha",
                           "--expect-challenge", "1=" + "x" * 32)
    assert res.exit_code == 1
    assert any("no replay binding" in e for e in payload["errors"])


def test_expected_phase_with_no_packet_fails(runner, alpha):
    n1 = _issue(runner, alpha, 1)
    res, payload = _verify(runner, alpha, "--require-binding", "--expect-project", "alpha",
                           "--expect-challenge", f"1={n1}")
    assert res.exit_code == 1
    assert any("missing proof" in e for e in payload["errors"])


def test_wrong_slot_bound_packet_rejected(runner, alpha):
    n1 = _issue(runner, alpha, 1)
    n2 = _issue(runner, alpha, 2)
    assert _seal(runner, alpha, 1, n1).exit_code == 0
    p1 = _proof(alpha, 1)
    shutil.copy(p1, p1.parent / "phase2_proof.json")
    res, payload = _verify(runner, alpha, "--require-binding", "--expect-project", "alpha",
                           "--expect-challenge", f"1={n1}", "--expect-challenge", f"2={n2}")
    assert res.exit_code == 1
    errs = " ".join(payload["errors"])
    assert "sealed for phase 1" in errs
    assert "Phase 2: packet challenge does not match" in errs
    assert "reuses the challenge of phase 1" in errs


def test_legacy_optin_cannot_satisfy_strict(runner, alpha):
    assert _seal(runner, alpha, 1).exit_code == 0
    res = _cli(runner, alpha, "verify", "--require-binding", "--allow-unbound",
               "--expect-project", "alpha")
    assert res.exit_code == 2 and "cannot be combined" in res.output
    # Without --require-binding, the opt-in accepts the legacy packet with a warning.
    res, payload = _verify(runner, alpha, "--expect-project", "alpha", "--allow-unbound")
    assert res.exit_code == 0
    assert payload["binding_required"] is False
    assert any("legacy packet" in w for w in payload["warnings"])
    # ...and without the opt-in, the same expectations reject it.
    res, payload = _verify(runner, alpha, "--expect-project", "alpha")
    assert res.exit_code == 1


def test_pre_13_packet_hash_still_verifies(runner, alpha):
    """Migration: a 1.2.0 packet (no binding key) keeps a valid hash + signature."""
    key = SHARED_KEY.encode()
    legacy = ProofPacket(schema_version="1.2.0", phase=1, name="Bootstrap & Doctrine",
                         verifier="old").sealed(signing_key=key)
    raw = legacy.model_dump(mode="json")
    raw.pop("binding")
    path = alpha / "legacy.json"
    path.write_text(json.dumps(raw))
    loaded = ProofPacket.load(path)
    assert loaded.binding is None
    assert loaded.verify_integrity() and loaded.verify_signature(key)


def test_placeholder_project_cannot_bind(runner, tmp_path):
    root = tmp_path / "anon"
    root.mkdir()
    (root / "rigforge.yaml").write_text("project: rigforge-project\n")
    res = _cli(runner, root.resolve(), "challenge", "issue", "1")
    assert res.exit_code == 2 and "placeholder" in res.output


def test_seal_with_challenge_requires_signing_key(runner, alpha, monkeypatch):
    n1 = _issue(runner, alpha, 1)
    monkeypatch.delenv("RIGFORGE_SIGNING_KEY")
    (alpha / DEFAULT_SIGNING_KEY_PATH).unlink()
    res = _seal(runner, alpha, 1, n1)
    assert res.exit_code == 2 and "signing key" in res.output


# ── unit level: no self-asserted expectations ───────────────────────────


def test_check_binding_never_uses_packet_values():
    pkt = ProofPacket(phase=1, name="x", verifier="v",
                      binding=ProofBinding(project_id="alpha", challenge="c" * 20))
    # No expectations at all under require -> fails, not "matches itself".
    errs, _ = check_binding(pkt, 1, ReplayExpectations(project_id="beta", require=True))
    assert any("cross-project" in e for e in errs)
    assert any("no trusted challenge" in e for e in errs)


def test_expectation_parsing_rejects_bad_input():
    with pytest.raises(BindingError):
        parse_expect_challenge(["1"])
    with pytest.raises(BindingError):
        parse_expect_challenge(["9=" + "a" * 20])
    with pytest.raises(BindingError):
        ReplayExpectations(project_id="alpha", challenges={1: "short"}).validate()


def test_challenge_store_consume_once(tmp_path):
    store = ChallengeStore(tmp_path)
    c = store.issue(3, "alpha")
    with pytest.raises(BindingError, match="project"):
        store.consume(3, "beta", c)
    store.consume(3, "alpha", c)
    with pytest.raises(BindingError, match="reused"):
        store.consume(3, "alpha", c)


# ── cockpit (webapp) path ───────────────────────────────────────────────


def _client(root: Path, expected_project: str | None):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from rigforge.context import ProjectContext
    from rigforge.webapp import build_app

    return TestClient(build_app(ProjectContext.discover(root),
                                expected_project=expected_project))


def test_webapp_current_run_passes_and_stale_fails(alpha, tmp_path):
    c = _client(alpha, "alpha")
    n1 = c.post("/api/phases/1/challenge").json()["challenge"]
    r = c.post("/api/phases/1/seal", json={"challenge": n1})
    assert r.status_code == 200 and r.json()["bound"] is True
    v = c.get("/api/verify", params={"require_binding": True}).json()
    assert v["ok"] is True, v
    # Reuse of the consumed challenge is refused.
    assert c.post("/api/phases/1/seal", json={"challenge": n1}).status_code == 409
    # A self-made challenge the server never issued is refused.
    assert c.post("/api/phases/1/seal",
                  json={"challenge": "agent-made-nonce-000000"}).status_code == 409
    # New run: the server issues a new challenge; the old packet is now stale.
    old = tmp_path / "old.json"
    shutil.copy(_proof(alpha, 1), old)
    n2 = c.post("/api/phases/1/challenge").json()["challenge"]
    assert c.post("/api/phases/1/seal", json={"challenge": n2}).status_code == 200
    assert c.get("/api/verify", params={"require_binding": True}).json()["ok"] is True
    shutil.copy(old, _proof(alpha, 1))
    v = c.get("/api/verify", params={"require_binding": True}).json()
    assert v["ok"] is False
    assert any("stale or replayed proof" in e for e in v["errors"])


def test_webapp_cross_project_same_key_fails(alpha, beta):
    ca = _client(alpha, "alpha")
    na = ca.post("/api/phases/1/challenge").json()["challenge"]
    assert ca.post("/api/phases/1/seal", json={"challenge": na}).status_code == 200
    cb = _client(beta, "beta")
    nb = cb.post("/api/phases/1/challenge").json()["challenge"]
    assert cb.post("/api/phases/1/seal", json={"challenge": nb}).status_code == 200
    shutil.copy(_proof(alpha, 1), _proof(beta, 1))
    v = cb.get("/api/verify", params={"require_binding": True}).json()
    assert v["ok"] is False
    assert any("cross-project replay" in e for e in v["errors"])


def test_webapp_without_trusted_project_fails_closed(alpha):
    c = _client(alpha, None)
    assert c.post("/api/phases/1/challenge").status_code == 409
    assert c.post("/api/phases/1/seal").status_code == 200  # unbound seal still allowed
    v = c.get("/api/verify", params={"require_binding": True}).json()
    assert v["ok"] is False
    assert any("--expect-project" in e for e in v["errors"])
    # Default verify keeps the old behaviour.
    assert c.get("/api/verify").json()["ok"] is True


# ── MCP path ────────────────────────────────────────────────────────────


def test_mcp_seal_and_verify_binds_server_project(alpha, monkeypatch):
    from rigforge.mcp_server import seal_and_verify

    monkeypatch.chdir(alpha)
    out = seal_and_verify("agent-x", "Bootstrap & Doctrine",
                          artifacts=["docs/evidence.txt"], phase=1)
    assert out["accepted"] is True and out["binding_ok"] is True
    assert out["binding"]["project_id"] == "alpha"
    monkeypatch.setenv("RIGFORGE_PROJECT_ID", "rigforge-project")
    out = seal_and_verify("agent-x", "Bootstrap & Doctrine", phase=1)
    assert out["binding_ok"] is None and "placeholder" in out["binding"]["error"]


def test_mcp_legacy_proof_seal_fails_require_binding(runner, alpha, monkeypatch):
    from rigforge import mcp_server

    monkeypatch.chdir(alpha)
    monkeypatch.setattr(mcp_server, "PROOF_DIR", alpha / "proofs")
    mcp_server.proof_seal(1, ["docs/evidence.txt"])
    res, payload = _verify(runner, alpha, "--require-binding", "--expect-project", "alpha",
                           "--expect-challenge", "1=" + "z" * 32)
    assert res.exit_code == 1
    assert any("Phase 1: packet has no replay binding" in e for e in payload["errors"])
