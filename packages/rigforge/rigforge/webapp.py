"""
RIGForge full-stack cockpit — REST API + single-page app (G011).

This promotes the CLI verbs (status / run / seal / verify / contracts / proof)
into one FastAPI application and serves a vanilla single-page cockpit on top.
It deliberately reuses the hardened pieces already in the platform:

* **Auth** — the same bearer-token contract as the MCP HTTP transport
  (``rigforge.config.resolve_mcp_token`` → ``Authorization: Bearer <token>``).
  Localhost-bound by default; the static SPA + ``/`` + ``/health`` are open so
  the page can load, the API surface is token-gated.
* **Harness** — :class:`~rigforge.harness.ArchonHarness` runs the phases, seals
  ProofPackets, and reports status; nothing is re-implemented here.
* **Ledger** — the SSE endpoint tails ``ExecutionLedger`` for a live feed.

No npm / Vite / React build: the frontend is plain ``index.html`` + ``app.js``
+ ``style.css`` served via ``StaticFiles``. That keeps the platform
deterministic and offline-friendly (no transpile step, no lockfile drift).
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from rigforge.context import ProjectContext
from rigforge.harness import ArchonHarness, PHASES
from rigforge.ledger import ExecutionLedger
from rigforge.proof import ProofPacket


WEB_DIR = Path(__file__).parent / "web"


def _verify_payload(
    ctx: ProjectContext,
    *,
    strict: bool = False,
    require_binding: bool = False,
    expected_project: str | None = None,
    challenges: dict[int, str] | None = None,
) -> dict[str, Any]:
    """Build the same verify report the CLI emits, as a plain dict.

    Binding expectations come from the server (its pinned ``expected_project``
    and the challenges it issued itself), never from the packets on disk.
    """
    from rigforge.binding import BindingError, ReplayExpectations, verify_proofs
    from rigforge.config import load_config

    try:
        cfg = load_config(ctx)
    except ValueError:
        cfg = None
    signing_key = cfg.resolve_signing_key(ctx.root) if cfg is not None else None

    expectations = ReplayExpectations(
        project_id=expected_project if require_binding else None,
        challenges=dict(challenges or {}) if require_binding else {},
        require=require_binding,
    )
    pre_errors: list[str] = []
    if require_binding:
        try:
            expectations.validate()
        except BindingError as exc:
            pre_errors.append(str(exc))
        if signing_key is None:
            pre_errors.append("require_binding needs a signing key on the server.")
    if pre_errors:
        return {"ok": False, "strict": strict, "binding_checked": require_binding,
                "binding_required": require_binding, "phases": [], "errors": pre_errors,
                "warnings": []}
    return verify_proofs(
        ctx,
        strict=strict,
        require_signature=require_binding,
        signing_key=signing_key,
        expectations=expectations,
    )


def build_app(ctx: ProjectContext, *, auth_token: str | None = None,
              allow_insecure: bool = True, expected_project: str | None = None):
    """Build the full-stack FastAPI app.

    ``auth_token`` gates the ``/api/*`` surface (the SPA, ``/`` and ``/health``
    stay open so the page can bootstrap). Unlike the MCP transport, the cockpit
    defaults to ``allow_insecure=True`` because it is a read-mostly local
    dashboard — but a configured token is honoured and enforced. Pass
    ``allow_insecure=False`` to require a token.

    ``expected_project`` is the trusted project id for replay binding (from
    ``rigforge serve --expect-project``). Challenges issued through
    ``POST /api/phases/{n}/challenge`` live only in this process's memory; the
    newest one per phase is what ``/api/verify?require_binding=true`` expects.
    """
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover — import guard
        raise ImportError(
            "Full-stack cockpit requires FastAPI. Install with: pip install rigforge[mcp]"
        ) from exc

    token = (auth_token or "").strip() or None
    if token is None and not allow_insecure:
        from rigforge.mcp_server import MCPInsecureBindError

        raise MCPInsecureBindError(
            "Refusing to start the cockpit API with no auth token (allow_insecure=False). "
            "Configure mcp.token / RIGFORGE_MCP_TOKEN."
        )

    app = FastAPI(
        title="RIGForge Cockpit",
        version="1.1.0",
        description="Full-stack mission-control: REST API + SPA over the deterministic harness.",
    )
    app.state.auth_token = token
    app.state.expected_project = (expected_project or "").strip() or None
    # phase -> {"challenge": str, "status": "open" | "consumed"}; server memory only.
    app.state.challenges = {}

    # Open paths the SPA needs before it can present a token, plus docs.
    OPEN_PATHS = {"/", "/health", "/openapi.json", "/docs", "/redoc"}

    @app.middleware("http")
    async def _auth(request, call_next):
        path = request.url.path
        # Static assets + open paths never require auth so the page can load.
        if token is None or path in OPEN_PATHS or path.startswith("/static"):
            return await call_next(request)
        if path.startswith("/api"):
            header = request.headers.get("authorization", "")
            scheme, _, supplied = header.partition(" ")
            ok = scheme.lower() == "bearer" and supplied.strip() == token
            # Browsers' EventSource cannot set headers, so the SSE endpoint also
            # accepts the token as a ``?token=`` query param. The token still
            # never appears in a response body or a log line we emit.
            if not ok and path == "/api/ledger/stream":
                ok = request.query_params.get("token", "") == token
            if not ok:
                return JSONResponse(
                    {"detail": "unauthorized"}, status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)

    # ── Page + health ──────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        index_html = WEB_DIR / "index.html"
        if index_html.exists():
            return index_html.read_text()
        return "<h1>RIGForge cockpit assets missing</h1>"

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "auth_required": token is not None, "root": str(ctx.root)}

    # ── REST API (CLI verbs promoted) ──────────────────────────────────

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        harness = ArchonHarness(ctx)
        return {
            "root": str(ctx.root),
            "auth_required": token is not None,
            "phases": {str(k): v for k, v in harness.status().items()},
        }

    @app.get("/api/phases")
    def api_phases() -> dict[str, Any]:
        harness = ArchonHarness(ctx)
        status = harness.status()
        phases = []
        for p, name in PHASES.items():
            info = status.get(p, {})
            phases.append({
                "phase": p,
                "name": name,
                "sealed": info.get("sealed", False),
                "verifier": info.get("verifier"),
                "integrity_ok": info.get("integrity_ok"),
                "signed": info.get("signed", False),
                "signature_ok": info.get("signature_ok"),
                "artifact_count": info.get("artifact_count", 0),
            })
        return {"phases": phases}

    @app.post("/api/phases/{n}/run")
    def api_run(n: int, dry_run: bool = False) -> dict[str, Any]:
        if not 1 <= n <= 7:
            raise HTTPException(status_code=404, detail="phase out of range (1-7)")
        harness = ArchonHarness(ctx)
        result = harness.run(n, dry_run=dry_run, verifier="cockpit")
        return result.to_dict()

    @app.post("/api/phases/{n}/challenge")
    def api_challenge(n: int) -> dict[str, Any]:
        from rigforge.binding import new_challenge

        if not 1 <= n <= 7:
            raise HTTPException(status_code=404, detail="phase out of range (1-7)")
        if app.state.expected_project is None:
            raise HTTPException(
                status_code=409,
                detail="server has no trusted project id; start it with --expect-project",
            )
        value = new_challenge()
        # A new challenge replaces the old one: a packet sealed in an earlier
        # run of this phase no longer matches what verify expects.
        app.state.challenges[n] = {"challenge": value, "status": "open"}
        return {"phase": n, "challenge": value, "project_id": app.state.expected_project}

    @app.post("/api/phases/{n}/seal")
    def api_seal(n: int, body: dict | None = None) -> dict[str, Any]:
        import hmac as _hmac

        from rigforge.binding import BindingError, validate_project_id
        from rigforge.proof import ProofBinding

        if not 1 <= n <= 7:
            raise HTTPException(status_code=404, detail="phase out of range (1-7)")
        body = body or {}
        evidence = body.get("evidence")
        force = bool(body.get("force", False))
        challenge = body.get("challenge")
        harness = ArchonHarness(ctx)
        binding = None
        if challenge is not None:
            issued = app.state.challenges.get(n)
            if issued is None or not _hmac.compare_digest(
                str(issued["challenge"]).encode(), str(challenge).encode()
            ):
                raise HTTPException(status_code=409,
                                    detail="challenge was not issued by this server for this phase")
            if issued["status"] != "open":
                raise HTTPException(status_code=409,
                                    detail="challenge was already used for a seal (reused nonce)")
            if not (harness.config.signing.enabled
                    and harness.config.resolve_signing_key(ctx.root)):
                raise HTTPException(status_code=409,
                                    detail="a bound seal needs a signing key")
            try:
                project_id = validate_project_id(harness.config.project)
            except BindingError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            binding = ProofBinding(project_id=project_id, challenge=str(challenge))
        run_result = harness.run(n, verifier="cockpit")
        if run_result.blockers and not force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "blocking gates failed; pass force=true to seal anyway",
                    "blockers": [b.to_dict() for b in run_result.blockers],
                },
            )
        packet = harness.seal(
            n, verifier="cockpit", evidence=evidence,
            gates=run_result.gates, envelope=run_result.envelope,
            binding=binding,
        )
        if binding is not None:
            app.state.challenges[n]["status"] = "consumed"
        return {
            "ok": True,
            "phase": n,
            "packet_sha256": packet.packet_sha256,
            "signed": bool(packet.signature),
            "bound": packet.binding is not None,
            "proof": str(ctx.proof_file(n).relative_to(ctx.root)),
        }

    @app.get("/api/verify")
    def api_verify(strict: bool = False, require_binding: bool = False) -> dict[str, Any]:
        return _verify_payload(
            ctx,
            strict=strict,
            require_binding=require_binding,
            expected_project=app.state.expected_project,
            challenges={p: c["challenge"] for p, c in app.state.challenges.items()},
        )

    @app.get("/api/contracts")
    def api_contracts() -> dict[str, Any]:
        if not ctx.contracts_dir.exists():
            return {"count": 0, "contracts": []}
        files = sorted(
            str(f.relative_to(ctx.root)) for f in ctx.contracts_dir.rglob("*.yaml")
        )
        return {"count": len(files), "contracts": files}

    @app.get("/api/proof/{phase}")
    def api_proof(phase: int) -> dict[str, Any]:
        if not 1 <= phase <= 7:
            raise HTTPException(status_code=404, detail="phase out of range (1-7)")
        path = ctx.proof_file(phase)
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"phase {phase} not sealed")
        try:
            packet = ProofPacket.load(path)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"proof unreadable: {exc}")
        data = packet.model_dump(mode="json")
        data["integrity_ok"] = packet.verify_integrity()
        return data

    # ── SSE live ledger feed ───────────────────────────────────────────

    @app.get("/api/ledger/stream")
    async def api_ledger_stream(limit: int = 20, follow: bool = True):
        """Server-Sent-Events feed of ledger events.

        Emits the last ``limit`` events immediately, then (when ``follow``)
        streams new events as they land. ``follow=false`` returns the snapshot
        and closes — used by tests so the stream terminates deterministically.
        """
        ledger = ExecutionLedger(ctx.ledger_file)

        def _format(event: dict) -> str:
            return f"data: {json.dumps(event, default=str)}\n\n"

        async def _gen():
            seen: set[str] = set()
            initial = ledger.read(limit=limit)
            for ev in initial:
                seen.add(ev.get("event_id", ""))
                yield _format(ev)
            if not follow:
                yield "event: end\ndata: {}\n\n"
                return
            # Poll for new events. Bounded so a test client without follow logic
            # cannot hang the worker; production clients keep the connection open.
            deadline = time.monotonic() + 3600
            while time.monotonic() < deadline:
                await asyncio.sleep(0.5)
                for ev in ledger.read(limit=200):
                    eid = ev.get("event_id", "")
                    if eid and eid not in seen:
                        seen.add(eid)
                        yield _format(ev)
                yield ": keep-alive\n\n"

        return StreamingResponse(_gen(), media_type="text/event-stream")

    # ── Static SPA assets ──────────────────────────────────────────────

    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    return app
