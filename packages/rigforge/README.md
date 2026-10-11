# RIGForge

### Don't trust your agents. Prove them.

**RIGForge catches your AI coding agent when it lies about "done."** When an agent
says `BUILD COMPLETE ✅`, you have its word and nothing behind it. RIGForge replaces
the word with a cryptographically signed `ProofPacket` — so "the build passed" becomes
something you re-verify with one command, not a message in a chat thread.

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
[![CI](https://github.com/mrodgersjs-web/rigforge/actions/workflows/ci.yml/badge.svg)](https://github.com/mrodgersjs-web/rigforge/actions/workflows/ci.yml)
![Works with](https://img.shields.io/badge/works%20with-Claude%20Code%20·%20Codex%20·%20Cursor-8A2BE2.svg)

<p align="center">
  <img src="docs/demo.svg" alt="rigforge demo — RIGForge catches a forged 'BUILD COMPLETE' by failing the HMAC signature check" width="720">
</p>

---

## See it catch a lie in 5 seconds

```bash
pip install -e .   # then:
rigforge demo
```

Output (real — the tamper detection is computed by the same crypto the platform uses):

```
╭───────────────────────────────────────────╮
│  RIGForge  ·  Live Tamper-Detection Demo  │
╰───────────────────────────────────────────╯

1 · the claim     An AI agent reports:  BUILD COMPLETE ✅

2 · RIGForge seals a signed ProofPacket
      packet sha256   7def637005db987daeb020992dd36ef1…
      hmac signature  8c80ed299a6298e22e60893af036f4f2…
      integrity       ✔ valid
      signature       ✔ valid

3 · the tamper    The artifact is TAMPERED and the packet hash is
                  re-forged to hide it. Naive integrity now PASSES —
                  the lie looks clean.

4 · RIGForge verify
      naive integrity check  PASS  — fooled by the re-forged hash
      hmac signature check   FAIL  — signature does not verify

   🚨 FORGED. Signature invalid. The agent lied.
```

Nothing in that demo is scripted. Every hash, signature, and verdict is computed by the
**same code path** that seals and verifies real work. Swap the narration for your own
`assert`s — the cryptographic outcome doesn't change. The forged seal gets caught because
the HMAC was bound to the *original* artifact hash, and the attacker never had the signing key.

## The problem

AI coding agents are fast and confident — and that's exactly the risk. They report success
they didn't earn, skip the gate that would've caught the failure, and leave no trail to prove
what actually ran. A "✅ done" in your terminal is unfalsifiable. You can't audit a vibe.

RIGForge makes agent output **provable**:

- Work seals a `ProofPacket` that SHA-256-hashes every artifact and records the exact run environment.
- The packet is HMAC-SHA256 **signed** — tamper the result and re-forge the hash, the signature still fails.
- Verification is a command: `rigforge verify --strict --require-signature`. Pass = a signed, re-checkable artifact. Not a message in a thread.

## 90-second quickstart

```bash
git clone https://github.com/mrodgersjs-web/rigforge.git
cd rigforge-deterministic-platform
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

rigforge demo                    # watch it catch a forged "done"
rigforge init                    # scaffold proofs/, contracts/, ledger/, rigforge.yaml
rigforge run 1                   # run a phase's deterministic gate bundle
rigforge seal 1 --artifact docs/PHASE1.md --evidence "bootstrap complete"
rigforge verify --require-signature
```

Wiring it into your own agent? [`examples/verify_agent_done.py`](examples/verify_agent_done.py)
is the smallest real integration — seal a claim, tamper it, watch the signature catch the lie.

## Prove it yourself — the honesty benchmark

Don't take the README's word for it either. RIGForge ships a seeded, offline, reproducible
benchmark that runs forged-proof attack scenarios (tampered artifact, forged signature,
swapped artifact, dropped gate, unsigned tamper, replay) and reports the **false-done-caught rate** —
how often the signature check catches a lie that naive integrity misses:

```bash
rigforge benchmark               # real crypto, deterministic seed, byte-identical across runs
```

On the default seed it runs 17 scenarios — 8 honest, 9 forged across 6 attack classes — and
catches **every** forged "done" while wrongly blocking **zero** honest ones:

```
false_done_caught_rate    1.00   (9/9 forgeries caught — 0 slipped through)
false_pass_rate           0.00   (0/8 honest claims wrongly blocked)
accuracy                  1.00   (17/17 verdicts correct)
```

That 100% isn't a marketing number — it's the *point*: an HMAC bound to the original artifact
hash is cryptographically unforgeable without the key, so a tampered "done" **must** fail the
signature check. Every figure is tallied from actual `ProofPacket.verify_signature()` verdicts,
not hardcoded. The replay scenario re-submits a genuine signed phase-N packet as proof of a
newer phase: its signature is valid, so it is caught by `ProofPacket.matches_claim()`, which
compares the signed phase to the claim being verified. Read [`rigforge/benchmark.py`](rigforge/benchmark.py) and re-run it yourself.

Want to see *why each layer matters*? The **[false-done-caught leaderboard](docs/LEADERBOARD.md)**
scores verification strategies head-to-head — naive integrity catches **0%**, signing **67%**,
spec-bound **100%**:

```bash
rigforge benchmark --leaderboard
```

## Works with your stack

**Your agent** — RIGForge exposes its contract + proof tools over **MCP**, so Claude Code,
Codex, Cursor, and OpenCode can seal and verify proofs directly:

```bash
rigforge mcp-serve --transport stdio          # preferred by Claude Code et al.
rigforge mcp-serve --auth-token "$RIGFORGE_MCP_TOKEN"   # HTTP, bearer-token auth
```

**Your observability** — RIGForge emits OpenTelemetry spans per phase and gate. Point it at
your existing collector and traces drop into **Langfuse / Phoenix / Jaeger**. With no
collector set, spans print as OTLP-JSON to stdout. Not installed? It's a clean no-op — the
free core never requires it:

```bash
pip install -e ".[telemetry]"
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 rigforge trace 1
```

## Running a fleet? The swarm verdict board

One agent, you can eyeball. Twenty-five, you can't. Every seal/verify lands on a per-agent
board so you can see — provably — **which of your agents to trust and which to reject:**

```bash
rigforge verdicts          # (or open the cockpit at :8770 for the live grid)
```

```
        RIGForge · swarm verdict board (by actor)
┃ actor        ┃ accepted ┃ rejected ┃ trust ┃
│ claude-code  │        5 │        1 │   83% │
│ cursor-agent │        3 │        0 │  100% │
│ rogue-bot    │        0 │        4 │    0% │   ← caught
```

Agents feed the board with **one MCP call** — no config, the signing key stays server-side so
the agent can't forge its own verdict:

```jsonc
// tools/call → gev.seal_and_verify
{ "agent": "claude-code", "name": "auth refactor", "artifacts": ["src/auth.py"] }
// → { "accepted": true, "integrity_ok": true, "signature_ok": true, ... }
```

## Spec-bound proofs — "did the build match the spec?"

Integrity proves the artifact is unchanged. **Spec-bound proofs go further: they prove the build
satisfied the acceptance criteria of the exact spec the agent was given.** Bind a spec when you
seal — a [spec-kit](https://github.com/github/spec-kit)-style markdown checklist or a YAML
`criteria:` list — and:

- the criteria are **signed into** the packet — a dropped or edited criterion breaks the signature;
- verification **rejects** unless every criterion has a passing gate — *even if the artifact is intact*;
- a swapped spec is caught by hash mismatch.

```bash
rigforge seal 1 --artifact build.out --spec spec.md
rigforge spec-check --proof proofs/phase1_proof.json --spec spec.md
#  ✅ spec-check: PASS   met: login works, tests pass, lint clean
```

Skip a requirement and the verdict flips — provably, not on a vibe:

```
❌ spec-check: FAIL
   MISSING: lint clean
```

Observability shows what happened; eval scores quality; orchestration runs the fleet. Proving
*build-matches-spec* is the part nobody else does.

## Honest scope

RIGForge proves **integrity and provenance** — that an artifact is what the agent claims
and that nothing changed it since sealing. It does **not** make your code correct or safe,
force an agent to seal, or survive a stolen signing key. Those boundaries are stated plainly,
not buried — full trust model and what it deliberately doesn't defend against:
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.

**Replay binding.** `verify` rejects a valid packet placed in a phase slot it was not sealed for (different phase number or different phase name). Since schema 1.3.0 it can also reject the two other replays: (1) a packet copied from another project that uses the same signing key, and (2) an older valid packet from an earlier run of the same phase. The caller issues a challenge per run (`rigforge challenge issue N`), the seal signs the project id and that challenge into the packet (`rigforge seal N --challenge <nonce>`), and `rigforge verify --require-binding --expect-project <id> --expect-challenge N=<nonce>` compares them with the values the caller kept. The expected values must come from the caller (flags, or an `--expectations` file kept outside the project), never from the packet. Packets without a binding (sealed before 1.3.0, or without `--challenge`) fail `--require-binding`; `--allow-unbound` accepts them only when `--require-binding` is off. Plain `verify` and `verify --strict --require-signature` do **not** check the binding and still accept both replays; use `--require-binding` when replay matters. Limit: anyone who holds the signing key can seal any project id and challenge, so the binding stops replay of genuine packets, not forgery by a key holder. Runnable demo: `packages/rigforge/examples/replay_binding_demo.sh`.

## How it works

Work flows through 7 explicit phases. Each phase runs a deterministic bundle of quality gates
(pytest, ruff, schema + config validation — each timeout-guarded). Passing a phase seals a
`ProofPacket`:

```
artifact ──SHA-256──▶ integrity hash ──HMAC-SHA256(signing key)──▶ signature
                                                   │
                          rigforge verify ─────────┘  re-checks both. Tamper either → FAIL.
```

| Phase | Name | What it gates |
|-------|------|---------------|
| 1 | Bootstrap & Doctrine | Repo structure, doctrine docs, hardening |
| 2 | Environment Validation | Python, deps, config checks |
| 3 | Runtime Kernel | Core models, schemas, registries |
| 4 | Control Plane Registries | Agent catalog, build cards, intent maps |
| 5 | GEV Loop + DoneContract | Contract-based verification with proof packets |
| 6 | Archon Harness | Agent orchestration, parallel gate scheduling, budget enforcement, auto-resume |
| 7 | Cockpit | `rigforge cockpit` — mission-control HTML view |

## CLI reference

```bash
rigforge init                    # scaffold a project
rigforge doctor                  # diagnose env, layout, contracts, CI, lint readiness
rigforge status                  # phase status        (--json for machine-readable)
rigforge run N [--dry-run]       # run phase N's deterministic gate bundle
rigforge seal N --artifact PATH [--spec FILE]      # seal a phase (optionally spec-bound)
rigforge verify [--strict] [--require-signature]   # re-check sealed phases
rigforge challenge issue N                         # per-run nonce for a replay-bound seal
rigforge seal N --challenge NONCE                  # sign project id + nonce into the packet
rigforge verify --require-binding --expect-project ID --expect-challenge N=NONCE
rigforge spec-check --proof P --spec S             # prove a build matched its spec
rigforge resume                  # resume the most recent failed/unfinished phase
rigforge benchmark               # the honesty benchmark (false-done-caught rate)
rigforge demo                    # live tamper-detection demo
rigforge verdicts                # swarm verdict board: per-agent accept/reject + trust%
rigforge trace N                 # run a phase with OpenTelemetry tracing
rigforge cockpit                 # serve the mission-control UI (127.0.0.1:8770)
rigforge mcp-serve               # expose tools to AI agents over MCP
rigforge contract list|create|validate|inspect
```

`--json` works everywhere it makes sense. `--cwd PATH` overrides project-root discovery.

## Configuration (`rigforge.yaml`)

`rigforge init` scaffolds a typed config (`rigforge.config.RigForgeConfig`):

| Section | Purpose |
|---------|---------|
| `budgets` | Cost / token / runtime ceilings, enforced by the harness |
| `mcp` | MCP transport (`http`\|`stdio`), services, bearer-token auth |
| `scheduler` | Parallel gate scheduling, agent catalog |
| `signing` | HMAC-SHA256 ProofPacket signing + `require_on_verify` |
| `cockpit` | Cockpit UI host/port |

Env overrides: `RIGFORGE_SIGNING_KEY[_FILE]`, `RIGFORGE_MCP_TOKEN[_FILE]`,
`RIGFORGE_MAX_PARALLEL_GATES`. `rigforge doctor` validates the file.

## Tests

```bash
pip install -e ".[dev]"
pytest                           # 252 passing
```

The suite is adversarial by design: tamper-detection, eval-loop no-spin guarantees, gate
timeouts, ledger concurrency, and MCP refuse-by-default are all proven with **planted
failures** — each test fails on the broken code and passes only with the fix in place.

## License

MIT — see [LICENSE](LICENSE). Built by [RIG (Rodgers Intelligence Group)](https://rodgersintelligence.com).

> ⭐ If "prove it, don't trust it" is how you want your agents to work, star the repo —
> it's the signal that keeps this free core moving.
