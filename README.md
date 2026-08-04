# proof-studio

> Catch AI coding agents when they lie about “done” — cryptographically signed ProofPackets make completion claims re-verifiable.

![status](https://img.shields.io/badge/status-public-studio-blue)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![proof](https://img.shields.io/badge/false--done-catch-brightgreen)

## Employer summary

AI coding agents are fast and confident. That confidence is the risk.

When an agent reports `BUILD COMPLETE ✅`, you usually have a sentence in a chat thread and nothing behind it. **proof-studio** replaces the sentence with a signed `ProofPacket`: artifact hashes, environment record, HMAC signature. Tamper the result and re-forge the hash — the signature still fails if you never had the key.

This is the FDE posture applied to agent work itself: **no proof, no done.**

### Review path

1. This README  
2. 60-second demo below  
3. [`packages/rigforge/`](packages/rigforge/) — installable platform  
4. [`docs/public-boundary.md`](docs/public-boundary.md)  
5. Sibling package surface: [`rigforge`](https://github.com/mrodgersjs-web/rigforge)  

## Proof in 60 seconds

```bash
git clone https://github.com/mrodgersjs-web/proof-studio.git
cd proof-studio/packages/rigforge
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
rigforge demo
```

Expected shape of the outcome:

1. Agent claims **BUILD COMPLETE**  
2. Platform seals a signed ProofPacket  
3. Artifact is tampered; naive integrity can be fooled  
4. **HMAC signature check fails** — forged done is caught  

Nothing in that demo should be a scripted fake. Hashes and signatures are computed by the same path used for real work.

## Why it exists

Production agent systems need a Definition of Done that is:

- **executable** (a command, not a vibe)  
- **tamper-evident** (signature over artifact digests)  
- **replayable** (another machine can re-verify)  
- **hostile to false greens** (planted failures must go red)  

If a gate cannot fail, it is theater.

## Architecture

```text
work artifacts
     │
     ▼
 gate bundle (tests / smoke / contracts)
     │
     ▼
 seal → ProofPacket { hashes, env, claims }
     │
     ▼
 HMAC-SHA256 signature
     │
     ▼
 verify --strict --require-signature
```

## Packages

| Path | Role |
| --- | --- |
| [`packages/rigforge`](packages/rigforge/) | ProofPacket CLI, demo, honesty benchmark, MCP/web surfaces |
| [`packages/deterministic-build-starter`](packages/deterministic-build-starter/) | Starter that ships with a sealed Definition of Done |

### Common commands (from `packages/rigforge`)

```bash
rigforge demo                 # watch forged done get caught
rigforge benchmark            # offline honesty scenarios
rigforge init                 # scaffold proofs/ contracts/ ledger/
rigforge verify --require-signature
```

## Evaluation / gates

| Gate | Intent |
| --- | --- |
| `rigforge demo` | Planted forge fails closed |
| `rigforge benchmark` | Honest vs forged scenario suite |
| unit/contract tests under package | CLI and packet invariants |
| public flag-gate | no secrets / PII patterns in tree |

## Public boundary

This studio does **not** ship customer PII, production signing keys, or private fleet credentials.  
Demo keys and fixtures are local/dev only. See [`docs/public-boundary.md`](docs/public-boundary.md).

## Video walkthrough

- Script: [`docs/video-script.md`](docs/video-script.md)  
- Capture target: terminal `rigforge demo` end-to-end (60–75s)  

## Related studios

- [fde-portfolio](https://github.com/mrodgersjs-web/fde-portfolio) — engagement playbooks  
- [jake-studio](https://github.com/mrodgersjs-web/jake-studio) — operator closed loops that should seal packets  
- [doctrine](https://github.com/mrodgersjs-web/doctrine) — proof standards agents load  
- [rigforge](https://github.com/mrodgersjs-web/rigforge) — package-first mirror  

## License

See package licenses under `packages/`. Root studio follows MIT unless a nested package states otherwise.


---

## FDE bar (this studio)

| Practice | Here |
| --- | --- |
| Employer summary | top of README |
| 60s / smoke proof | fde-portfolio smoke PASS |
| Public boundary |  |
| Claim under test | '"rigforge demo catches forged done"' |
| Related fleet | [profile](https://github.com/mrodgersjs-web) · [resume](https://github.com/mrodgersjs-web/resume) · [patents teaser](https://github.com/mrodgersjs-web/patents) |

If fde-portfolio smoke PASS fails, the README claim is considered false until fixed.
