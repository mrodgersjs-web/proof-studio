# AGENTS.md — proof-studio
Proof before narrative. Do not weaken signature checks. No secrets in fixtures.

## Repository quick reference

`proof-studio` packages the public ProofPacket demonstration and its planted-forge verification path.

- `packages/rigforge/`: installable package, CLI, demo, and package tests.
- `scripts/`: repository smoke entry point.
- `tests/failures/`: planted-failure fixtures.
- `docs/`: architecture, evaluation, and public-boundary guidance.
- `graft/`: generated context; read when useful and preserve unchanged.

Bootstrap from the repository root:

```bash
cd packages/rigforge
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Test and smoke from the repository root:

```bash
bash scripts/smoke.sh
```

Run the installed demonstration:

```bash
rigforge demo
```

Always run the smoke command before claiming done.
