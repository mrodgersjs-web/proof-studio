# Copilot instructions

## Repository purpose

`proof-studio` packages the public ProofPacket demonstration and supporting deterministic build assets. Its planted-forge path proves that tampered completion evidence is rejected.

## Work map

- `packages/rigforge/`: installable ProofPacket package, CLI, demo, and package tests.
- `scripts/`: repository smoke entry point.
- `tests/failures/`: planted-failure fixtures.
- `docs/`: architecture, evaluation, and public-boundary guidance.
- `graft/`: generated context; read when needed and leave unchanged.

## Commands

Bootstrap the package from the repository root:

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

## Editing rules

- Proof precedes narrative. Do not weaken signature checks.
- Keep planted failures capable of turning the gate red.
- Keep fixtures free of secrets and private data.
- Preserve the public boundary and deterministic smoke path.
- Always run the smoke command before claiming done.
