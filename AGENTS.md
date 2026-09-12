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

## RIG lattice contract (stamped)

This repository runs the shared RIG lattice: loops in `.rig/loop.yaml`, pre-tool
hooks in `.rig/hooks/`, CI gate in `.github/workflows/rig-lattice.yml`, execution
owner routing in `.rig/work-routing.yaml` (operator standard 2026-09-11), and a
results-driven MCP server at `mcp/server.py` returning verified results only.
D85 rules apply: every outward action needs a Gate-D request + typed approval;
durable builds need four ratios >= 0.85 and a sealed proof. Done-claims need TAC
close-gate sealed evidence. Shared agent substrate lives in Supabase schema
`rig_shared` (see PROGRAM.md in rig-lattice-retrofit).
