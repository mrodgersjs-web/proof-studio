# proof-studio

> Catch AI coding agents when they lie about "done" — cryptographically signed ProofPackets.

## 60-second demo

```bash
cd packages/rigforge
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
rigforge demo
```

Also see top-level package mirror: [rigforge](https://github.com/mrodgersjs-web/rigforge).

## Packages
| Path | Role |
|---|---|
| `packages/rigforge` | ProofPacket CLI + honesty benchmark |
| `packages/deterministic-build-starter` | Vite/TS starter that ships with a sealed packet |

## Public boundary
See [docs/public-boundary.md](docs/public-boundary.md).
