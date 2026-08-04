# Evaluation strategy — Proof Studio

## Gates
| Gate | Command | Pass |
| --- | --- | --- |
| Smoke | `bash scripts/smoke.sh` | exit 0 |
| Boundary | `docs/public-boundary.md` exists | file present |
| Claim integrity | README claims map to smoke | manual PR check |

## Failure policy
If smoke fails, README promises are considered **false** until fixed.

## Human approval
Required before any outward/customer action in real deployments. This public repo only proves local/demo gates.
