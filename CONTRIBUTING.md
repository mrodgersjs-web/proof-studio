# Contributing

## Bar
1. Public-boundary safe (no PII, secrets, client dumps, ToS-risk bots).
2. `bash scripts/smoke.sh` must pass.
3. README claims must match runnable commands.
4. Prefer small diffs with proof over large narrative refactors.

## Flow
1. Fork or branch from `main`.
2. Add/adjust tests or smoke coverage for the change.
3. Run `bash scripts/smoke.sh`.
4. Open a PR with: what changed, how verified, boundary impact.
