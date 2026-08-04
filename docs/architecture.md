# Architecture — Proof Studio

## One-liner
Catch agents when they lie about done

## Flow
```text
claim → evidence bundle → HMAC/signature → verifier gate → pass|fail packet
```

## Trust boundaries
- Public inputs only in examples/fixtures
- Secrets never enter the repo
- Completion claims require smoke/proof

## Related
- Profile: https://github.com/mrodgersjs-web
- Doctrine: https://github.com/mrodgersjs-web/doctrine
- Proof entry: https://github.com/mrodgersjs-web/proof-studio
