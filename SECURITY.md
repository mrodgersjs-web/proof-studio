# Security Policy

## Supported surfaces
This repository's public `main` branch.

## Reporting
Email **mrodgersjs@gmail.com** with:
- affected path / command
- impact
- proof of concept (non-destructive)

Do **not** open a public issue for secrets or exploitable bugs.

## Secrets
- Never commit `.env`, cookies, tokens, private keys, or customer data.
- Rotate any credential that may have been exposed.
- Public boundary: `docs/public-boundary.md`.
