# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-19

First packaged release: proof-studio becomes the tamper-scenario and benchmark
studio around the vendored rigforge core.

### Added

- `proof_studio` package: scenario model and manifest loading, deterministic
  planted-failure vector builders, the strict verify runner (integrity, HMAC
  signature, claim binding), per-class catch report, and the `proof-studio` CLI
  (`run`, `list`, `build-vectors`).
- Planted-failure vectors (control, tampered_artifact_hash,
  forged_signature_no_key, replay_attack) with the `scenarios.yml` manifest,
  fulfilling the vector plan in `tests/failures/README.md`. The JSON vectors
  are generated deterministically by `proof-studio build-vectors` and are
  gitignored; `proof-studio run` rebuilds them before verifying.
- Test suite (`tests/`): scenario and vector tests, runner tests including the
  gate-can-fail cases, CLI and vector-reproducibility tests, packaging
  invariants, README truth lint.
- `pyproject.toml` packaging (name, version, MIT license, authors, classifiers,
  dependencies, `dev` and `mcp` extras, console script, ruff config).
- Community files: `CODE_OF_CONDUCT.md`, this changelog, issue templates, a pull
  request template, `CITATION.cff`, and `.github/dependabot.yml`.
- CI runs the studio suite with coverage across Python 3.11 to 3.13 plus the
  generated vectors, and keeps the vendored rigforge test job.

### Changed

- README rewritten to a distinct purpose: the studio around rigforge, with
  rigforge named as the core library, a "What it proves" table of runnable
  checks with measured results, a mermaid flow, and the honest replay limits.
  The four front-page hero assets are reduced to one demo GIF.
- `docs/architecture.md` documents the real design (scenario model, strict
  policy, vector lifecycle, outcome classification); `docs/evaluation-strategy.md`
  lists the real gates.
- `scripts/smoke.sh` runs `proof-studio run` before the core demo.
- `mcp/server.py` resolves the platform helper from `RIG_LOOP` or `PATH` instead
  of a hardcoded home-directory path.
