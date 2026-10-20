# Planted-failure test vectors

This directory holds the tamper scenario manifest (`scenarios.yml`) and the
generated planted-failure vectors. `proof-studio run` regenerates every vector
from its deterministic builder and then verifies it. The JSON vector files are
gitignored because `proof-studio build-vectors` rebuilds them byte-identically.

Each vector is a ProofPacket the verifier MUST reject, plus one control it MUST
accept. CI fails if any planted failure passes verification.

| File | Kind | Expectation |
| --- | --- | --- |
| clean_build.json | control | must PASS |
| tampered_artifact_hash.json | tampered_artifact_hash | must FAIL |
| forged_signature_no_key.json | forged_signature | must FAIL |
| replay_attack.json | replay | must FAIL (claim binding) |

The claim each vector is submitted against lives in `scenarios.yml`.

> Every planted failure must go red. If a gate cannot fail, it is theater.
