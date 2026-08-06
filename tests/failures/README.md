# Planted-failure test vectors

This directory holds planted-failure test vectors. Each file is a forged ProofPacket that the verifier **MUST** reject. CI fails if any planted failure passes verification.

Planned test vector files:

1. `clean_build.json` — baseline, **must PASS** (not a failure vector; the control case)
2. `tampered_artifact_hash.json` — artifact hash modified after sealing; **must FAIL**
3. `forged_signature_no_key.json` — signature generated without the secret key; **must FAIL**
4. `replay_attack.json` — valid packet replayed against a different build/context; **must FAIL**

> Every planted failure must go red. If a gate cannot fail, it is theater.
