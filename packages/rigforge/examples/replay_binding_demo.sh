#!/usr/bin/env bash
# Replay-binding demo: runs the REAL `rigforge` CLI end to end.
#
# Two projects (alpha, beta) share ONE signing key, the worst case for replay.
# The caller issues a challenge per run, keeps it, and verifies with
# --require-binding using values it holds itself (never read from a packet).
#
# Expected: the current-run packet passes; a stale packet from an earlier run,
# a packet copied from the other project, a reused challenge and a legacy
# unbound packet are all refused. Exits non-zero if any expectation fails.
set -uo pipefail

RIGFORGE="${RIGFORGE:-rigforge}"
PYTHON="${PYTHON:-python}"
WORK="$(cd "$(mktemp -d)" && pwd -P)"  # resolve /var -> /private/var on macOS
trap 'rm -rf "$WORK"' EXIT
export RIGFORGE_SIGNING_KEY="demo-shared-key-$(date +%s)-$RANDOM"
FAILS=0

expect() {  # expect <wanted-exit> <label> -- cmd...
  local want="$1" label="$2"; shift 3
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq "$want" ]; then
    echo "PASS  [$rc] $label"
  else
    echo "FAIL  [$rc, wanted $want] $label"; echo "$out" | sed 's/^/      /'
    FAILS=$((FAILS + 1))
  fi
  printf '%s\n' "$out" | grep -E "cross-project|stale|reused|no replay binding|cannot be combined|no trusted|trusted project|trusted challenge|signature does not|UNTRUSTED" | head -1 | sed -E 's/^ *(- |❌ )?/      reason: /'
}

mkproject() {
  local dir="$WORK/$1"
  mkdir -p "$dir/rigforge" "$dir/contracts/v1" "$dir/docs"
  printf "[project]\nname='%s'\n" "$1" > "$dir/pyproject.toml"
  "$RIGFORGE" --cwd "$dir" init >/dev/null
  sed -i.bak "s/^project: .*/project: $1/" "$dir/rigforge.yaml" && rm -f "$dir/rigforge.yaml.bak"
  echo "evidence for $1" > "$dir/docs/evidence.txt"
}
mkproject alpha
mkproject beta
A="$WORK/alpha"; B="$WORK/beta"

# Run 1 in alpha: caller issues a challenge and keeps it.
N1="$("$RIGFORGE" --cwd "$A" challenge issue 1)"
"$RIGFORGE" --cwd "$A" seal 1 --artifact "$A/docs/evidence.txt" --challenge "$N1" >/dev/null
P1="$(find "$A" -name 'phase1_proof.json' | head -1)"
cp "$P1" "$WORK/alpha-run1-phase1.json"
expect 0 "alpha run 1: current packet, expected project + challenge" -- \
  "$RIGFORGE" --cwd "$A" verify --strict --require-binding --expect-project alpha --expect-challenge "1=$N1"

# Run 2 in alpha: new challenge, new seal; then an old run-1 packet is put back.
N2="$("$RIGFORGE" --cwd "$A" challenge issue 1)"
"$RIGFORGE" --cwd "$A" seal 1 --artifact "$A/docs/evidence.txt" --challenge "$N2" >/dev/null
expect 0 "alpha run 2: current packet" -- \
  "$RIGFORGE" --cwd "$A" verify --strict --require-binding --expect-project alpha --expect-challenge "1=$N2"
cp "$P1" "$WORK/alpha-run2-phase1.json"
cp "$WORK/alpha-run1-phase1.json" "$P1"
expect 1 "stale same-phase replay (run-1 packet, run-2 challenge)" -- \
  "$RIGFORGE" --cwd "$A" verify --strict --require-binding --expect-project alpha --expect-challenge "1=$N2"
# The pre-1.3 strict command and plain verify must not pass the stale packet.
expect 2 "stale packet, old strict flags (--strict --require-signature, no expectations)" -- \
  "$RIGFORGE" --cwd "$A" verify --strict --require-signature
expect 1 "stale packet, plain verify (no trusted expectations)" -- \
  "$RIGFORGE" --cwd "$A" verify
cp "$WORK/alpha-run2-phase1.json" "$P1"

# Reused challenge: sealing again with the consumed run-2 challenge is refused.
expect 2 "reused challenge at seal time" -- \
  "$RIGFORGE" --cwd "$A" seal 1 --artifact "$A/docs/evidence.txt" --challenge "$N2"

# Cross-project with the SAME key: alpha's valid packet copied into beta.
NB="$("$RIGFORGE" --cwd "$B" challenge issue 1)"
"$RIGFORGE" --cwd "$B" seal 1 --artifact "$B/docs/evidence.txt" --challenge "$NB" >/dev/null
PB="$(find "$B" -name 'phase1_proof.json' | head -1)"
expect 0 "beta: current packet" -- \
  "$RIGFORGE" --cwd "$B" verify --strict --require-binding --expect-project beta --expect-challenge "1=$NB"
cp "$PB" "$WORK/beta-phase1.json"
cp "$P1" "$PB"
expect 1 "cross-project replay, shared key (alpha packet in beta)" -- \
  "$RIGFORGE" --cwd "$B" verify --strict --require-binding --expect-project beta --expect-challenge "1=$NB"
# Even if the attacker knows alpha's challenge, the project id still fails.
expect 1 "cross-project replay, attacker supplies alpha's own challenge" -- \
  "$RIGFORGE" --cwd "$B" verify --strict --require-binding --expect-project beta --expect-challenge "1=$N2"
cp "$WORK/beta-phase1.json" "$PB"

# Legacy: an unbound packet fails strict binding, and the legacy opt-in
# cannot be combined with --require-binding.
"$RIGFORGE" --cwd "$B" seal 2 --artifact "$B/docs/evidence.txt" >/dev/null
expect 1 "unbound packet (no challenge) under --require-binding" -- \
  "$RIGFORGE" --cwd "$B" verify --require-binding --expect-project beta --expect-challenge "1=$NB" --expect-challenge "2=${NB}x"
expect 2 "--allow-unbound with --require-binding is refused" -- \
  "$RIGFORGE" --cwd "$B" verify --require-binding --allow-unbound --expect-project beta
expect 2 "--allow-unbound with --strict is refused" -- \
  "$RIGFORGE" --cwd "$B" verify --strict --allow-unbound
expect 0 "--allow-unbound alone: legacy packet accepted as UNTRUSTED" -- \
  "$RIGFORGE" --cwd "$B" verify --allow-unbound
expect 2 "missing expected challenge: no self-asserted fallback" -- \
  "$RIGFORGE" --cwd "$B" verify --require-binding --expect-project beta

# Forgeries without the key: strip the binding / rewrite it, recompute the plain hash.
forge() {  # forge <proof> strip|rewrite <challenge>
  "$PYTHON" - "$@" <<'PY'
import json, sys
from rigforge.proof import ProofBinding, ProofPacket
path, mode, ch = sys.argv[1:4]
p = ProofPacket.load(path)
b = None if mode == "strip" else ProofBinding(project_id="beta", challenge=ch)
p = p.model_copy(update={"binding": b})
p = p.model_copy(update={"packet_sha256": p.compute_hash()})
open(path, "w").write(json.dumps(p.model_dump(mode="json")))
PY
}
cp "$PB" "$WORK/beta-good.json"
forge "$PB" strip "$NB"
expect 1 "stripped binding + recomputed hash under --allow-unbound (bad signature)" -- \
  "$RIGFORGE" --cwd "$B" verify --allow-unbound
cp "$P1" "$PB"; forge "$PB" rewrite "$NB"
expect 1 "alpha packet re-labelled beta, hash recomputed, expectations only (no --require-binding)" -- \
  "$RIGFORGE" --cwd "$B" verify --expect-project beta --expect-challenge "1=$NB"
cp "$WORK/beta-good.json" "$PB"

echo
if [ "$FAILS" -eq 0 ]; then
  echo "replay-binding demo: all expectations met"
else
  echo "replay-binding demo: $FAILS expectation(s) FAILED"; exit 1
fi
