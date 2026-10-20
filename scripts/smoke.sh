#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 -m pip install -e '.[dev]' -q
proof-studio run
cd "$ROOT/packages/rigforge"
python3 -m pip install -e . -q
rigforge demo > /dev/null
echo "proof-studio smoke PASS"
