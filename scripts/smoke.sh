#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/packages/rigforge"
python3 -m pip install -e . -q
rigforge demo
echo "proof-studio smoke PASS"
