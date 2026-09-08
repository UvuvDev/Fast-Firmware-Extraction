#!/bin/bash
# Runs the fixture-driven test suite against the real Binary Ninja Python API.
# Requires: a licensed local Binary Ninja install at ~/binaryninja (build/out
# tree) or BN_APP set to its Contents/Resources dir; and `python3 -m venv
# .venv && .venv/bin/pip install pytest` run once from this directory.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BN_APP="${BN_APP:-$HOME/binaryninja/build/out/binaryninja.app/Contents/Resources}"

export PYTHONPATH="$BN_APP/python:$BN_APP/python3"
exec "$REPO_DIR/.venv/bin/python3" -m pytest "$REPO_DIR/tests" "$@"
