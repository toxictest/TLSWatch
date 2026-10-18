#!/usr/bin/env bash
# Development tests only; Python is NOT a TLSWatch runtime dependency.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v python3 >/dev/null || { echo 'Tests require Python 3 (auditor does not).' >&2; exit 2; }
exec python3 run_tests.py
