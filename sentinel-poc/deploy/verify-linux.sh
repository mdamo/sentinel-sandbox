#!/bin/bash
# No root required. Real adapters use only temporary files and loopback fixtures.
set -euo pipefail
project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
interpreter=${PYTHON:-python3.13}
command -v "$interpreter" >/dev/null || { echo "Missing $interpreter; set PYTHON explicitly." >&2; exit 1; }
cd "$project_dir"
"$interpreter" test_sentinel.py
"$interpreter" test_runtime.py
"$interpreter" run_demo.py
"$interpreter" evaluate_runtime.py --output evaluation-report.json
git diff --check
