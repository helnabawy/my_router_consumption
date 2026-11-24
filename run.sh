#!/bin/bash
# Creates the Python environment on first use, then starts WE Monitor.
#   ./run.sh           start with your real network
#   ./run.sh --demo    start with simulated devices (nothing is read from your network)
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then PY="$c"; break; fi
  done
fi
if [ -z "$PY" ]; then
  echo "Python 3.10 or newer is required. Install it with:  brew install python@3.12" >&2
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "First run: creating .venv and installing packages..."
  "$PY" -m venv .venv
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt
fi
[ -f config.yaml ] || cp config.example.yaml config.yaml

if [ "${1:-}" = "--demo" ]; then
  export WE_MONITOR_MODE=demo
  [ -f data/demo.sqlite ] || .venv/bin/python -m app.cli seed-demo
fi
exec .venv/bin/python -m app
