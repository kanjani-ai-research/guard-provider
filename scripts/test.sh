#!/usr/bin/env bash
# Single test entry point (guard-core docs/TESTING-STANDARD.md). Extra args go to pytest:
#   scripts/test.sh                  unit tests
#   scripts/test.sh -m integration   tests that need a live cluster / AWS / third-party service
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON=3.12                    # = FROM python:X.Y in Dockerfile
# Runtime deps = pyproject [project.dependencies] (the Dockerfile's `pip install .`);
# test deps = the [dev] extra. No private wheels.

if [ "$(.venv/bin/python -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" != "$PYTHON" ]; then
  rm -rf .venv
  uv venv -q --python "$PYTHON" .venv
fi
VIRTUAL_ENV="$PWD/.venv" uv pip install -q -r pyproject.toml --extra dev

.venv/bin/python -m pytest "$@"
