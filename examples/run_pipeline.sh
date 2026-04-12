#!/usr/bin/env bash
# One-shot demo pipeline: collect traces → enrich → PC graphs (+ optional corr).
#
# Usage (from anywhere):
#   bash examples/run_pipeline.sh
#   bash examples/run_pipeline.sh --with-corr
#   bash examples/run_pipeline.sh --comparison-only
#   bash examples/run_pipeline.sh --comparison-only --with-corr
#
# Uses repo .venv/bin/python3 when present; else python3 on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x "${ROOT}/.venv/bin/python3" ]]; then
  PY="${ROOT}/.venv/bin/python3"
else
  PY="python3"
fi

WITH_CORR=0
SKIP_COLLECT=0
COMP_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-corr|--corr)
      WITH_CORR=1
      shift
      ;;
    --comparison-only)
      SKIP_COLLECT=1
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--with-corr] [--comparison-only]"
      echo "  (default)          build_real_artifacts.py then build_comparison.py"
      echo "  --with-corr        also lag-correlation PNGs + counts"
      echo "  --comparison-only  skip collection; use existing examples/*_enriched.csv"
      exit 0
      ;;
    *)
      COMP_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ "${SKIP_COLLECT}" -eq 0 ]]; then
  echo "==> Collect + enrich (${PY})"
  "${PY}" examples/build_real_artifacts.py
else
  echo "==> Skipping collection (--comparison-only)"
fi

echo "==> PC graphs + diff (${PY})"
if [[ "${WITH_CORR}" -eq 1 ]]; then
  "${PY}" examples/build_comparison.py --with-corr "${COMP_ARGS[@]:-}"
else
  "${PY}" examples/build_comparison.py "${COMP_ARGS[@]:-}"
fi

echo "==> Done. See examples/*_pc.png (and *_corr.png if --with-corr)."
