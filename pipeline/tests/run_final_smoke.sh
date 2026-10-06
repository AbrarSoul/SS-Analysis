#!/bin/bash
# Real-model smoke test on 8 FINAL-set cases (Step 2 follow-up). Run this yourself in a terminal.
#
# The GPT-Lab key is NOT stored in this file or anywhere on disk: it is read from a hidden prompt
# (or reused if GPTLAB_API_KEY is already exported in this terminal) and lives only in this process.
#
#   bash pipeline/tests/run_final_smoke.sh
#
set -eo pipefail
cd "$(dirname "$0")/../.."
source .venv/bin/activate

# Key sources, in order: already exported in this terminal -> macOS Keychain item "GPTLAB_API_KEY" -> hidden prompt.
if [ -z "${GPTLAB_API_KEY:-}" ] && command -v security >/dev/null 2>&1; then
  if KEY_FROM_KEYCHAIN="$(security find-generic-password -a "$USER" -s GPTLAB_API_KEY -w 2>/dev/null)" && [ -n "$KEY_FROM_KEYCHAIN" ]; then
    export GPTLAB_API_KEY="$KEY_FROM_KEYCHAIN"
    echo "(using the GPT-Lab key from the macOS Keychain)"
  fi
  unset KEY_FROM_KEYCHAIN
fi
if [ -z "${GPTLAB_API_KEY:-}" ]; then
  read -r -s -p "GPT-Lab API key (input hidden): " GPTLAB_API_KEY
  echo
  export GPTLAB_API_KEY
fi

OUT="results/runs_final_realsmoke_$(date +%Y%m%d_%H%M%S)"   # fresh dir each time: Autogrep caches "processed" patches

echo "== 1/2 authentication check (lists models on GPU-farmi-004) =="
python "Open Models/models.py" | head -4

echo "== 2/2 running 8 final cases through qwen2.5-coder:7b-instruct (autogrep_default, temp 0, 3 retries) =="
python pipeline/run_generation.py --models qwen2.5-coder:7b-instruct \
  --cases CASE-0079,CASE-0181,CASE-0341,CASE-0342,CASE-0078,CASE-0056,CASE-0090,CASE-0299 \
  --results-dir "$OUT"

echo
echo "Done. Results are in $OUT/ -- tell Claude it finished and it will analyse them."
