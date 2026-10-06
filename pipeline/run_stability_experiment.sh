#!/bin/bash
# Section 13.4 stability experiment: the 100-case frozen subset (benchmark/stability_subset_100.json),
# all 8 primary models, temperature 0.2, run 5 times SEQUENTIALLY (not concurrently -- untested whether
# GPT-Lab handles 5x parallel load gracefully, so this stays cautious).
#
# Run this INSIDE tmux, on the VM, with GPTLAB_API_KEY already exported in the same shell
# (see Research_Log/Phase5_VM_Runbook.md for the key-loading steps). Each repeat writes to its own
# results directory so nothing overwrites a previous repeat, and each repeat is independently
# resume-safe (run_generation.py's own _completed_case_ids() skip logic) if this script itself is
# interrupted and re-run.
#
#   bash pipeline/run_stability_experiment.sh
#
set -eo pipefail
cd "$(dirname "$0")/.."

if [ -z "${GPTLAB_API_KEY:-}" ]; then
  echo "GPTLAB_API_KEY is not set in this shell -- export it first (see the runbook), then re-run this script."
  exit 1
fi

mkdir -p results

for REP in 1 2 3 4 5; do
  OUT="results/runs_phase5_stability_rep${REP}"
  echo "=================================================================="
  echo "== Stability repeat ${REP}/5 -> ${OUT}"
  echo "=================================================================="
  PATH=.venv/bin:$PATH .venv/bin/python pipeline/run_generation.py \
    --models primary --cases stability --temperature 0.2 --prompt-variant autogrep_default \
    --results-dir "$OUT"
  echo "== Repeat ${REP}/5 done =="
done

echo
echo "All 5 stability repeats complete."
