"""
Selects the 100-case stratified subset for the Section 13.4 stability experiment
(temperature 0.2, 5 runs per model-case), from the 300 frozen final cases.

Run and frozen BEFORE the Section 13.3 primary run's results exist, deliberately --
selecting after seeing primary results would invite (even unintentional) bias toward
convenient cases. See Research_Log/Implementation_Log.md Section 12.27.

Stratified jointly by (language, semgrep_representability) so the subset preserves
both the final set's language balance (Python/Java/JS/TS) and its representability
mix (supported/partially_supported/unsupported) proportionally -- the same
methodology already used for the Section 9 second-rater sample earlier in this
project. Per-cell target counts use largest-remainder rounding of exactly 100 * (cell
size / 300) so the subset sums to exactly 100; within each cell, cases are chosen by
a fixed-seed random sample of the cell's own case ids, sorted first for determinism.
"""
import json
import random
from collections import defaultdict
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
SUBSET_SIZE = 100
RANDOM_SEED = 20260929100  # fixed for reproducibility; distinct from all prior selection seeds in this project


def largest_remainder_round(counts: dict, total: int) -> dict:
    exact = {k: v * total / sum(counts.values()) for k, v in counts.items()}
    floors = {k: int(v) for k, v in exact.items()}
    remainder = total - sum(floors.values())
    order = sorted(exact, key=lambda k: exact[k] - floors[k], reverse=True)
    for k in order[:remainder]:
        floors[k] += 1
    return floors


def main():
    random.seed(RANDOM_SEED)
    recs = [json.loads(line) for line in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines()]
    assert len(recs) == 300, f"expected 300 final cases, found {len(recs)}"

    by_cell = defaultdict(list)
    for r in recs:
        by_cell[(r["language"], r["semgrep_representability"])].append(r["case_id"])

    cell_sizes = {k: len(v) for k, v in by_cell.items()}
    targets = largest_remainder_round(cell_sizes, SUBSET_SIZE)
    assert sum(targets.values()) == SUBSET_SIZE, sum(targets.values())

    subset = []
    for cell, ids in by_cell.items():
        ids = sorted(ids)
        random.shuffle(ids)
        subset.extend(ids[:targets[cell]])
    subset.sort()
    assert len(subset) == SUBSET_SIZE and len(set(subset)) == SUBSET_SIZE

    out = {
        "purpose": "Section 13.4 stability experiment subset (temperature 0.2, 5 runs per model-case)",
        "selected_before_primary_run_results_exist": True,
        "stratified_by": ["language", "semgrep_representability"],
        "random_seed": RANDOM_SEED,
        "subset_size": SUBSET_SIZE,
        "source_manifest": "manifest_frozen_final.jsonl",
        "target_counts_per_cell": {f"{lang}/{rep}": n for (lang, rep), n in targets.items()},
        "case_ids": subset,
    }
    out_path = BENCH_DIR / "stability_subset_100.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")

    print(f"Selected {len(subset)} cases -> {out_path}")
    for (lang, rep), n in sorted(targets.items()):
        print(f"  {lang:12} {rep:20} {n:3} (of {cell_sizes[(lang, rep)]})")


if __name__ == "__main__":
    main()
