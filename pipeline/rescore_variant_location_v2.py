"""
2026-10-10 versioned refinement of Finding 1's location-correctness correction
(pipeline/rescore_variant_location.py). Found during unrelated diagnostic development
(Research_Log/Diagnostic_20261010/README.md): for 4 cases, the restructured variant's
vulnerable construct was moved by the transformation into a NEW helper function/declaration,
disjoint from the originally-annotated range -- so a rule that correctly matched at the NEW,
real location was being scored as wrong-location (FN) by Finding 1's original, single-range
annotation. Each of the 4 was independently re-verified against the actual source file before
being added here (see Correction_Log.md and benchmark/variant_vulnerable_lines_v2_additions.jsonl
for the evidence and exact line numbers).

This is ADDITIVE, not a replacement: `benchmark/variant_vulnerable_lines.jsonl` (Finding 1's
annotations) is read unchanged; `variant_vulnerable_lines_v2_additions.jsonl` supplies a SECOND,
disjoint valid range for the 4 affected (case_id, variant) pairs only. A finding is now scored
"correct location" if it falls in EITHER range -- never narrower than Finding 1's original scoring,
only ever potentially wider (recovering FN->TP flips Finding 1's narrower annotation produced
incorrectly, never introducing a new FN).

Reads from results_corrected/ (Finding 1's already-corrected tree, NOT the raw results/ tree --
this is a refinement layered on top of Finding 1, not a redo of it) and writes to
results_corrected_v2/, leaving results_corrected/ untouched, so Finding 1's own tree stays
reproducible on its own. Only variant_vulnerable_1/2 records for the 4 affected cases can change;
every other record is carried through byte-identical (re-serialized, not re-decided).

Usage:
    python pipeline/rescore_variant_location_v2.py
"""
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_schema import SampleExecutionRecord
from rescore_variant_location import TARGET_GLOBS, load_line_ranges

ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT / "benchmark"
RESULTS_CORRECTED_DIR = ROOT / "results_corrected"
RESULTS_CORRECTED_V2_DIR = ROOT / "results_corrected_v2"


def load_v2_additions():
    out = defaultdict(list)
    for line in (BENCH_DIR / "variant_vulnerable_lines_v2_additions.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        out[(r["case_id"], r["variant"])].append((r["start_line"], r["end_line"]))
    return out


def rescore_record(r: dict, line_ranges: dict, v2_additions: dict):
    if r["sample_type"] not in ("variant_vulnerable_1", "variant_vulnerable_2"):
        return r, False
    if not r["detected"]:
        return r, False  # a non-detection's outcome doesn't depend on location

    key = (r["case_id"], r["sample_type"])
    extra_ranges = v2_additions.get(key)
    if extra_ranges is None:
        return r, False  # not one of the 4 affected (case_id, variant) pairs -- carry through unchanged

    # Already correct under Finding 1's original range? Nothing to do.
    if r.get("finding_location_correct") is True:
        return r, False

    finding_lines = r.get("finding_lines") or []
    # Finding 1's original range, if available, stays a valid location too (additive, never narrower).
    base_range = line_ranges.get(key)
    all_ranges = list(extra_ranges)
    if base_range is not None:
        all_ranges.append(base_range)

    location_ok = any(any(start <= ln <= end for ln in finding_lines) for start, end in all_ranges)
    if not location_ok:
        return r, False  # still correctly scored as wrong-location even under the wider v2 ranges

    old_outcome = r["outcome"]
    rec = SampleExecutionRecord(
        run_id=r["run_id"], case_id=r["case_id"], model_tag=r["model_tag"], condition=r["condition"],
        sample_type=r["sample_type"], label=r["label"], detected=r["detected"],
        finding_location_correct=True, finding_lines=r.get("finding_lines"),
        outcome=None,
    )
    changed = rec.outcome != old_outcome
    return json.loads(rec.to_json()), changed


def main():
    line_ranges = load_line_ranges()
    v2_additions = load_v2_additions()
    print(f"Loaded {len(v2_additions)} v2 additive-range (case_id, variant) pairs: {sorted(v2_additions)}")

    total_records = 0
    total_flips = 0
    files_written = 0

    for pattern in TARGET_GLOBS:
        for src in glob.glob(str(RESULTS_CORRECTED_DIR / pattern)):
            src_path = Path(src)
            rel = src_path.relative_to(RESULTS_CORRECTED_DIR)
            dst_path = RESULTS_CORRECTED_V2_DIR / rel
            dst_path.parent.mkdir(parents=True, exist_ok=True)

            out_lines = []
            file_flips = 0
            for line in src_path.read_text().splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                total_records += 1
                new_r, changed = rescore_record(r, line_ranges, v2_additions)
                if changed:
                    file_flips += 1
                    total_flips += 1
                out_lines.append(json.dumps(new_r))

            dst_path.write_text("\n".join(out_lines) + "\n")
            files_written += 1
            if file_flips:
                print(f"  {rel}: {file_flips} FN->TP flip(s)")

    print()
    print(f"Files written: {files_written}")
    print(f"Total sample records processed: {total_records}")
    print(f"Total FN->TP flips from the v2 additive-range fix: {total_flips}")


if __name__ == "__main__":
    main()
