"""
Correction (2026-10-06 audit, Finding 1): retroactively applies finding-location-correctness to
every existing variant_vulnerable_1/2 sample record, using the annotations computed by
compute_variant_vulnerable_lines.py. No Semgrep or LLM re-execution -- every record already stores
the finding's actual line numbers (`finding_lines`); only the per-variant "where is the vulnerable
construct" range was missing until now.

Writes CORRECTED COPIES under results_corrected/<same relative path>, leaving every original
results/ file byte-for-byte untouched (Step 1's preservation principle) -- diff the two trees at
any point to see exactly what changed and why.

Only rescoring happens here: HIGH-confidence annotations get a real finding_location_correct value
(True/False); LOW-confidence or missing annotations are left as finding_location_correct=None
(unchanged from the original, unverified state) rather than guessed -- a corrected record that
can't be verified stays explicitly unverified, it doesn't silently become "verified wrong."

Usage:
    python pipeline/rescore_variant_location.py
"""
import glob
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_schema import SampleExecutionRecord

ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT / "benchmark"
RESULTS_DIR = ROOT / "results"
RESULTS_CORRECTED_DIR = ROOT / "results_corrected"

# Every real sample_execution_log.jsonl that any reported result in Paper_Draft_Notes.md depends on.
TARGET_GLOBS = [
    "runs_phase5_primary/*/sample_execution_log.jsonl",
    "runs_phase5_stability_rep1/*/sample_execution_log.jsonl",
    "runs_phase5_stability_rep2/*/sample_execution_log.jsonl",
    "runs_phase5_stability_rep3/*/sample_execution_log.jsonl",
    "runs_phase5_stability_rep4/*/sample_execution_log.jsonl",
    "runs_phase5_stability_rep5/*/sample_execution_log.jsonl",
    "runs_c2_primary/*/sample_execution_log.jsonl",
    "runs_c3/*/sample_execution_log.jsonl",
    "runs_c4/*/sample_execution_log.jsonl",
]


def load_line_ranges():
    out = {}
    for line in (BENCH_DIR / "variant_vulnerable_lines.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r["confidence"] != "high":
            continue  # LOW-confidence annotations are not used to rescore -- stays unverified
        out[(r["case_id"], r["variant"])] = (r["start_line"], r["end_line"])
    return out


def rescore_record(r: dict, line_ranges: dict):
    if r["sample_type"] not in ("variant_vulnerable_1", "variant_vulnerable_2"):
        return r, False  # untouched -- only these two sample types are affected by this correction
    if not r["detected"]:
        return r, False  # a non-detection's outcome (FN) doesn't depend on location at all

    key = (r["case_id"], r["sample_type"])
    rng = line_ranges.get(key)
    if rng is None:
        return r, False  # no high-confidence annotation available -- leave as originally recorded

    start, end = rng
    finding_lines = r.get("finding_lines") or []
    location_ok = any(start <= ln <= end for ln in finding_lines)

    old_outcome = r["outcome"]
    rec = SampleExecutionRecord(
        run_id=r["run_id"], case_id=r["case_id"], model_tag=r["model_tag"], condition=r["condition"],
        sample_type=r["sample_type"], label=r["label"], detected=r["detected"],
        finding_location_correct=location_ok, finding_lines=r.get("finding_lines"),
        outcome=None,  # force recomputation via __post_init__
    )
    changed = rec.outcome != old_outcome
    return json.loads(rec.to_json()), changed


def main():
    line_ranges = load_line_ranges()
    print(f"Loaded {len(line_ranges)} high-confidence variant line-range annotations.")

    total_records = 0
    total_rescored_candidates = 0  # variant_vulnerable + detected=True
    total_flips = 0
    files_written = 0

    for pattern in TARGET_GLOBS:
        for src in glob.glob(str(RESULTS_DIR / pattern)):
            src_path = Path(src)
            rel = src_path.relative_to(RESULTS_DIR)
            dst_path = RESULTS_CORRECTED_DIR / rel
            dst_path.parent.mkdir(parents=True, exist_ok=True)

            out_lines = []
            file_flips = 0
            for line in src_path.read_text().splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                total_records += 1
                if r["sample_type"] in ("variant_vulnerable_1", "variant_vulnerable_2") and r["detected"]:
                    total_rescored_candidates += 1
                new_r, changed = rescore_record(r, line_ranges)
                if changed:
                    file_flips += 1
                    total_flips += 1
                out_lines.append(json.dumps(new_r))

            dst_path.write_text("\n".join(out_lines) + "\n")
            files_written += 1
            if file_flips:
                print(f"  {rel}: {file_flips} TP->FN flip(s)")

    print()
    print(f"Files written: {files_written}")
    print(f"Total sample records processed: {total_records}")
    print(f"variant_vulnerable_1/2 records with detected=True (rescoring candidates): {total_rescored_candidates}")
    print(f"Total TP->FN flips from the location-correctness fix: {total_flips}")
    if total_rescored_candidates:
        print(f"Flip rate among rescoring candidates: {total_flips/total_rescored_candidates*100:.1f}%")


if __name__ == "__main__":
    main()
