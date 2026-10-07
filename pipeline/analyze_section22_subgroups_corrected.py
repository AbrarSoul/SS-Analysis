"""
Correction (2026-10-06 audit, Step 6): reruns the §22.4 subgroup analysis against the corrected
sample data from Finding 1's fix. Same model/condition choice as the original
(analyze_section22_subgroups.py: qwen2.5-coder:32b, autogrep, full 300-case set) for direct
comparability -- only the sample_execution_log source changes (results_corrected/ instead of
results/); generation_log (unaffected by Finding 1) still comes from results/.

Correction (2026-10-07, external reviewer feedback round 3): this script's case population was
NEVER filtered through `eligible_cases.py` -- it used the raw 300-case manifest directly, so
CASE-0166 (post-hoc dataset exclusion) and the 5 ground-truth-excluded cases (Priority 2) were
still being pooled into every bucket here, including the "Supported vs partially supported"
bucket's own MCC. Caught concretely: this script's "supported" bucket reported qwen2.5-coder:32b
MCC 0.536 while the primary headline table (built on the 150-case eligible population) reports
0.539 for the same model/condition -- same underlying inconsistency Priority 4 already fixed
everywhere else. Fixed by filtering `all_cases` through `eligible_cases.py`'s exclusions globally
(not just for the representability bucket) -- a case whose ground truth is untrustworthy shouldn't
be used in ANY subgroup breakdown (language, CWE, patch size, CVE age), since its recorded TP/FP
outcomes rest on that same questionable patched-sample label regardless of which bucket it's
sliced into.
"""
import json
import re
import sys
import warnings
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, BENCH_DIR
from analyze_section22 import PRIMARY_MODEL_DIRS
from analyze_section22_subgroups import (
    cve_year, repo_aware_bootstrap_mcc, print_bucket_table, load_full_manifest,
)
from analyze_section22_corrected import RESULTS, RESULTS_CORRECTED
from eligible_cases import POST_HOC_DATASET_EXCLUSIONS, GROUND_TRUTH_EXCLUSIONS, VERSION as ELIGIBLE_VERSION

warnings.filterwarnings("ignore", category=RuntimeWarning, module="scipy")

MODEL = "qwen2.5-coder:32b"
MODEL_DIR = PRIMARY_MODEL_DIRS[MODEL]
CONDITION = "autogrep"


def load_corrected_full():
    gen = [json.loads(l) for l in (RESULTS / "runs_phase5_primary" / MODEL_DIR / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / "runs_phase5_primary" / MODEL_DIR / "sample_execution_log.jsonl").read_text().splitlines()]
    gen_c = {g["case_id"]: g for g in gen if g["condition"] == CONDITION}
    smp_by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == CONDITION:
            smp_by_case[s["case_id"]].append(s)
    return {cid: smp_by_case.get(cid, []) for cid in gen_c}


def main():
    manifest = load_full_manifest()
    case_to_samples = load_corrected_full()
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    excluded = POST_HOC_DATASET_EXCLUSIONS | GROUND_TRUTH_EXCLUSIONS
    all_cases = [cid for cid in manifest if cid in case_to_samples and cid not in excluded]

    print(f"Section 22.4 subgroup analysis -- CORRECTED -- model={MODEL}, condition={CONDITION}, "
          f"n={len(all_cases)} cases (eligible_cases.py v{ELIGIBLE_VERSION}: {len(excluded)} "
          f"cases excluded -- CASE-0166 dataset exclusion + 5 ground-truth exclusions).")
    print(f"({sum(1 for c in all_cases if case_to_samples[c])} have evaluable samples.)")

    buckets = defaultdict(list)
    for cid in all_cases:
        buckets[manifest[cid]["language"]].append(cid)
    print_bucket_table("By language", buckets, case_to_repo, case_to_samples)

    buckets = defaultdict(list)
    for cid in all_cases:
        buckets[manifest[cid]["pattern_or_taint"]].append(cid)
    print_bucket_table("Pattern vs taint", buckets, case_to_repo, case_to_samples)

    buckets = defaultdict(list)
    for cid in all_cases:
        buckets[manifest[cid]["context_complexity"]].append(cid)
    print_bucket_table("Structural vs context-heavy", buckets, case_to_repo, case_to_samples)

    buckets = defaultdict(list)
    for cid in all_cases:
        rep = manifest[cid]["semgrep_representability"]
        if rep in ("supported", "partially_supported"):
            buckets[rep].append(cid)
    print_bucket_table("Supported vs partially supported (unsupported excluded)", buckets, case_to_repo, case_to_samples)

    years = {cid: cve_year(manifest[cid]) for cid in all_cases}
    valid_years = sorted(y for y in years.values() if y is not None)
    median_year = valid_years[len(valid_years) // 2]
    buckets = defaultdict(list)
    for cid in all_cases:
        y = years[cid]
        if y is None:
            continue
        buckets[f"<= {median_year} (older)" if y <= median_year else f"> {median_year} (newer)"].append(cid)
    print(f"\n  (median CVE year: {median_year})")
    print_bucket_table("Older vs newer CVE", buckets, case_to_repo, case_to_samples)

    sizes = {cid: manifest[cid]["patch_size_added"] + manifest[cid]["patch_size_deleted"] for cid in all_cases}
    sorted_cases = sorted(all_cases, key=lambda c: sizes[c])
    n = len(sorted_cases)
    t1, t2, t3 = sorted_cases[: n // 3], sorted_cases[n // 3: 2 * n // 3], sorted_cases[2 * n // 3:]
    buckets = {
        f"small (<= {sizes[t1[-1]]} lines)": t1,
        f"medium ({sizes[t2[0]]}-{sizes[t2[-1]]} lines)": t2,
        f"large (>= {sizes[t3[0]]} lines)": t3,
    }
    print_bucket_table("Patch size (tertiles)", buckets, case_to_repo, case_to_samples)

    cwe_buckets = defaultdict(list)
    for cid in all_cases:
        for cwe in manifest[cid].get("cwe_ids") or ["(none)"]:
            cwe_buckets[cwe].append(cid)
    well_populated = {k: v for k, v in cwe_buckets.items() if len(v) >= 10}
    print(f"\n  -- CWE breakdown ({len(cwe_buckets)} distinct IDs), {len(well_populated)} with >= 10 cases --")
    if well_populated:
        print_bucket_table("CWEs with >= 10 cases", well_populated, case_to_repo, case_to_samples)


if __name__ == "__main__":
    main()
