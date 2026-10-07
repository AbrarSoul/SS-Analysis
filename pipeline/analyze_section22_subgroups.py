"""
Section 22.4 (design doc) subgroup analysis -- the last unbuilt piece of Section 22. See
Research_Log/Section22_Scope.md for the methodology (repository-aware bootstrap CIs, since CVEs
from the same repository aren't fully independent -- Section 22.4's own explicit requirement).

Applied to the primary benchmark's `autogrep` condition on the FULL 300-case set (not restricted to
`supported` cases) for the model with the most statistical power among the top performers
(`qwen2.5-coder:32b`, 86 cases with evaluable samples -- confirmed directly, not assumed, by
checking sample counts across all 8 models first). The 153-case multi-agent conditions are
confirmed too sparse for meaningful subgroup breakdowns (as few as 11 accepted cases total for
C4-A -- splitting that further into 4 languages or ~100+ CWEs would produce near-empty cells) and
are deliberately NOT broken out here; this is stated explicitly rather than silently omitted.
"""
import json
import random
import re
import sys
import warnings
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, BENCH_DIR
from analyze_section22 import load_primary, PRIMARY_MODEL_DIRS

warnings.filterwarnings("ignore", category=RuntimeWarning, module="scipy")

MODEL = "qwen2.5-coder:32b"
MODEL_DIR = PRIMARY_MODEL_DIRS[MODEL]
CONDITION = "autogrep"


def load_full_manifest():
    rows = [json.loads(l) for l in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines()]
    return {r["case_id"]: r for r in rows}


def cve_year(row):
    cid = row.get("cve_id") or (row.get("cve_ids_all") or [None])[0]
    m = re.match(r"CVE-(\d{4})-", cid or "")
    return int(m.group(1)) if m else None


def repo_aware_bootstrap_mcc(case_ids: list, case_to_repo: dict, case_to_samples: dict, n_boot=10000, seed=42):
    """Resamples at the REPOSITORY level (grouping its cases together each draw), respecting
    non-independence of cases from the same repo, then recomputes pooled MCC per resample. Returns
    (point_estimate_mcc, ci_lo, ci_hi, n_cases, n_repos)."""
    repo_to_cases = defaultdict(list)
    for cid in case_ids:
        repo_to_cases[case_to_repo[cid]].append(cid)
    repo_ids = list(repo_to_cases.keys())

    def pooled_mcc_for(cids):
        samples = []
        for cid in cids:
            samples.extend(case_to_samples.get(cid, []))
        return mcc(confusion_from_samples(samples)) if samples else None

    point = pooled_mcc_for(case_ids)
    if point is None:
        return None, None, None, len(case_ids), len(repo_ids)

    rng = random.Random(seed)
    n = len(repo_ids)
    diffs = []
    for _ in range(n_boot):
        sampled_repos = [repo_ids[rng.randrange(n)] for _ in range(n)]
        resampled_cases = []
        for r in sampled_repos:
            resampled_cases.extend(repo_to_cases[r])
        m = pooled_mcc_for(resampled_cases)
        if m is not None:
            diffs.append(m)
    if not diffs:
        return point, None, None, len(case_ids), len(repo_ids)
    diffs.sort()
    lo = diffs[int(0.025 * len(diffs))]
    hi = diffs[int(0.975 * len(diffs)) - 1]
    return point, lo, hi, len(case_ids), len(repo_ids)


def print_bucket_table(title, buckets: dict, case_to_repo, case_to_samples):
    print(f"\n  -- {title} --")
    for bucket_name, cids in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        point, lo, hi, n_cases, n_repos = repo_aware_bootstrap_mcc(cids, case_to_repo, case_to_samples)
        if point is None:
            print(f"    {bucket_name:25s} n={n_cases:3d} ({n_repos} repos)  no evaluable samples in this bucket")
        else:
            print(f"    {bucket_name:25s} n={n_cases:3d} ({n_repos} repos)  MCC={point:+.3f}  "
                  f"95% CI=({lo:+.3f}, {hi:+.3f})")


def main():
    manifest = load_full_manifest()
    data = load_primary(MODEL_DIR, CONDITION, case_filter=None)  # full 300-case set
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    case_to_samples = {cid: v["samples"] for cid, v in data.items()}
    all_cases = [cid for cid in manifest if cid in data]

    print(f"Section 22.4 subgroup analysis -- model={MODEL}, condition={CONDITION}, "
          f"n={len(all_cases)} cases (full 300-case set, NOT restricted to 'supported' -- "
          f"subgroup analysis needs the volume).")
    print(f"({sum(1 for c in all_cases if case_to_samples[c])} of these have evaluable samples; "
          f"the rest had no executable rule and contribute 0 to pooled MCC's denominator terms "
          f"the same way the primary analysis has always treated them.)")

    # 1. Language
    buckets = defaultdict(list)
    for cid in all_cases:
        buckets[manifest[cid]["language"]].append(cid)
    print_bucket_table("By language", buckets, case_to_repo, case_to_samples)

    # 2. Pattern vs taint
    buckets = defaultdict(list)
    for cid in all_cases:
        buckets[manifest[cid]["pattern_or_taint"]].append(cid)
    print_bucket_table("Pattern vs taint", buckets, case_to_repo, case_to_samples)

    # 3. Structural vs context-heavy
    buckets = defaultdict(list)
    for cid in all_cases:
        buckets[manifest[cid]["context_complexity"]].append(cid)
    print_bucket_table("Structural vs context-heavy", buckets, case_to_repo, case_to_samples)

    # 4. Supported vs partially supported (unsupported cases excluded from comparative metrics,
    # per Section 7.3's own established convention -- not included as a 3rd bucket here)
    buckets = defaultdict(list)
    for cid in all_cases:
        rep = manifest[cid]["semgrep_representability"]
        if rep in ("supported", "partially_supported"):
            buckets[rep].append(cid)
    print_bucket_table("Supported vs partially supported (unsupported excluded)", buckets, case_to_repo, case_to_samples)

    # 5. Older vs newer CVE (median year split)
    years = {cid: cve_year(manifest[cid]) for cid in all_cases}
    valid_years = sorted(y for y in years.values() if y is not None)
    median_year = valid_years[len(valid_years) // 2]
    buckets = defaultdict(list)
    for cid in all_cases:
        y = years[cid]
        if y is None:
            continue
        buckets[f"<= {median_year} (older)" if y <= median_year else f"> {median_year} (newer)"].append(cid)
    print(f"\n  (median CVE year across all cases: {median_year} -- note: substitutes for the "
          f"never-populated `advisory_date` field, year-level granularity only, flagged in scope doc)")
    print_bucket_table("Older vs newer CVE", buckets, case_to_repo, case_to_samples)

    # 6. Patch size (tertiles, total added+deleted lines)
    sizes = {cid: manifest[cid]["patch_size_added"] + manifest[cid]["patch_size_deleted"] for cid in all_cases}
    sorted_cases = sorted(all_cases, key=lambda c: sizes[c])
    n = len(sorted_cases)
    t1, t2 = sorted_cases[: n // 3], sorted_cases[n // 3: 2 * n // 3]
    t3 = sorted_cases[2 * n // 3:]
    buckets = {
        f"small (<= {sizes[t1[-1]]} lines)": t1,
        f"medium ({sizes[t2[0]]}-{sizes[t2[-1]]} lines)": t2,
        f"large (>= {sizes[t3[0]]} lines)": t3,
    }
    print_bucket_table("Patch size (tertiles)", buckets, case_to_repo, case_to_samples)

    # 7. CWE -- counts only; CI only for CWEs with >= 10 cases, rest reported honestly as too sparse
    cwe_buckets = defaultdict(list)
    for cid in all_cases:
        for cwe in manifest[cid].get("cwe_ids") or ["(none)"]:
            cwe_buckets[cwe].append(cid)
    print(f"\n  -- CWE breakdown ({len(cwe_buckets)} distinct CWE IDs across {len(all_cases)} cases) --")
    well_populated = {k: v for k, v in cwe_buckets.items() if len(v) >= 10}
    sparse = {k: v for k, v in cwe_buckets.items() if len(v) < 10}
    print(f"  {len(well_populated)} CWE(s) have >= 10 cases (CI reported); "
          f"{len(sparse)} CWE(s) have < 10 cases (count only, no CI -- too sparse for a meaningful "
          f"bootstrap CI, stated explicitly rather than silently dropped)")
    if well_populated:
        print_bucket_table("CWEs with >= 10 cases", well_populated, case_to_repo, case_to_samples)
    print(f"\n  Sparse CWEs (count only): {sorted(((k, len(v)) for k, v in sparse.items()), key=lambda kv: -kv[1])[:20]}"
          f"{' ... (truncated)' if len(sparse) > 20 else ''}")


if __name__ == "__main__":
    main()
