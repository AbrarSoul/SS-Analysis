"""
Correction (2026-10-06 audit, Step 6): reruns Section 22's 7 predefined comparisons (§22.3) and
subgroup analysis (§22.4) against the corrected data from Finding 1's fix (results_corrected/,
where variant_vulnerable_1/2 samples have real finding-location-correctness applied instead of the
"fires anywhere in the file" default -- see Research_Log/Correction_Log.md).

Does NOT modify analyze_section22.py or analyze_section22_subgroups.py (the original scripts,
whose own output is already reported and should stay reproducible against the original,
uncorrected data) -- imports their stats/comparison machinery directly and only swaps WHERE sample
records are read from (results_corrected/ instead of results/; episode/generation logs are read
from the ORIGINAL results/ unchanged, since Finding 1 only affects hidden-variant sample scoring,
not the visible-pair accept/reject decision those logs record).

Also fixes a real inconsistency flagged during the audit: the original analyze_section22.py's main
comparisons used a CASE-level paired bootstrap, while analyze_section22_subgroups.py correctly used
a REPOSITORY-level bootstrap (cases from the same repo aren't independent -- this project's own
stated principle, Section22_Scope.md). This script uses repository-level resampling throughout, for
every comparison, closing that inconsistency per the audit's explicit "repository-aware uncertainty
estimates" instruction (Step 6).
"""
import json
import random
import sys
import warnings
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, rate, per_case_vgr_fpr, load_manifest
from analyze_section22 import PRIMARY_MODEL_DIRS, C2_MODEL_DIRS, supported_case_ids, _esr_from_samples
from stats_section22 import mcnemar_exact, holm_correct, friedman_on_matrix, wilcoxon_paired

warnings.filterwarnings("ignore", category=RuntimeWarning, module="scipy")

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RESULTS_CORRECTED = ROOT / "results_corrected"
BENCH_DIR = ROOT / "benchmark"


# ---------------------------------------------------------------------------------------------
# Loaders: episode/generation logs from the ORIGINAL results/ (visible-pair accept/reject is
# unaffected by Finding 1's fix); sample_execution_log from results_corrected/ (where Finding 1's
# fix lives).
# ---------------------------------------------------------------------------------------------

def load_primary_corrected(model_dir_name: str, condition: str, case_filter=None):
    gen = [json.loads(l) for l in (RESULTS / "runs_phase5_primary" / model_dir_name / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / "runs_phase5_primary" / model_dir_name / "sample_execution_log.jsonl").read_text().splitlines()]
    gen_c = {g["case_id"]: g for g in gen if g["condition"] == condition}
    smp_by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == condition:
            smp_by_case[s["case_id"]].append(s)
    out = {}
    for cid, g in gen_c.items():
        if case_filter is not None and cid not in case_filter:
            continue
        executable = bool(g["yaml_valid"] and g["semgrep_valid"])
        case_samples = smp_by_case.get(cid, [])
        out[cid] = {"esr": _esr_from_samples(case_samples, executable), "samples": case_samples}
    return out


def load_c2_corrected(model_dir_name: str, case_filter=None):
    ep = [json.loads(l) for l in (RESULTS / "runs_c2_primary" / model_dir_name / "c2_episode_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / "runs_c2_primary" / model_dir_name / "sample_execution_log.jsonl").read_text().splitlines()]
    smp_by_case = defaultdict(list)
    for s in smp:
        smp_by_case[s["case_id"]].append(s)
    out = {}
    for e in ep:
        cid = e["case_id"]
        if case_filter is not None and cid not in case_filter:
            continue
        case_samples = smp_by_case.get(cid, [])
        out[cid] = {"esr": _esr_from_samples(case_samples, executable=bool(e["accepted"])), "samples": case_samples}
    return out


def load_multiagent_corrected(results_subdir: str, variant: str, case_filter=None):
    log_name = "c3_episode_log.jsonl" if "c3" in results_subdir else "c4_episode_log.jsonl"
    ep = [json.loads(l) for l in (RESULTS / results_subdir / variant / log_name).read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / results_subdir / variant / "sample_execution_log.jsonl").read_text().splitlines()]
    smp_by_case = defaultdict(list)
    for s in smp:
        smp_by_case[s["case_id"]].append(s)
    out = {}
    for e in ep:
        cid = e["case_id"]
        if case_filter is not None and cid not in case_filter:
            continue
        case_samples = smp_by_case.get(cid, [])
        out[cid] = {"esr": _esr_from_samples(case_samples, executable=bool(e["accepted"])), "samples": case_samples}
    return out


def load_c3_corrected(variant, case_filter=None):
    return load_multiagent_corrected("runs_c3", variant, case_filter)


def load_c4_corrected(variant, case_filter=None):
    return load_multiagent_corrected("runs_c4", variant, case_filter)


# ---------------------------------------------------------------------------------------------
# Repository-aware paired bootstrap (fixes the case-level/repo-level inconsistency)
# ---------------------------------------------------------------------------------------------

def repo_grouped(case_ids, case_to_repo):
    groups = defaultdict(list)
    for cid in case_ids:
        groups[case_to_repo[cid]].append(cid)
    return groups


def repo_aware_bootstrap(common_cases, case_to_repo, metric_fn_a, metric_fn_b, n_boot=10000, seed=42):
    groups = repo_grouped(common_cases, case_to_repo)
    repo_ids = list(groups.keys())
    rng = random.Random(seed)
    n = len(repo_ids)

    def expand(repo_sample):
        cids = []
        for r in repo_sample:
            cids.extend(groups[r])
        return cids

    observed_diff = metric_fn_a(common_cases) - metric_fn_b(common_cases)
    diffs = []
    for _ in range(n_boot):
        sample_repos = [repo_ids[rng.randrange(n)] for _ in range(n)]
        cids = expand(sample_repos)
        diffs.append(metric_fn_a(cids) - metric_fn_b(cids))
    diffs.sort()
    lo = diffs[int(0.025 * n_boot)]
    hi = diffs[int(0.975 * n_boot) - 1]
    n_le = sum(1 for d in diffs if d <= 0)
    n_ge = sum(1 for d in diffs if d >= 0)
    p = min(1.0, 2 * min(n_le, n_ge) / n_boot)
    return observed_diff, lo, hi, p


def pooled_mcc_fn(cond_data):
    def fn(ids):
        samples = []
        for cid in ids:
            samples.extend(cond_data[cid]["samples"])
        return mcc(confusion_from_samples(samples)) if samples else 0.0
    return fn


def paired_comparison_corrected(label_a, data_a, label_b, data_b, case_to_repo, n_boot=10000):
    common = sorted(set(data_a) & set(data_b))
    b = sum(1 for c in common if data_a[c]["esr"] == 1 and data_b[c]["esr"] == 0)
    cc = sum(1 for c in common if data_a[c]["esr"] == 0 and data_b[c]["esr"] == 1)
    mcnemar_p = mcnemar_exact(b, cc)
    esr_a = sum(data_a[c]["esr"] for c in common) / len(common)
    esr_b = sum(data_b[c]["esr"] for c in common) / len(common)

    fn_a, fn_b = pooled_mcc_fn(data_a), pooled_mcc_fn(data_b)
    diff, lo, hi, boot_p = repo_aware_bootstrap(common, case_to_repo, fn_a, fn_b, n_boot=n_boot)

    return {
        "label_a": label_a, "label_b": label_b, "n_common": len(common),
        "esr_a": esr_a, "esr_b": esr_b, "mcnemar_b": b, "mcnemar_c": cc, "mcnemar_p": mcnemar_p,
        "mcc_a": fn_a(common), "mcc_b": fn_b(common),
        "mcc_diff": diff, "mcc_ci": (lo, hi), "mcc_boot_p": boot_p,
    }


def print_comparison(r):
    sig = "no statistically detectable difference" if r["mcc_boot_p"] >= 0.05 else "SIGNIFICANT"
    print(f"\n  {r['label_a']}  vs  {r['label_b']}   (n={r['n_common']} common cases)")
    print(f"    ESR: {r['esr_a']:.3f} vs {r['esr_b']:.3f}  |  McNemar b={r['mcnemar_b']} c={r['mcnemar_c']}  p={r['mcnemar_p']:.4f}")
    print(f"    MCC: {r['mcc_a']:.3f} vs {r['mcc_b']:.3f}  |  diff={r['mcc_diff']:+.3f}  "
          f"95% CI=({r['mcc_ci'][0]:+.3f}, {r['mcc_ci'][1]:+.3f})  repo-aware bootstrap p={r['mcc_boot_p']:.4f}  [{sig}]")


def main():
    supported = supported_case_ids()
    manifest = load_manifest()
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    print(f"Loaded {len(supported)} supported cases. Using CORRECTED sample data "
          f"(results_corrected/) + REPOSITORY-AWARE bootstrap throughout (fixes the case-level/"
          f"repo-level inconsistency flagged during the audit).\n")

    print("=" * 100)
    print("COMPARISON 1: Qwen2.5-Coder 7B vs 32B (scale effect) -- CORRECTED")
    print("=" * 100)
    a = load_primary_corrected(PRIMARY_MODEL_DIRS["qwen2.5-coder:7b-instruct"], "autogrep", supported)
    b = load_primary_corrected(PRIMARY_MODEL_DIRS["qwen2.5-coder:32b"], "autogrep", supported)
    print_comparison(paired_comparison_corrected("qwen2.5-coder:7b-instruct", a, "qwen2.5-coder:32b", b, case_to_repo))

    print("\n" + "=" * 100)
    print("COMPARISON 2: Qwen2.5-Coder 7B vs DeepHat 7B (security fine-tuning effect) -- CORRECTED")
    print("=" * 100)
    a = load_primary_corrected(PRIMARY_MODEL_DIRS["qwen2.5-coder:7b-instruct"], "autogrep", supported)
    b = load_primary_corrected(PRIMARY_MODEL_DIRS["DeepHat-V1-7B"], "autogrep", supported)
    print_comparison(paired_comparison_corrected("qwen2.5-coder:7b-instruct", a, "DeepHat-V1-7B", b, case_to_repo))

    print("\n" + "=" * 100)
    print("COMPARISON 3: Small code-model family effect (Friedman omnibus on ESR) -- CORRECTED")
    print("=" * 100)
    family_models = ["qwen2.5-coder:7b-instruct", "deepseek-coder:6.7b", "codegemma:7b",
                      "magicoder:7b", "yi-coder:9b", "DeepHat-V1-7B"]
    family_data = {m: load_primary_corrected(PRIMARY_MODEL_DIRS[m], "autogrep", supported) for m in family_models}
    common = sorted(set.intersection(*[set(d) for d in family_data.values()]))
    matrix = [[family_data[m][cid]["esr"] for m in family_models] for cid in common]
    stat, p = friedman_on_matrix(matrix)
    if stat is None:
        print("  Friedman omnibus degenerate.")
    else:
        print(f"  Friedman omnibus (n={len(common)}, k={len(family_models)}): stat={stat:.3f}  p={p:.4f}")
        for m in family_models:
            esr_m = sum(family_data[m][c]["esr"] for c in common) / len(common)
            print(f"    {m}: ESR={esr_m:.3f}")
        if p < 0.05:
            pairs = [(i, j) for i in range(len(family_models)) for j in range(i + 1, len(family_models))]
            raw_ps = []
            for i, j in pairs:
                ma, mb = family_models[i], family_models[j]
                b_ = sum(1 for c in common if family_data[ma][c]["esr"] == 1 and family_data[mb][c]["esr"] == 0)
                c_ = sum(1 for c in common if family_data[ma][c]["esr"] == 0 and family_data[mb][c]["esr"] == 1)
                raw_ps.append(mcnemar_exact(b_, c_))
            adj_ps = holm_correct(raw_ps)
            for (i, j), raw_p, adj_p in zip(pairs, raw_ps, adj_ps):
                flag = " *" if adj_p < 0.05 else ""
                print(f"    {family_models[i]} vs {family_models[j]}: raw p={raw_p:.4f}  Holm-adj p={adj_p:.4f}{flag}")
        else:
            print("  Omnibus not significant -- no pairwise follow-ups run.")

    print("\n" + "=" * 100)
    print("COMPARISON 4: Raw vs Autogrep (pipeline effect), all 8 models -- CORRECTED")
    print("=" * 100)
    raw_ps = []
    for m, dirname in PRIMARY_MODEL_DIRS.items():
        a = load_primary_corrected(dirname, "raw", supported)
        b = load_primary_corrected(dirname, "autogrep", supported)
        r = paired_comparison_corrected(f"{m} (raw)", a, f"{m} (autogrep)", b, case_to_repo)
        print_comparison(r)
        raw_ps.append(r["mcnemar_p"])
    adj_ps = holm_correct(raw_ps)
    n_sig = sum(1 for p in adj_ps if p < 0.05)
    print(f"\n  Aggregate: {n_sig}/{len(PRIMARY_MODEL_DIRS)} models show a significant raw-vs-autogrep "
          f"ESR difference after Holm correction.")

    print("\n" + "=" * 100)
    print("COMPARISON 5: C1 vs C2 (iterative feedback effect), all 8 models -- CORRECTED")
    print("=" * 100)
    raw_ps = []
    for m, dirname in PRIMARY_MODEL_DIRS.items():
        a = load_primary_corrected(dirname, "raw", supported)
        b = load_c2_corrected(C2_MODEL_DIRS[m], supported)
        r = paired_comparison_corrected(f"{m} (C1/raw)", a, f"{m} (C2)", b, case_to_repo)
        print_comparison(r)
        raw_ps.append(r["mcnemar_p"])
    adj_ps = holm_correct(raw_ps)
    n_sig = sum(1 for p in adj_ps if p < 0.05)
    print(f"\n  Aggregate: {n_sig}/{len(PRIMARY_MODEL_DIRS)} models show a significant C1-vs-C2 "
          f"ESR difference after Holm correction.")

    print("\n" + "=" * 100)
    print("COMPARISON 6: C2 vs C3 (role-separation effect) -- CORRECTED")
    print("=" * 100)
    a = load_c2_corrected(C2_MODEL_DIRS["qwen2.5-coder:32b"], supported)
    b = load_c3_corrected("C3-S", supported)
    print_comparison(paired_comparison_corrected("qwen2.5-coder:32b (C2)", a, "C3-S", b, case_to_repo))
    a = load_c2_corrected(C2_MODEL_DIRS["qwen2.5-coder:7b-instruct"], supported)
    b = load_c3_corrected("C3-E", supported)
    print_comparison(paired_comparison_corrected("qwen2.5-coder:7b-instruct (C2)", a, "C3-E", b, case_to_repo))

    print("\n" + "=" * 100)
    print("COMPARISON 7: C3 vs C4 (heterogeneous assignment effect) -- CORRECTED")
    print("=" * 100)
    ma_data = {
        "C3-S": load_c3_corrected("C3-S", supported), "C3-E": load_c3_corrected("C3-E", supported),
        "C4-A": load_c4_corrected("C4-A", supported), "C4-B": load_c4_corrected("C4-B", supported),
    }
    labels = list(ma_data.keys())
    common = sorted(set.intersection(*[set(d) for d in ma_data.values()]))
    matrix = [[ma_data[lb][cid]["esr"] for lb in labels] for cid in common]
    stat, p = friedman_on_matrix(matrix)
    if stat is None:
        print("  Friedman omnibus degenerate.")
    else:
        print(f"  Friedman omnibus (n={len(common)}, k={len(labels)}): stat={stat:.3f}  p={p:.4f}")
        for lb in labels:
            esr_lb = sum(ma_data[lb][c]["esr"] for c in common) / len(common)
            print(f"    {lb}: ESR={esr_lb:.3f}")

    print("\n  Pairwise MCC repo-aware bootstrap for all 6 pairs (MCC is the metric the original")
    print("  C4-A/C4-B narrative was built on):")
    pairs = [(i, j) for i in range(len(labels)) for j in range(i + 1, len(labels))]
    raw_ps = []
    results7 = []
    for i, j in pairs:
        la, lb = labels[i], labels[j]
        fn_a, fn_b = pooled_mcc_fn(ma_data[la]), pooled_mcc_fn(ma_data[lb])
        diff, lo, hi, boot_p = repo_aware_bootstrap(common, case_to_repo, fn_a, fn_b)
        raw_ps.append(boot_p)
        results7.append((la, lb, diff, lo, hi, boot_p))
    adj_ps = holm_correct(raw_ps)
    for (la, lb, diff, lo, hi, boot_p), adj_p in zip(results7, adj_ps):
        flag = " *" if adj_p < 0.05 else ""
        print(f"    {la} vs {lb}: MCC diff={diff:+.3f}  95% CI=({lo:+.3f}, {hi:+.3f})  "
              f"raw p={boot_p:.4f}  Holm-adj p={adj_p:.4f}{flag}")


if __name__ == "__main__":
    main()
