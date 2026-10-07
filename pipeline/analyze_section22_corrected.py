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

Correction (2026-10-07 audit round 2, Priority 3+6): two further fixes.
1. Case population switched from analyze_section22.supported_case_ids() (the uncorrected 153,
   no CASE-0166/ground-truth exclusions) to pipeline/eligible_cases.py's frozen 150-case
   eligible_supported_cases() -- "paired comparisons on the SAME eligible population" (Priority 6).
2. Repository-awareness EXTENDED to the end-to-end (ESR) comparisons, not just MCC: the exact
   McNemar test on discordant pairs assumes pairs are independent, which Section22_Scope.md's own
   stated principle says is false for cases sharing a repo. `pooled_esr_fn` + the same
   `repo_aware_bootstrap` primitive already used for MCC now also produces a repo-aware CI/p-value
   for the ESR difference; THAT p-value (not McNemar's) is now what Holm correction and the
   "SIGNIFICANT" flag are based on. McNemar's b/c counts are kept printed for descriptive context
   only. Also: a bootstrap p-value of exactly 0 with n_boot=10000 means "no resample crossed zero,"
   not "p is truly 0" -- printed as "p < 0.0001" (the test's resolution floor) instead of "p=0.0000"
   per the audit's explicit instruction to never report p=0.0000 as if it were an exact value.
"""
import json
import random
import sys
import warnings
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, rate, per_case_vgr_fpr, load_manifest, gated_samples
from analyze_section22 import PRIMARY_MODEL_DIRS, C2_MODEL_DIRS, _esr_from_samples
from eligible_cases import eligible_supported_cases, VERSION as ELIGIBLE_VERSION
from stats_section22 import mcnemar_exact, holm_correct, friedman_on_matrix, wilcoxon_paired


def fmt_p(p):
    """Never prints a rounded-to-zero p-value as if it were exact (audit instruction)."""
    return "p < 0.0001" if p < 0.0001 else f"p={p:.4f}"

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
        case_samples = gated_samples(cid, executable, smp_by_case)
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
        executable = bool(e["accepted"])
        case_samples = gated_samples(cid, executable, smp_by_case)
        out[cid] = {"esr": _esr_from_samples(case_samples, executable), "samples": case_samples}
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
        executable = bool(e["accepted"])
        case_samples = gated_samples(cid, executable, smp_by_case)
        out[cid] = {"esr": _esr_from_samples(case_samples, executable), "samples": case_samples}
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


def pooled_esr_fn(cond_data):
    def fn(ids):
        return sum(cond_data[cid]["esr"] for cid in ids) / len(ids) if ids else 0.0
    return fn


def paired_comparison_corrected(label_a, data_a, label_b, data_b, case_to_repo, n_boot=10000):
    common = sorted(set(data_a) & set(data_b))
    b = sum(1 for c in common if data_a[c]["esr"] == 1 and data_b[c]["esr"] == 0)
    cc = sum(1 for c in common if data_a[c]["esr"] == 0 and data_b[c]["esr"] == 1)
    mcnemar_p = mcnemar_exact(b, cc)  # descriptive only -- assumes independent pairs, not used for significance
    esr_a = sum(data_a[c]["esr"] for c in common) / len(common)
    esr_b = sum(data_b[c]["esr"] for c in common) / len(common)

    esr_fn_a, esr_fn_b = pooled_esr_fn(data_a), pooled_esr_fn(data_b)
    esr_diff, esr_lo, esr_hi, esr_boot_p = repo_aware_bootstrap(common, case_to_repo, esr_fn_a, esr_fn_b, n_boot=n_boot)

    fn_a, fn_b = pooled_mcc_fn(data_a), pooled_mcc_fn(data_b)
    diff, lo, hi, boot_p = repo_aware_bootstrap(common, case_to_repo, fn_a, fn_b, n_boot=n_boot)

    return {
        "label_a": label_a, "label_b": label_b, "n_common": len(common),
        "esr_a": esr_a, "esr_b": esr_b, "mcnemar_b": b, "mcnemar_c": cc, "mcnemar_p": mcnemar_p,
        "esr_diff": esr_diff, "esr_ci": (esr_lo, esr_hi), "esr_boot_p": esr_boot_p,
        "mcc_a": fn_a(common), "mcc_b": fn_b(common),
        "mcc_diff": diff, "mcc_ci": (lo, hi), "mcc_boot_p": boot_p,
    }


def print_comparison(r):
    sig = "no statistically detectable difference" if r["esr_boot_p"] >= 0.05 else "SIGNIFICANT"
    print(f"\n  {r['label_a']}  vs  {r['label_b']}   (n={r['n_common']} common cases)")
    print(f"    ESR: {r['esr_a']:.3f} vs {r['esr_b']:.3f}  |  diff={r['esr_diff']:+.3f}  "
          f"95% CI=({r['esr_ci'][0]:+.3f}, {r['esr_ci'][1]:+.3f})  repo-aware bootstrap {fmt_p(r['esr_boot_p'])}  [{sig}]")
    print(f"    (descriptive only, assumes independent pairs) McNemar b={r['mcnemar_b']} c={r['mcnemar_c']}  {fmt_p(r['mcnemar_p'])}")
    print(f"    MCC (conditional, among accepted cases only): {r['mcc_a']:.3f} vs {r['mcc_b']:.3f}  |  diff={r['mcc_diff']:+.3f}  "
          f"95% CI=({r['mcc_ci'][0]:+.3f}, {r['mcc_ci'][1]:+.3f})  repo-aware bootstrap {fmt_p(r['mcc_boot_p'])}")


def main():
    supported = eligible_supported_cases()
    manifest = load_manifest()
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    print(f"eligible_cases.py v{ELIGIBLE_VERSION}: {len(supported)} eligible supported cases "
          f"(CASE-0166 dataset exclusion + 3 ground-truth exclusions applied). Using CORRECTED "
          f"sample data (results_corrected/) + REPOSITORY-AWARE bootstrap throughout, extended to "
          f"the ESR/end-to-end comparisons as well as MCC (2026-10-07 audit round 2, Priority 6).\n")

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
        print("  (descriptive/exploratory only -- NOT repository-aware; scipy's friedmanchisquare")
        print("  assumes independent rows, false here since cases share repositories. Only the")
        print("  repo-aware bootstrap pairwise follow-ups below carry a confirmatory claim.)")
        for m in family_models:
            esr_m = sum(family_data[m][c]["esr"] for c in common) / len(common)
            print(f"    {m}: ESR={esr_m:.3f}")
        if p < 0.05:
            print("  Omnibus p<0.05 (descriptive) -- running repo-aware ESR bootstrap pairwise follow-ups")
            print("  (not McNemar: cases sharing a repo aren't independent, Section22_Scope.md):")
            pairs = [(i, j) for i in range(len(family_models)) for j in range(i + 1, len(family_models))]
            raw_ps = []
            for i, j in pairs:
                ma, mb = family_models[i], family_models[j]
                _, _, _, boot_p = repo_aware_bootstrap(common, case_to_repo, pooled_esr_fn(family_data[ma]), pooled_esr_fn(family_data[mb]))
                raw_ps.append(boot_p)
            adj_ps = holm_correct(raw_ps)
            for (i, j), raw_p, adj_p in zip(pairs, raw_ps, adj_ps):
                flag = " *" if adj_p < 0.05 else ""
                print(f"    {family_models[i]} vs {family_models[j]}: raw {fmt_p(raw_p)}  Holm-adj {fmt_p(adj_p)}{flag}")
        else:
            print("  Omnibus not significant -- no pairwise follow-ups run.")

    print("\n" + "=" * 100)
    print("COMPARISON 4: Raw vs Autogrep (pipeline effect), all 8 models -- CORRECTED")
    print("=" * 100)
    esr_ps, mcc_ps = [], []
    for m, dirname in PRIMARY_MODEL_DIRS.items():
        a = load_primary_corrected(dirname, "raw", supported)
        b = load_primary_corrected(dirname, "autogrep", supported)
        r = paired_comparison_corrected(f"{m} (raw)", a, f"{m} (autogrep)", b, case_to_repo)
        print_comparison(r)
        esr_ps.append(r["esr_boot_p"])
        mcc_ps.append(r["mcc_boot_p"])
    adj_esr = holm_correct(esr_ps)
    n_sig_esr = sum(1 for p in adj_esr if p < 0.05)
    adj_mcc = holm_correct(mcc_ps)
    n_sig_mcc = sum(1 for p in adj_mcc if p < 0.05)
    print(f"\n  Aggregate (end-to-end/ESR): {n_sig_esr}/{len(PRIMARY_MODEL_DIRS)} models show a "
          f"significant raw-vs-autogrep ESR difference after Holm correction (repo-aware bootstrap p-values).")
    print(f"  Aggregate (conditional MCC, among each condition's own accepted cases): "
          f"{n_sig_mcc}/{len(PRIMARY_MODEL_DIRS)} models show a significant difference after Holm "
          f"correction. Direction: raw's conditional MCC is numerically HIGHER than autogrep's for "
          f"7 of 8 models (the one exception, codellama, is the precision outlier).")

    print("\n" + "=" * 100)
    print("COMPARISON 5: C1 vs C2 (iterative feedback effect), all 8 models -- CORRECTED")
    print("=" * 100)
    esr_ps, mcc_ps = [], []
    for m, dirname in PRIMARY_MODEL_DIRS.items():
        a = load_primary_corrected(dirname, "raw", supported)
        b = load_c2_corrected(C2_MODEL_DIRS[m], supported)
        r = paired_comparison_corrected(f"{m} (C1/raw)", a, f"{m} (C2)", b, case_to_repo)
        print_comparison(r)
        esr_ps.append(r["esr_boot_p"])
        mcc_ps.append(r["mcc_boot_p"])
    adj_esr = holm_correct(esr_ps)
    n_sig_esr = sum(1 for p in adj_esr if p < 0.05)
    adj_mcc = holm_correct(mcc_ps)
    n_sig_mcc = sum(1 for p in adj_mcc if p < 0.05)
    print(f"\n  Aggregate (end-to-end/ESR): {n_sig_esr}/{len(PRIMARY_MODEL_DIRS)} models show a "
          f"significant C1-vs-C2 ESR difference after Holm correction (repo-aware bootstrap p-values).")
    print(f"  Aggregate (conditional MCC, among each condition's own accepted cases): "
          f"{n_sig_mcc}/{len(PRIMARY_MODEL_DIRS)} models show a significant difference after Holm correction.")

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
        print("  (descriptive/exploratory only -- NOT repository-aware; see Comparison 3's note.")
        print("  Only the repo-aware bootstrap pairwise follow-ups below carry a confirmatory claim.)")
        for lb in labels:
            esr_lb = sum(ma_data[lb][c]["esr"] for c in common) / len(common)
            print(f"    {lb}: ESR={esr_lb:.3f}")

    pairs = [(i, j) for i in range(len(labels)) for j in range(i + 1, len(labels))]

    print("\n  Pairwise ESR (end-to-end) repo-aware bootstrap for all 6 pairs:")
    raw_ps_esr = []
    results_esr = []
    for i, j in pairs:
        la, lb = labels[i], labels[j]
        diff, lo, hi, boot_p = repo_aware_bootstrap(common, case_to_repo, pooled_esr_fn(ma_data[la]), pooled_esr_fn(ma_data[lb]))
        raw_ps_esr.append(boot_p)
        results_esr.append((la, lb, diff, lo, hi, boot_p))
    adj_ps_esr = holm_correct(raw_ps_esr)
    for (la, lb, diff, lo, hi, boot_p), adj_p in zip(results_esr, adj_ps_esr):
        flag = " *" if adj_p < 0.05 else ""
        print(f"    {la} vs {lb}: ESR diff={diff:+.3f}  95% CI=({lo:+.3f}, {hi:+.3f})  "
              f"raw {fmt_p(boot_p)}  Holm-adj {fmt_p(adj_p)}{flag}")

    print("\n  Pairwise MCC (conditional, among accepted cases only) repo-aware bootstrap for all 6")
    print("  pairs -- the metric the original C4-A/C4-B narrative was built on:")
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
              f"raw {fmt_p(boot_p)}  Holm-adj {fmt_p(adj_p)}{flag}")


if __name__ == "__main__":
    main()
