"""
Section 22 (design doc) formal statistical analysis -- the 7 predefined comparisons (Section 22.3)
plus subgroup analysis (Section 22.4). Scoped in Research_Log/Section22_Scope.md; read that first for
the methodology decisions this script implements (case-level paired bootstrap for pooled metrics
like MCC since there's no natural per-case MCC value; McNemar for per-case binary ESR; real Wilcoxon
only for genuinely per-case scalars like tokens/latency; Friedman for >2-condition omnibus tests).

Reuses analyze_phase5_primary.py's confusion_from_samples/mcc/rate/per_case_vgr_fpr directly (no
duplication, no modification to that already-trusted script) and stats_section22.py's hand-rolled
McNemar/Holm/bootstrap primitives (independently verified in pipeline/tests/test_stats_section22.py
before being trusted here).
"""
import json
import re
import sys
import warnings
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import load_manifest, confusion_from_samples, mcc, rate, per_case_vgr_fpr, CODELLAMA
from stats_section22 import mcnemar_exact, holm_correct, paired_case_bootstrap, friedman_on_matrix, wilcoxon_paired

warnings.filterwarnings("ignore", category=RuntimeWarning, module="scipy")

RESULTS = Path(__file__).resolve().parent.parent / "results"
BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"

VGR_T, FPR_T = 1.00, 0.00  # the single effective ESR threshold -- Section 12.23 showed the 3x3
                            # grid collapses to this one combination given 2 vuln variants / 3 negs


# ---------------------------------------------------------------------------------------------
# Data loading: every condition normalized to {case_id: {"esr": 0/1, "samples": [...], "tokens":
# int|None, "latency": float|None}}, so every comparison downstream is condition-agnostic.
# ---------------------------------------------------------------------------------------------

def _esr_from_samples(case_samples, executable: bool) -> int:
    if not executable or not case_samples:
        return 0
    vgr, fpr, vuln_tp, patched_tn = per_case_vgr_fpr(case_samples)
    ok = (vuln_tp and patched_tn and vgr is not None and vgr >= VGR_T and fpr is not None and fpr <= FPR_T)
    return 1 if ok else 0


def load_primary(model_dir_name: str, condition: str, case_filter=None):
    d = RESULTS / "runs_phase5_primary" / model_dir_name
    gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (d / "sample_execution_log.jsonl").read_text().splitlines()]
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
        tokens = None
        if g.get("input_tokens") is not None and g.get("output_tokens") is not None:
            tokens = g["input_tokens"] + g["output_tokens"]
        out[cid] = {
            "esr": _esr_from_samples(case_samples, executable),
            "samples": case_samples,
            "tokens": tokens,
            "latency": g.get("generation_seconds"),
        }
    return out


def load_c2(model_dir_name: str, case_filter=None):
    d = RESULTS / "runs_c2_primary" / model_dir_name
    ep = [json.loads(l) for l in (d / "c2_episode_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (d / "sample_execution_log.jsonl").read_text().splitlines()]
    smp_by_case = defaultdict(list)
    for s in smp:
        smp_by_case[s["case_id"]].append(s)

    out = {}
    for e in ep:
        cid = e["case_id"]
        if case_filter is not None and cid not in case_filter:
            continue
        case_samples = smp_by_case.get(cid, [])
        out[cid] = {
            "esr": _esr_from_samples(case_samples, executable=bool(e["accepted"])),
            "samples": case_samples,
            "tokens": (e.get("input_tokens_used") or 0) + (e.get("output_tokens_used") or 0),
            "latency": e.get("wall_clock_seconds"),
        }
    return out


def load_multiagent(results_subdir: str, variant: str, case_filter=None):
    """Shared loader for C3 (results/runs_c3/<variant>/) and C4 (results/runs_c4/<variant>/) --
    same schema (c{3,4}_episode_log.jsonl + sample_execution_log.jsonl), no per-episode token/
    latency tracking (flagged explicitly in Section22_Scope.md -- Wilcoxon latency/token tests are
    skipped for these conditions, not silently fabricated)."""
    d = RESULTS / results_subdir / variant
    log_name = "c3_episode_log.jsonl" if "c3" in results_subdir else "c4_episode_log.jsonl"
    ep = [json.loads(l) for l in (d / log_name).read_text().splitlines()]
    smp = [json.loads(l) for l in (d / "sample_execution_log.jsonl").read_text().splitlines()]
    smp_by_case = defaultdict(list)
    for s in smp:
        smp_by_case[s["case_id"]].append(s)

    out = {}
    for e in ep:
        cid = e["case_id"]
        if case_filter is not None and cid not in case_filter:
            continue
        case_samples = smp_by_case.get(cid, [])
        out[cid] = {
            "esr": _esr_from_samples(case_samples, executable=bool(e["accepted"])),
            "samples": case_samples,
            "tokens": None,
            "latency": None,
        }
    return out


def load_c3(variant: str, case_filter=None):
    return load_multiagent("runs_c3", variant, case_filter)


def load_c4(variant: str, case_filter=None):
    return load_multiagent("runs_c4", variant, case_filter)


# ---------------------------------------------------------------------------------------------
# Comparison machinery: given two (or more) {case_id: {...}} dicts over the SAME case set, run the
# full battery (McNemar on ESR, case-level bootstrap on pooled MCC/VGR/FPR/PDS, Wilcoxon on tokens/
# latency where available).
# ---------------------------------------------------------------------------------------------

def paired_comparison(label_a, data_a, label_b, data_b, n_boot=10000):
    common = sorted(set(data_a) & set(data_b))
    assert len(common) > 0, f"no common cases between {label_a} and {label_b}"

    # McNemar on ESR
    b = sum(1 for c in common if data_a[c]["esr"] == 1 and data_b[c]["esr"] == 0)
    cc = sum(1 for c in common if data_a[c]["esr"] == 0 and data_b[c]["esr"] == 1)
    mcnemar_p = mcnemar_exact(b, cc)
    esr_a = sum(data_a[c]["esr"] for c in common) / len(common)
    esr_b = sum(data_b[c]["esr"] for c in common) / len(common)

    # Case-level paired bootstrap on pooled MCC
    def pooled_mcc(cond_data):
        def fn(ids):
            samples = []
            for cid in ids:
                samples.extend(cond_data[cid]["samples"])
            return mcc(confusion_from_samples(samples)) if samples else 0.0
        return fn

    mcc_diff, mcc_lo, mcc_hi, mcc_p = paired_case_bootstrap(
        common, pooled_mcc(data_a), pooled_mcc(data_b), n_boot=n_boot)

    # Wilcoxon on tokens/latency, only if BOTH conditions track them
    tok_result = lat_result = None
    if all(data_a[c]["tokens"] is not None for c in common) and all(data_b[c]["tokens"] is not None for c in common):
        tok_a = [data_a[c]["tokens"] for c in common]
        tok_b = [data_b[c]["tokens"] for c in common]
        tok_result = wilcoxon_paired(tok_a, tok_b)
    if all(data_a[c]["latency"] is not None for c in common) and all(data_b[c]["latency"] is not None for c in common):
        lat_a = [data_a[c]["latency"] for c in common]
        lat_b = [data_b[c]["latency"] for c in common]
        lat_result = wilcoxon_paired(lat_a, lat_b)

    return {
        "label_a": label_a, "label_b": label_b, "n_common": len(common),
        "esr_a": esr_a, "esr_b": esr_b, "mcnemar_b": b, "mcnemar_c": cc, "mcnemar_p": mcnemar_p,
        "mcc_a": pooled_mcc(data_a)(common), "mcc_b": pooled_mcc(data_b)(common),
        "mcc_diff": mcc_diff, "mcc_ci": (mcc_lo, mcc_hi), "mcc_boot_p": mcc_p,
        "tokens_wilcoxon": tok_result, "latency_wilcoxon": lat_result,
    }


def print_comparison(r):
    print(f"\n  {r['label_a']}  vs  {r['label_b']}   (n={r['n_common']} common cases)")
    print(f"    ESR: {r['esr_a']:.3f} vs {r['esr_b']:.3f}  |  McNemar b={r['mcnemar_b']} c={r['mcnemar_c']}  p={r['mcnemar_p']:.4f}")
    print(f"    MCC: {r['mcc_a']:.3f} vs {r['mcc_b']:.3f}  |  diff={r['mcc_diff']:+.3f}  "
          f"95% CI=({r['mcc_ci'][0]:+.3f}, {r['mcc_ci'][1]:+.3f})  bootstrap p={r['mcc_boot_p']:.4f}")
    if r["tokens_wilcoxon"] is not None:
        stat, p = r["tokens_wilcoxon"]
        print(f"    Tokens (Wilcoxon): stat={stat}  p={p:.4f}" if stat is not None else "    Tokens: all differences zero")
    if r["latency_wilcoxon"] is not None:
        stat, p = r["latency_wilcoxon"]
        print(f"    Latency (Wilcoxon): stat={stat}  p={p:.4f}" if stat is not None else "    Latency: all differences zero")


# ---------------------------------------------------------------------------------------------
# Model-name mapping (dir names -> display names) and the supported-case filter
# ---------------------------------------------------------------------------------------------

PRIMARY_MODEL_DIRS = {
    "qwen2.5-coder:7b-instruct": "qwen2.5-coder_7b-instruct__autogrep_default",
    "qwen2.5-coder:32b": "qwen2.5-coder_32b__autogrep_default",
    "DeepHat-V1-7B": "DeepHat_DeepHat-V1-7B__autogrep_default",
    "deepseek-coder:6.7b": "deepseek-coder_6.7b__autogrep_default",
    "codegemma:7b": "codegemma_7b__autogrep_default",
    "magicoder:7b": "magicoder_7b__autogrep_default",
    "yi-coder:9b": "yi-coder_9b__autogrep_default",
    "codellama:7b-instruct-fp16": "codellama_7b-instruct-fp16__autogrep_default",
}
C2_MODEL_DIRS = {k: v.replace("autogrep_default", "c2") for k, v in PRIMARY_MODEL_DIRS.items()}


def supported_case_ids():
    manifest = load_manifest()
    return {cid for cid, r in manifest.items() if r["semgrep_representability"] == "supported"}


def main():
    supported = supported_case_ids()
    print(f"Loaded manifest: {len(supported)} supported cases (restriction used throughout, per "
          f"Section 7.3's established primary-ranking scope).")

    print("\n" + "=" * 100)
    print("COMPARISON 1: Qwen2.5-Coder 7B vs 32B (scale effect)")
    print("=" * 100)
    a = load_primary(PRIMARY_MODEL_DIRS["qwen2.5-coder:7b-instruct"], "autogrep", supported)
    b = load_primary(PRIMARY_MODEL_DIRS["qwen2.5-coder:32b"], "autogrep", supported)
    print_comparison(paired_comparison("qwen2.5-coder:7b-instruct (autogrep)", a, "qwen2.5-coder:32b (autogrep)", b))

    print("\n" + "=" * 100)
    print("COMPARISON 2: Qwen2.5-Coder 7B vs DeepHat 7B (security fine-tuning effect)")
    print("=" * 100)
    a = load_primary(PRIMARY_MODEL_DIRS["qwen2.5-coder:7b-instruct"], "autogrep", supported)
    b = load_primary(PRIMARY_MODEL_DIRS["DeepHat-V1-7B"], "autogrep", supported)
    print_comparison(paired_comparison("qwen2.5-coder:7b-instruct (autogrep)", a, "DeepHat-V1-7B (autogrep)", b))

    print("\n" + "=" * 100)
    print("COMPARISON 3: Small code-model family effect at similar scale (Friedman omnibus)")
    print("=" * 100)
    family_models = ["qwen2.5-coder:7b-instruct", "deepseek-coder:6.7b", "codegemma:7b",
                      "magicoder:7b", "yi-coder:9b", "DeepHat-V1-7B"]
    print(f"  Models ({len(family_models)}, ~7-9B scale, codellama excluded per its existing "
          f"precision-confound flag, 32b excluded as the scale outlier covered by comparison 1):")
    print(f"    {family_models}")
    family_data = {m: load_primary(PRIMARY_MODEL_DIRS[m], "autogrep", supported) for m in family_models}
    common = sorted(set.intersection(*[set(d) for d in family_data.values()]))
    matrix = [[family_data[m][cid]["esr"] for m in family_models] for cid in common]
    stat, p = friedman_on_matrix(matrix)
    if stat is None:
        print(f"  Friedman omnibus degenerate (no variance across models on ESR) -- cannot test. n={len(common)}")
    else:
        print(f"  Friedman omnibus (n={len(common)} cases, k={len(family_models)} models): "
              f"stat={stat:.3f}  p={p:.4f}")
        for m in family_models:
            esr_m = sum(family_data[m][c]["esr"] for c in common) / len(common)
            print(f"    {m}: ESR={esr_m:.3f}")
        if p < 0.05:
            print("  Omnibus significant -- running Holm-corrected pairwise McNemar follow-ups:")
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
            print("  Omnibus not significant at alpha=0.05 -- no pairwise follow-ups run (avoids inflating false positives).")

    print("\n" + "=" * 100)
    print("COMPARISON 4: Raw vs Autogrep (pipeline effect) -- per model, all 8")
    print("=" * 100)
    raw_ps = []
    for m, dirname in PRIMARY_MODEL_DIRS.items():
        a = load_primary(dirname, "raw", supported)
        b = load_primary(dirname, "autogrep", supported)
        r = paired_comparison(f"{m} (raw)", a, f"{m} (autogrep)", b)
        print_comparison(r)
        raw_ps.append(r["mcnemar_p"])
    adj_ps = holm_correct(raw_ps)
    n_sig = sum(1 for p in adj_ps if p < 0.05)
    print(f"\n  Aggregate: {n_sig}/{len(PRIMARY_MODEL_DIRS)} models show a significant raw-vs-autogrep "
          f"ESR difference after Holm correction across the 8 per-model tests.")

    print("\n" + "=" * 100)
    print("COMPARISON 5: C1 vs C2 (iterative feedback effect) -- per model, all 8")
    print("=" * 100)
    raw_ps = []
    for m, dirname in PRIMARY_MODEL_DIRS.items():
        a = load_primary(dirname, "raw", supported)
        b = load_c2(C2_MODEL_DIRS[m], supported)
        r = paired_comparison(f"{m} (C1/raw)", a, f"{m} (C2)", b)
        print_comparison(r)
        raw_ps.append(r["mcnemar_p"])
    adj_ps = holm_correct(raw_ps)
    n_sig = sum(1 for p in adj_ps if p < 0.05)
    print(f"\n  Aggregate: {n_sig}/{len(PRIMARY_MODEL_DIRS)} models show a significant C1-vs-C2 "
          f"ESR difference after Holm correction across the 8 per-model tests.")

    print("\n" + "=" * 100)
    print("COMPARISON 6: C2 vs C3 (role-separation effect) -- the 2 models where both exist")
    print("=" * 100)
    a = load_c2(C2_MODEL_DIRS["qwen2.5-coder:32b"], supported)
    b = load_c3("C3-S", supported)
    print_comparison(paired_comparison("qwen2.5-coder:32b (C2)", a, "C3-S", b))
    a = load_c2(C2_MODEL_DIRS["qwen2.5-coder:7b-instruct"], supported)
    b = load_c3("C3-E", supported)
    print_comparison(paired_comparison("qwen2.5-coder:7b-instruct (C2)", a, "C3-E", b))

    print("\n" + "=" * 100)
    print("COMPARISON 7: C3 vs C4 (heterogeneous assignment effect) -- Friedman omnibus, 4 configs")
    print("=" * 100)
    ma_data = {
        "C3-S": load_c3("C3-S", supported), "C3-E": load_c3("C3-E", supported),
        "C4-A": load_c4("C4-A", supported), "C4-B": load_c4("C4-B", supported),
    }
    labels = list(ma_data.keys())
    common = sorted(set.intersection(*[set(d) for d in ma_data.values()]))
    matrix = [[ma_data[lb][cid]["esr"] for lb in labels] for cid in common]
    stat, p = friedman_on_matrix(matrix)
    if stat is None:
        print(f"  Friedman omnibus degenerate. n={len(common)}")
    else:
        print(f"  Friedman omnibus (n={len(common)} cases, k={len(labels)} configs): stat={stat:.3f}  p={p:.4f}")
        for lb in labels:
            esr_lb = sum(ma_data[lb][c]["esr"] for c in common) / len(common)
            print(f"    {lb}: ESR={esr_lb:.3f}")
        if p < 0.05:
            print("  Omnibus significant -- running Holm-corrected pairwise McNemar follow-ups:")
            pairs = [(i, j) for i in range(len(labels)) for j in range(i + 1, len(labels))]
            raw_ps = []
            for i, j in pairs:
                la, lb = labels[i], labels[j]
                b_ = sum(1 for c in common if ma_data[la][c]["esr"] == 1 and ma_data[lb][c]["esr"] == 0)
                c_ = sum(1 for c in common if ma_data[la][c]["esr"] == 0 and ma_data[lb][c]["esr"] == 1)
                raw_ps.append(mcnemar_exact(b_, c_))
            adj_ps = holm_correct(raw_ps)
            for (i, j), raw_p, adj_p in zip(pairs, raw_ps, adj_ps):
                flag = " *" if adj_p < 0.05 else ""
                print(f"    {labels[i]} vs {labels[j]}: raw p={raw_p:.4f}  Holm-adj p={adj_p:.4f}{flag}")
        else:
            print("  Omnibus not significant at alpha=0.05 on ESR -- no ESR-based pairwise follow-ups run.")

    print("\n  ESR has very low power here (base rates 1.3%-5.9%, few discordant pairs) -- running")
    print("  pairwise MCC case-level bootstrap directly as well, since MCC (not ESR) is the metric")
    print("  this study's descriptive C4-A/C4-B findings were actually built on:")
    pairs = [(i, j) for i in range(len(labels)) for j in range(i + 1, len(labels))]
    raw_ps = []
    results7 = []
    for i, j in pairs:
        la, lb = labels[i], labels[j]

        def pooled_mcc(cond_data):
            def fn(ids):
                samples = []
                for cid in ids:
                    samples.extend(cond_data[cid]["samples"])
                return mcc(confusion_from_samples(samples)) if samples else 0.0
            return fn

        diff, lo, hi, boot_p = paired_case_bootstrap(common, pooled_mcc(ma_data[la]), pooled_mcc(ma_data[lb]))
        raw_ps.append(boot_p)
        results7.append((la, lb, diff, lo, hi, boot_p))
    adj_ps = holm_correct(raw_ps)
    for (la, lb, diff, lo, hi, boot_p), adj_p in zip(results7, adj_ps):
        flag = " *" if adj_p < 0.05 else ""
        print(f"    {la} vs {lb}: MCC diff={diff:+.3f}  95% CI=({lo:+.3f}, {hi:+.3f})  "
              f"raw p={boot_p:.4f}  Holm-adj p={adj_p:.4f}{flag}")

    print("\n" + "=" * 100)
    print("NOTE: token/latency Wilcoxon tests are skipped throughout wherever not printed above --")
    print("the primary benchmark's generation_log never captured per-case tokens/latency for either")
    print("raw or autogrep (both all-None, confirmed by direct inspection, not assumed), and C3/C4's")
    print("episode logs don't track them either. Only C2 has real per-case token/latency data, but")
    print("none of its comparison partners (raw, C3) do, so no Wilcoxon token/latency test is")
    print("computable for ANY of the 7 predefined comparisons given what was actually collected.")
    print("Flagged as a genuine dataset limitation, not a script bug.")
    print("=" * 100)


if __name__ == "__main__":
    main()
