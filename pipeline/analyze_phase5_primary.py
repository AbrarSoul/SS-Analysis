"""
Phase 7 analysis of the Phase 5 primary benchmark (design doc Section 21 metrics, Section 16.2
correctness rule, Section 7.3 representability split).

Reads results/runs_phase5_primary/*/{generation_log,sample_execution_log}.jsonl and
benchmark/manifest_frozen_final.jsonl (for each case's language/CWE/representability label),
computes per-model metrics for both the "raw" and "autogrep" conditions, and prints a report.

Key methodology decisions, made explicit rather than silently assumed:

- MCC/FPR/Specificity/Balanced-Accuracy/BSDR are computed from ONE POOLED confusion matrix per
  model (all sample-level TP/FP/FN/TN across every case in scope, summed), matching Section 21.9's
  "overall sample-level" framing -- not a macro-average of per-case values.
- PDS and VGR are likewise pooled counts (rules-detecting-vuln-not-patched / all cases; hidden
  variants detected / all hidden variants), matching their own stated formulas directly.
- Per Section 7.3: the PRIMARY ranking uses only `supported` cases. `partially_supported` cases are
  reported separately (not blended into the primary numbers). `unsupported` cases are excluded from
  comparative metrics; their count is reported.
- `codellama:7b-instruct-fp16` is computed like every other model but flagged and kept OUT of the
  primary ranking table (Section 12.23's precision-policy decision), reported in its own section.
- ESR (Section 21.13, "rules meeting every predefined correctness condition") is computed per case
  as: yaml_valid AND semgrep_valid AND VGR_this_case>=threshold AND FPR_this_case<=threshold, at
  each of the 3x3 threshold combinations Section 16.2 specifies. IMPORTANT CAVEAT, checked and
  reported rather than assumed away: with exactly 2 hidden vulnerable variants and 3 negative
  samples per case, per-case VGR only takes values {0, 0.5, 1.0} and per-case FPR only {0, 0.33,
  0.67, 1.0} -- so the 0.60/0.80 VGR thresholds are mathematically equivalent to each other (both
  require VGR=1.0, since 0.5 fails both), and the 0.10/0.20 FPR thresholds are equivalent to each
  other and to 0.00 (all three require FP=0). This is verified numerically below, not just argued.
"""
import glob
import json
from collections import Counter, defaultdict
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results" / "runs_phase5_primary"
CODELLAMA = "codellama:7b-instruct-fp16"


def load_manifest():
    out = {}
    for line in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines():
        r = json.loads(line)
        out[r["case_id"]] = r
    return out


def load_run_dir(d):
    gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (d / "sample_execution_log.jsonl").read_text().splitlines()]
    return gen, smp


def confusion_from_samples(samples):
    c = Counter(s["outcome"] for s in samples)
    return {"TP": c["TP"], "FP": c["FP"], "FN": c["FN"], "TN": c["TN"]}


def mcc(counts):
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    num = tp * tn - fp * fn
    terms = (tp + fp, tp + fn, tn + fp, tn + fn)
    if any(t == 0 for t in terms):
        return 0.0
    denom = (terms[0] * terms[1] * terms[2] * terms[3]) ** 0.5
    return num / denom


def rate(num, denom):
    return (num / denom) if denom else None


def gated_samples(cid, is_accepted, smp_by_case):
    """THE single shared rule for which sample records feed any 'accepted-only'/'conditional'
    pooled metric (MCC/VGR/FPR/PDS): a case's samples count only if that case is accepted
    (yaml_valid AND semgrep_valid for primary/raw, or the episode's own `accepted` flag for
    C2/C3/C4). Needed because sample_execution_log.jsonl is NOT reliably empty for non-accepted
    cases in every condition -- confirmed directly for "raw" (the pilot/primary benchmark's
    one-shot condition): it records a real, scored sample bundle whenever the rule's YAML parsed,
    REGARDLESS of whether semgrep_valid is True, unlike "autogrep" (whose sample records only ever
    exist for already-accepted cases, by construction of its retry loop). Before this helper
    existed, three independent call sites each re-implemented this gate, and two of them (this
    file's analyze_model() and analyze_section22_corrected.py's three loaders) did it WITHOUT the
    gate -- silently pooling rejected raw-condition rules' samples into what was reported
    everywhere as "conditional MCC among accepted cases," producing self-contradictory numbers
    across reports (e.g. qwen2.5-coder:7b-instruct raw MCC reported as both 0.626 and 0.101 for
    the supposedly identical metric on the identical population -- found and fixed 2026-10-07 per
    reviewer feedback on audit round 2). Every caller of this function now shares one
    implementation of the gate, so this class of bug can't reappear silently."""
    return smp_by_case.get(cid, []) if is_accepted else []


def is_semgrep_parse_error(validation_error) -> bool:
    """True when the rule reached Semgrep but Semgrep itself rejected it (a real syntax/pattern
    error) -- as opposed to a schema-validation failure (never reached Semgrep at all, already
    excluded from SCR's numerator via yaml_valid) or a plain discrimination miss (Semgrep ran the
    rule fine, it just didn't flag the right things). Found necessary while building this script --
    448 "Rule parse error" records in the raw data would otherwise have been miscounted as
    'executable' for SCR purposes."""
    if validation_error is None:
        return False
    if isinstance(validation_error, dict):
        t = str(validation_error.get("type", ""))
        return "parse error" in t.lower() or "syntax error" in t.lower()
    s = str(validation_error)
    return "Rule parse error" in s or "Invalid pattern" in s or "Syntax error" in s


def per_case_vgr_fpr(case_samples):
    """Returns (vgr, fpr, vuln_tp, patched_tn) for ONE case's sample records (one condition)."""
    by_type = {s["sample_type"]: s for s in case_samples}
    variants = [s for s in case_samples if s["sample_type"].startswith("variant_vulnerable")]
    vgr = rate(sum(1 for s in variants if s["outcome"] == "TP"), len(variants)) if variants else None
    negs = [s for s in case_samples if s["sample_type"] in ("original_patched", "variant_safe", "benign_lookalike")]
    fp_count = sum(1 for s in negs if s["outcome"] == "FP")
    fpr = rate(fp_count, len(negs)) if negs else None
    vuln = by_type.get("original_vulnerable")
    patched = by_type.get("original_patched")
    vuln_tp = vuln is not None and vuln["outcome"] == "TP"
    patched_tn = patched is not None and patched["outcome"] == "TN"
    return vgr, fpr, vuln_tp, patched_tn


def analyze_model(model_dir_name, gen, smp, manifest, rep_filter):
    """rep_filter: set of semgrep_representability values to include, or None for all."""
    case_lang = {cid: manifest[cid]["semgrep_representability"] for cid in manifest}
    included_cases = {cid for cid in manifest if rep_filter is None or case_lang[cid] in rep_filter}

    out = {}
    for cond in ("raw", "autogrep"):
        gen_c = [g for g in gen if g["condition"] == cond and g["case_id"] in included_cases]
        smp_by_case = defaultdict(list)
        for s in smp:
            if s["condition"] == cond and s["case_id"] in included_cases:
                smp_by_case[s["case_id"]].append(s)

        n_cases = len(included_cases)
        # SCR (Section 21.2) is specifically about the RAW condition's own generations ("Raw Syntactic
        # Compilation Rate") -- computed properly here (yaml_valid AND not rejected by Semgrep itself
        # with a real parse error) only for cond=="raw", where validation_error is reliable (it comes
        # directly from evaluate_case_bundle(), untouched by the Section 12.30 bug). For cond=="autogrep",
        # yaml_valid and semgrep_valid are IDENTICAL at the top level by construction (Autogrep's own
        # retry loop only accepts an already-validated rule), so a finer executable-vs-discriminates-
        # wrong split isn't available at this granularity even without the bug; reported as "n/a".
        if cond == "raw":
            scr_num = sum(1 for g in gen_c if g["yaml_valid"] and not is_semgrep_parse_error(g.get("validation_error")))
        else:
            scr_num = None
        pds_num = 0
        esr_hits = defaultdict(int)  # keyed by (vgr_thresh, fpr_thresh)
        all_samples = []
        vgr_values = []  # for degeneracy check
        fpr_values = []

        for cid in included_cases:
            g = next((g for g in gen_c if g["case_id"] == cid), None)
            executable = g is not None and g["yaml_valid"] and g["semgrep_valid"]
            case_samples = gated_samples(cid, executable, smp_by_case)
            all_samples.extend(case_samples)
            if not case_samples:
                continue
            vgr, fpr, vuln_tp, patched_tn = per_case_vgr_fpr(case_samples)
            if vgr is not None:
                vgr_values.append(vgr)
            if fpr is not None:
                fpr_values.append(fpr)
            if vuln_tp and patched_tn:
                pds_num += 1
            for vgr_t in (0.60, 0.80, 1.00):
                for fpr_t in (0.00, 0.10, 0.20):
                    ok = (executable and vuln_tp and patched_tn
                          and vgr is not None and vgr >= vgr_t
                          and fpr is not None and fpr <= fpr_t)
                    esr_hits[(vgr_t, fpr_t)] += 1 if ok else 0

        counts = confusion_from_samples(all_samples)
        vgr_num = sum(1 for s in all_samples if s["sample_type"].startswith("variant_vulnerable") and s["outcome"] == "TP")
        vgr_den = sum(1 for s in all_samples if s["sample_type"].startswith("variant_vulnerable"))

        out[cond] = {
            "n_cases": n_cases,
            "scr": rate(scr_num, len(gen_c)) if scr_num is not None else None,
            "pds": rate(pds_num, n_cases),
            "vgr_pooled": rate(vgr_num, vgr_den),
            "counts": counts,
            "mcc": mcc(counts),
            "fpr": rate(counts["FP"], counts["FP"] + counts["TN"]),
            "specificity": rate(counts["TN"], counts["TN"] + counts["FP"]),
            "recall": rate(counts["TP"], counts["TP"] + counts["FN"]),
            "balanced_acc": None,
            "bsdr": None,
            "esr": {k: rate(v, n_cases) for k, v in esr_hits.items()},
            "vgr_value_distribution": Counter(vgr_values),
            "fpr_value_distribution": Counter(fpr_values),
        }
        if out[cond]["recall"] is not None and out[cond]["specificity"] is not None:
            out[cond]["balanced_acc"] = (out[cond]["recall"] + out[cond]["specificity"]) / 2
            out[cond]["bsdr"] = 1 - out[cond]["balanced_acc"]
    return out


def main():
    manifest = load_manifest()
    rep_counts = Counter(r["semgrep_representability"] for r in manifest.values())
    print("=" * 100)
    print("PHASE 7 ANALYSIS -- Phase 5 primary benchmark (300 final cases, autogrep_default, temperature 0)")
    print("=" * 100)
    print(f"\nRepresentability split (design Section 7.3): supported={rep_counts['supported']}, "
          f"partially_supported={rep_counts['partially_supported']}, unsupported={rep_counts['unsupported']} "
          f"(unsupported cases excluded from comparative metrics below; count reported here per Section 7.3)")

    model_dirs = sorted(glob.glob(str(RESULTS_DIR / "*__autogrep_default")))
    results = {}
    for d in model_dirs:
        d = Path(d)
        gen, smp = load_run_dir(d)
        # Use the model_tag as it actually appears in the records (colon form, e.g.
        # "codellama:7b-instruct-fp16"), not the directory name -- that's sanitized
        # (colons/slashes -> underscores) by run_generation.py's safe_name, so parsing it back out
        # doesn't round-trip and silently broke the CODELLAMA-constant lookup below.
        model = gen[0]["model_tag"]
        results[model] = {
            "supported": analyze_model(model, gen, smp, manifest, {"supported"}),
            "partially_supported": analyze_model(model, gen, smp, manifest, {"partially_supported"}),
            "all_300": analyze_model(model, gen, smp, manifest, None),
        }

    # --- degeneracy check for the threshold sensitivity sweep ---
    any_model = next(iter(results.values()))
    vgr_dist = any_model["supported"]["autogrep"]["vgr_value_distribution"]
    fpr_dist = any_model["supported"]["autogrep"]["fpr_value_distribution"]
    print(f"\nPer-case VGR value distribution observed (checking Section 16.2's sensitivity sweep for degeneracy): "
          f"{dict(sorted(vgr_dist.items()))}")
    print(f"Per-case FPR value distribution observed: {dict(sorted(fpr_dist.items()))}")

    def print_table(rep_key, title, models_to_include):
        print(f"\n{'-' * 100}")
        print(f"{title}  (n={rep_counts.get(rep_key.replace('all_300','ALL')) if rep_key!='all_300' else 300} cases in scope)")
        print(f"{'-' * 100}")
        header = f"{'model':32} {'cond':10} {'SCR':>6} {'PDS':>6} {'VGR':>6} {'FPR':>6} {'MCC':>7} {'BSDR':>6} {'ESR(0.80/0.10)':>15}"
        print(header)
        rows = []
        for model in models_to_include:
            r = results[model][rep_key]
            for cond in ("raw", "autogrep"):
                d = r[cond]
                def fmt(x):
                    return f"{x:.3f}" if x is not None else "  n/a"
                esr = d["esr"].get((0.80, 0.10))
                rows.append((model, cond, d["mcc"] if cond == "autogrep" else -999,
                             f"{model:32} {cond:10} {fmt(d['scr'])} {fmt(d['pds'])} {fmt(d['vgr_pooled'])} "
                             f"{fmt(d['fpr'])} {fmt(d['mcc'])} {fmt(d['bsdr'])} {fmt(esr):>15}"))
        rows.sort(key=lambda t: -t[2])
        for _, _, _, line in rows:
            print(line)

    primary_models = [m for m in results if m != CODELLAMA]
    print_table("supported", "PRIMARY RANKING -- supported cases only (Section 7.3), CodeLlama excluded (Section 12.23 precision outlier)", primary_models)
    print_table("partially_supported", "SECONDARY -- partially_supported cases (analyzed separately per Section 7.3)", primary_models)

    print(f"\n{'-' * 100}")
    print(f"CODELLAMA (precision outlier, fp16 -- not ranked against the quantized models above)")
    print(f"{'-' * 100}")
    print_table("supported", "codellama, supported cases only", [CODELLAMA])

    print(f"\n{'-' * 100}")
    print("ALL 300 CASES (for reference only -- not the primary comparison; mixes supported/partial/unsupported)")
    print(f"{'-' * 100}")
    print_table("all_300", "all cases, all models", list(results.keys()))


if __name__ == "__main__":
    main()
