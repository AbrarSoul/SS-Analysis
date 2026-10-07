"""
Section 13.4 / RQ8 stability analysis: "How consistent are rule syntax and detection behavior
across repeated generations?" -- 5 repeats, temperature 0.2, the same stratified 100-case subset
(benchmark/stability_subset_100.json), the same 8 primary models, autogrep_default prompt.

The design doc states RQ8 as a question (Section 2, line 70-72) and fixes the experimental
configuration (Section 13.4: temp 0.2, 5 repeats, 100-case subset) but gives no exact formula for
"stability" the way Section 21 gives exact formulas for MCC/VGR/FPR/etc. The two measures below are
therefore a documented methodology choice, not a literal spec requirement:

1. Metric-level spread: reuses analyze_phase5_primary.py's pooled-confusion machinery (same MCC/
   VGR/FPR/PDS/ESR definitions, same Section 7.3 supported-cases-only scope) computed SEPARATELY per
   repeat, then reports mean/min/max across the 5 repeats per model -- shows how much the Phase 5
   headline numbers could plausibly have varied under a different sampling draw.
2. Case-level outcome agreement: for each (case, model), builds a fingerprint per repeat --
   "syntax" = whether the autogrep rule validated at all (semgrep_valid); "full-behavior" = the
   complete sorted (sample_type, outcome) pattern across all 6 bundle samples -- and measures what
   fraction of the 5 repeats match the most common (modal) fingerprint for that case, averaged over
   cases. This directly answers RQ8's two stated halves (rule syntax / detection behavior) with one
   interpretable number each per model: 1.0 = perfectly reproducible even at temperature 0.2, lower
   values = real run-to-run variation.

Both measures restrict to `supported` cases within the subset (Section 7.3's primary-ranking scope),
matching analyze_phase5_primary.py's own convention.

Correction (2026-10-07 audit round 2, Priority 8): this script previously read sample_execution_log
from `results/` (original, uncorrected data) in every code path, despite Paper_Draft_Notes.md's §7.3
labeling its output "corrected data" -- that label was not actually true of this script's own output.
Finding 1's location-correctness fix changes hidden-variant TP/FN outcomes, which both PART 1 (MCC/
VGR/FPR/ESR) and PART 2 (full-behavior agreement fingerprint) depend on directly. Fixed to read
generation_log from `results/` (visible-pair accept/reject is unaffected by Finding 1) and
sample_execution_log from `results_corrected/` (where Finding 1's fix lives) -- the same split
already used throughout `analyze_section22_corrected.py` and `build_step4_tables.py`.
"""
import glob
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import load_manifest, analyze_model
from eligible_cases import POST_HOC_DATASET_EXCLUSIONS, GROUND_TRUTH_EXCLUSIONS, VERSION as ELIGIBLE_VERSION

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
RESULTS_ROOT = Path(__file__).resolve().parent.parent / "results"
RESULTS_CORRECTED_ROOT = Path(__file__).resolve().parent.parent / "results_corrected"
CODELLAMA = "codellama:7b-instruct-fp16"
N_REPEATS = 5


def load_run_dir_corrected(d: Path, corrected_d: Path):
    """gen from the original run dir (unaffected by Finding 1); smp from its results_corrected/
    counterpart (where Finding 1's location-correctness fix lives)."""
    gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (corrected_d / "sample_execution_log.jsonl").read_text().splitlines()]
    return gen, smp


def load_stability_subset_ids():
    d = json.loads((BENCH_DIR / "stability_subset_100.json").read_text())
    return d["case_ids"]


def modal_agreement(fingerprints):
    counts = Counter(fingerprints)
    return counts.most_common(1)[0][1] / len(fingerprints)


def main():
    manifest = load_manifest()
    subset_ids = load_stability_subset_ids()
    subset_manifest = {cid: manifest[cid] for cid in subset_ids}
    rep_counts = Counter(subset_manifest[cid]["semgrep_representability"] for cid in subset_ids)
    excluded = POST_HOC_DATASET_EXCLUSIONS | GROUND_TRUTH_EXCLUSIONS
    supported_ids_raw = [cid for cid in subset_ids if subset_manifest[cid]["semgrep_representability"] == "supported"]
    supported_ids = [cid for cid in supported_ids_raw if cid not in excluded]

    print("=" * 100)
    print("PHASE 7 STABILITY ANALYSIS -- Section 13.4 / RQ8 (5 repeats, temperature 0.2, autogrep_default)")
    print("=" * 100)
    print(f"\nStability subset: {len(subset_ids)} cases -- supported={rep_counts['supported']}, "
          f"partially_supported={rep_counts['partially_supported']}, unsupported={rep_counts['unsupported']}")
    print(f"Of the {len(supported_ids_raw)} supported cases, {len(supported_ids_raw) - len(supported_ids)} are "
          f"ground-truth-excluded (eligible_cases.py v{ELIGIBLE_VERSION}) -- metrics below use the "
          f"eligible n={len(supported_ids)}, matching Section 7.3's primary scope exactly (2026-10-07, "
          f"external reviewer feedback round 3: previously used all {len(supported_ids_raw)} supported "
          f"cases without applying the ground-truth exclusions).")

    rep1_dirs = sorted(glob.glob(str(RESULTS_ROOT / "runs_phase5_stability_rep1" / "*__autogrep_default")))
    models = [json.loads((Path(d) / "generation_log.jsonl").read_text().splitlines()[0])["model_tag"] for d in rep1_dirs]

    per_repeat_metrics = defaultdict(lambda: defaultdict(list))  # model -> metric -> [val x5]
    per_repeat_raw = defaultdict(dict)  # model -> rep -> (gen, smp)

    for rep in range(1, N_REPEATS + 1):
        dirs = sorted(glob.glob(str(RESULTS_ROOT / f"runs_phase5_stability_rep{rep}" / "*__autogrep_default")))
        for d in dirs:
            d = Path(d)
            corrected_d = RESULTS_CORRECTED_ROOT / f"runs_phase5_stability_rep{rep}" / d.name
            gen, smp = load_run_dir_corrected(d, corrected_d)
            model = gen[0]["model_tag"]
            per_repeat_raw[model][rep] = (gen, smp)
            autogrep = analyze_model(model, gen, smp, subset_manifest, {"supported"})["autogrep"]
            per_repeat_metrics[model]["mcc"].append(autogrep["mcc"])
            per_repeat_metrics[model]["vgr_pooled"].append(autogrep["vgr_pooled"])
            per_repeat_metrics[model]["fpr"].append(autogrep["fpr"])
            per_repeat_metrics[model]["pds"].append(autogrep["pds"])
            per_repeat_metrics[model]["esr"].append(autogrep["esr"].get((0.80, 0.10)))

    print(f"\n{'-' * 100}")
    print(f"PART 1 -- metric-level spread across {N_REPEATS} repeats (autogrep condition, supported cases, n={len(supported_ids)})")
    print(f"{'-' * 100}")
    print(f"{'model':32} {'MCC mean':>9} {'MCC min':>8} {'MCC max':>8} {'VGR mean':>9} {'FPR mean':>9} {'ESR mean':>9}")

    def stat(xs):
        xs = [v for v in xs if v is not None]
        return (sum(xs) / len(xs), min(xs), max(xs)) if xs else (None, None, None)

    def fmt(x):
        return f"{x:7.3f}" if x is not None else "    n/a"

    rows = []
    for model in models:
        if model == CODELLAMA:
            continue
        v = per_repeat_metrics[model]
        mcc_mean, mcc_min, mcc_max = stat(v["mcc"])
        vgr_mean, _, _ = stat(v["vgr_pooled"])
        fpr_mean, _, _ = stat(v["fpr"])
        esr_mean, _, _ = stat(v["esr"])
        rows.append((mcc_mean if mcc_mean is not None else -999,
                     f"{model:32} {fmt(mcc_mean)} {fmt(mcc_min)} {fmt(mcc_max)} {fmt(vgr_mean)} {fmt(fpr_mean)} {fmt(esr_mean)}"))
    rows.sort(key=lambda t: -t[0])
    for _, line in rows:
        print(line)

    if CODELLAMA in per_repeat_metrics:
        mcc_mean, mcc_min, mcc_max = stat(per_repeat_metrics[CODELLAMA]["mcc"])
        print(f"\n(codellama, precision outlier, not ranked): MCC mean={mcc_mean:.3f} min={mcc_min:.3f} max={mcc_max:.3f}")

    print(f"\n{'-' * 100}")
    print("PART 2 -- case-level outcome agreement (fraction of repeats matching the modal outcome, averaged over cases)")
    print(f"{'-' * 100}")
    print(f"{'model':32} {'syntax agreement':>18} {'full-behavior agreement':>24}")

    agree_rows = []
    for model in models:
        syntax_agreements, behavior_agreements = [], []
        for cid in supported_ids:
            syntax_fp, behavior_fp = [], []
            for rep in range(1, N_REPEATS + 1):
                gen, smp = per_repeat_raw[model][rep]
                g = next((g for g in gen if g["condition"] == "autogrep" and g["case_id"] == cid), None)
                syntax_fp.append(bool(g and g["yaml_valid"] and g["semgrep_valid"]))
                samples = sorted((s["sample_type"], s["outcome"]) for s in smp
                                  if s["condition"] == "autogrep" and s["case_id"] == cid)
                behavior_fp.append(tuple(samples))
            syntax_agreements.append(modal_agreement(syntax_fp))
            behavior_agreements.append(modal_agreement(behavior_fp))
        syn_mean = sum(syntax_agreements) / len(syntax_agreements)
        beh_mean = sum(behavior_agreements) / len(behavior_agreements)
        tag = " (outlier)" if model == CODELLAMA else ""
        agree_rows.append((beh_mean, f"{model + tag:32} {syn_mean:18.3f} {beh_mean:24.3f}"))
    agree_rows.sort(key=lambda t: -t[0])
    for _, line in agree_rows:
        print(line)

    print(f"\nNote: syntax agreement = 1.0 means the rule's validate-or-not outcome (semgrep_valid) was identical "
          f"in all {N_REPEATS} repeats for every case; full-behavior agreement additionally requires every one of "
          f"the 6 bundle samples' TP/FP/FN/TN outcome to match across repeats. Both are the modal (most common) "
          f"outcome's share of the {N_REPEATS} repeats, averaged over the {len(supported_ids)} supported cases.")


if __name__ == "__main__":
    main()
