"""
Ad hoc, one-off comparison: ranks the original 8-model primary benchmark, the 7-model
2026-10-08/09 follow-up campaign, and the 2026-10-10 full-dataset gpt-4o run, all on the
identical 150-case eligible-supported population (pipeline/eligible_cases.py), all using the
Finding-1-corrected sample logs (results_corrected/), all via the shared gated_samples()/mcc()/
rate() helpers -- the same methodology as build_step4_tables.py and build_followup_table.py,
just merged into one ranked table across all three campaigns at once.

Usage:
    python pipeline/build_full_openai_comparison.py
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, rate, gated_samples
from eligible_cases import eligible_supported_cases, VERSION as ELIGIBLE_VERSION

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RESULTS_CORRECTED = ROOT / "results_corrected"

MODEL_RUNS = {
    # original 8-model primary benchmark
    "qwen2.5-coder:7b-instruct": ("runs_phase5_primary", "qwen2.5-coder_7b-instruct__autogrep_default"),
    "qwen2.5-coder:32b":         ("runs_phase5_primary", "qwen2.5-coder_32b__autogrep_default"),
    "DeepHat-V1-7B":             ("runs_phase5_primary", "DeepHat_DeepHat-V1-7B__autogrep_default"),
    "deepseek-coder:6.7b":       ("runs_phase5_primary", "deepseek-coder_6.7b__autogrep_default"),
    "codegemma:7b":              ("runs_phase5_primary", "codegemma_7b__autogrep_default"),
    "magicoder:7b":              ("runs_phase5_primary", "magicoder_7b__autogrep_default"),
    "yi-coder:9b":                ("runs_phase5_primary", "yi-coder_9b__autogrep_default"),
    "codellama:7b-instruct-fp16": ("runs_phase5_primary", "codellama_7b-instruct-fp16__autogrep_default"),
    # 7-model follow-up campaign (2026-10-08/09)
    "qwen3-coder:30b":           ("runs_followup_20261008", "qwen3-coder_30b__autogrep_default"),
    "gpt-oss:20b":               ("runs_followup_20261008", "gpt-oss_20b__autogrep_default"),
    "opencoder:8b-instruct-q4_K_M": ("runs_followup_20261008", "opencoder_8b-instruct-q4_K_M__autogrep_default"),
    "granite-code:8b-instruct-128k-q4_1": ("runs_followup_20261008", "granite-code_8b-instruct-128k-q4_1__autogrep_default"),
    "llama3.1:8b-instruct-q4_K_M": ("runs_followup_20261008", "llama3.1_8b-instruct-q4_K_M__autogrep_default"),
    "Mistral-Small-24B-Instruct-2501": ("runs_followup_20261008", "hf.co_lmstudio-community_Mistral-Small-24B-Instruct-2501-GGUF_Q8_0__autogrep_default"),
    "phi4:14b-q4_K_M":           ("runs_followup_20261008", "phi4_14b-q4_K_M__autogrep_default"),
    # 2026-10-10 full-dataset diagnostic
    "gpt-4o":                    ("runs_openai_full_20261010", "gpt-4o__autogrep_default"),
}


def is_semgrep_parse_error(ve):
    if ve is None:
        return False
    s = str(ve)
    return "Rule parse error" in s or "Invalid pattern" in s or "Syntax error" in s


def table_row(label, run_subdir, model_dir, condition, case_filter):
    gen = [json.loads(l) for l in (RESULTS / run_subdir / model_dir / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / run_subdir / model_dir / "sample_execution_log.jsonl").read_text().splitlines()]
    gen_c = {g["case_id"]: g for g in gen if g["condition"] == condition and g["case_id"] in case_filter}
    smp_by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == condition:
            smp_by_case[s["case_id"]].append(s)

    n_requested = len(case_filter)
    n_accepted = sum(1 for g in gen_c.values() if g["yaml_valid"] and g["semgrep_valid"])

    accepted_samples = []
    for cid, g in gen_c.items():
        accepted_samples.extend(gated_samples(cid, bool(g["yaml_valid"] and g["semgrep_valid"]), smp_by_case))
    cond_mcc = mcc(confusion_from_samples(accepted_samples)) if accepted_samples else None

    e2e_tp, e2e_total = 0, 0
    esr_hits = 0
    for cid in case_filter:
        g = gen_c.get(cid)
        executable = g is not None and g["yaml_valid"] and g["semgrep_valid"]
        case_samples = gated_samples(cid, executable, smp_by_case)
        variants = [s for s in case_samples if s["sample_type"].startswith("variant_vulnerable")]
        e2e_total += 2
        e2e_tp += sum(1 for s in variants if s["outcome"] == "TP")
        if executable and case_samples:
            vuln = next((s for s in case_samples if s["sample_type"] == "original_vulnerable"), None)
            patched = next((s for s in case_samples if s["sample_type"] == "original_patched"), None)
            if vuln and patched and vuln["outcome"] == "TP" and patched["outcome"] == "TN" and variants and all(v["outcome"] == "TP" for v in variants):
                fps = sum(1 for s in case_samples if s["label"] == "negative" and s["outcome"] == "FP")
                if fps == 0:
                    esr_hits += 1

    return {
        "label": label, "n_requested": n_requested, "n_accepted": n_accepted,
        "acceptance_coverage": rate(n_accepted, n_requested),
        "conditional_mcc": cond_mcc,
        "e2e_hidden_detection_rate": rate(e2e_tp, e2e_total), "e2e_tp": e2e_tp, "e2e_total": e2e_total,
        "e2e_success_rate": rate(esr_hits, n_requested), "esr_hits": esr_hits,
    }


def print_row(r):
    cm = f"{r['conditional_mcc']:.3f}" if r["conditional_mcc"] is not None else "n/a (0 accepted)"
    print(f"{r['label']:38s} accepted={r['n_accepted']:3d}/{r['n_requested']} ({r['acceptance_coverage']*100:5.1f}%)  "
          f"cond.MCC={cm:>8s}  "
          f"e2e-detect={r['e2e_hidden_detection_rate']*100:5.1f}% ({r['e2e_tp']}/{r['e2e_total']})  "
          f"e2e-success={r['e2e_success_rate']*100:5.1f}% ({r['esr_hits']}/{r['n_requested']})")


def main():
    supported = eligible_supported_cases()
    print(f"eligible_cases.py version {ELIGIBLE_VERSION} -- {len(supported)} eligible supported cases")
    print("All 16 models (8 original primary + 7 follow-up + gpt-4o full), autogrep condition,")
    print("all Finding-1-corrected, all on the identical 150-case population.\n")

    rows = []
    for label, (run_subdir, model_dir) in MODEL_RUNS.items():
        r = table_row(label, run_subdir, model_dir, "autogrep", supported)
        rows.append(r)

    print("=" * 110)
    print("Ranked by conditional MCC (headline metric):")
    print("=" * 110)
    for r in sorted(rows, key=lambda r: r["conditional_mcc"] or -1, reverse=True):
        print_row(r)

    print()
    print("=" * 110)
    print("Ranked by end-to-end success rate:")
    print("=" * 110)
    for r in sorted(rows, key=lambda r: r["e2e_success_rate"], reverse=True):
        print_row(r)


if __name__ == "__main__":
    main()
