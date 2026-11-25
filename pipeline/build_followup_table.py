"""
Scores the 2026-10-08/09 follow-up model campaign (7 models, NOT part of the original 8-model
primary benchmark or its audit -- see pipeline/gptlab_config.py's FOLLOWUP_MODEL_HOSTS) with the
exact same methodology as build_step4_tables.py: the same shared gated_samples() helper, the same
150-case eligible-supported population (pipeline/eligible_cases.py), the same five-row structure
(compile rate, acceptance coverage, conditional MCC, end-to-end hidden-positive detection, end-to-end
successful-rule rate), and the same Autogrep compile-rate-unavailable treatment -- so this table is
directly, mechanically comparable to the original 8-model table, not a parallel invention.

Reads results/runs_followup_20261008/ (generation_log.jsonl, unaffected by Finding 1) and
results_corrected/runs_followup_20261008/ (sample_execution_log.jsonl, WITH Finding 1's
location-correctness fix applied -- pipeline/rescore_variant_location.py's TARGET_GLOBS already
includes this directory).

Usage:
    python pipeline/build_followup_table.py
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, rate, gated_samples
from eligible_cases import eligible_supported_cases, VERSION as ELIGIBLE_VERSION


def is_semgrep_parse_error(ve):
    """Verbatim copy of build_step4_tables.py's helper -- not imported from there directly, since
    that module's import chain pulls in analyze_section22 -> stats_section22 -> scipy, an
    unnecessary dependency for this script's actual needs."""
    if ve is None:
        return False
    s = str(ve)
    return "Rule parse error" in s or "Invalid pattern" in s or "Syntax error" in s

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RESULTS_CORRECTED = ROOT / "results_corrected"
RUN_SUBDIR = "runs_followup_20261008"

EXPECTED_HIDDEN_VULN_PER_CASE = 2

FOLLOWUP_MODEL_DIRS = {
    "qwen3-coder:30b": "qwen3-coder_30b__autogrep_default",
    "gpt-oss:20b": "gpt-oss_20b__autogrep_default",
    "opencoder:8b-instruct-q4_K_M": "opencoder_8b-instruct-q4_K_M__autogrep_default",
    "granite-code:8b-instruct-128k-q4_1": "granite-code_8b-instruct-128k-q4_1__autogrep_default",
    "llama3.1:8b-instruct-q4_K_M": "llama3.1_8b-instruct-q4_K_M__autogrep_default",
    "hf.co/lmstudio-community/Mistral-Small-24B-Instruct-2501-GGUF:Q8_0":
        "hf.co_lmstudio-community_Mistral-Small-24B-Instruct-2501-GGUF_Q8_0__autogrep_default",
    "phi4:14b-q4_K_M": "phi4_14b-q4_K_M__autogrep_default",
}


def table_row(label, model_dir, condition, case_filter):
    gen = [json.loads(l) for l in (RESULTS / RUN_SUBDIR / model_dir / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / RUN_SUBDIR / model_dir / "sample_execution_log.jsonl").read_text().splitlines()]
    gen_c = {g["case_id"]: g for g in gen if g["condition"] == condition and g["case_id"] in case_filter}
    smp_by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == condition:
            smp_by_case[s["case_id"]].append(s)

    n_requested = len(case_filter)
    n_accepted = sum(1 for g in gen_c.values() if g["yaml_valid"] and g["semgrep_valid"])

    # Same Priority-7 treatment as the original 8: autogrep's attempted-candidate compile rate is
    # not recoverable (Implementation_Log.md Sec 12.30); raw's top-level yaml_valid IS trustworthy.
    if condition == "autogrep":
        n_compiled_candidate = None
    else:
        n_compiled_candidate = sum(1 for g in gen_c.values() if g["yaml_valid"] and not is_semgrep_parse_error(g.get("validation_error")))

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
        e2e_total += EXPECTED_HIDDEN_VULN_PER_CASE
        e2e_tp += sum(1 for s in variants if s["outcome"] == "TP")
        if executable and case_samples:
            vuln = next((s for s in case_samples if s["sample_type"] == "original_vulnerable"), None)
            patched = next((s for s in case_samples if s["sample_type"] == "original_patched"), None)
            if vuln and patched and vuln["outcome"] == "TP" and patched["outcome"] == "TN" and variants and all(v["outcome"] == "TP" for v in variants):
                fps = sum(1 for s in case_samples if s["label"] == "negative" and s["outcome"] == "FP")
                if fps == 0:
                    esr_hits += 1

    return {
        "label": label, "n_requested": n_requested,
        "compilation_rate": rate(n_compiled_candidate, n_requested) if n_compiled_candidate is not None else None,
        "acceptance_coverage": rate(n_accepted, n_requested),
        "conditional_mcc": cond_mcc,
        "e2e_hidden_detection_rate": rate(e2e_tp, e2e_total), "e2e_tp": e2e_tp, "e2e_total": e2e_total,
        "e2e_success_rate": rate(esr_hits, n_requested), "esr_hits": esr_hits,
    }


def print_row(r):
    cm = f"{r['conditional_mcc']:.3f}" if r["conditional_mcc"] is not None else "n/a (0 accepted)"
    compile_str = f"{r['compilation_rate']*100:5.1f}%" if r["compilation_rate"] is not None else "N/A: not recoverable"
    print(f"{r['label']:65s} n={r['n_requested']:4d}  "
          f"compile={compile_str:>20s}  "
          f"accept={r['acceptance_coverage']*100:5.1f}%  "
          f"cond.MCC={cm:>8s}  "
          f"e2e-detect={r['e2e_hidden_detection_rate']*100:5.1f}% ({r['e2e_tp']}/{r['e2e_total']})  "
          f"e2e-success={r['e2e_success_rate']*100:5.1f}% ({r['esr_hits']}/{r['n_requested']})")


def main():
    supported = eligible_supported_cases()
    print(f"eligible_cases.py version {ELIGIBLE_VERSION} -- {len(supported)} eligible supported cases")
    print("Follow-up campaign (2026-10-08/09), 7 models, NOT part of the original audited 8-model set.")
    print("run_generation.py captures both conditions per case automatically -- autogrep row directly")
    print("above its raw-condition counterpart, per model, same layout as the original table.\n")

    print("=" * 130)
    print(f"FOLLOW-UP MODELS, {len(supported)} eligible supported cases -- autogrep row, raw row, per model")
    print("=" * 130)
    autogrep_rows = []
    for m, dirname in FOLLOWUP_MODEL_DIRS.items():
        r_auto = table_row(m, dirname, "autogrep", supported)
        r_raw = table_row(m, dirname, "raw", supported)
        autogrep_rows.append(r_auto)
        print_row(r_auto)
        print_row(r_raw)
        print()

    print("-" * 130)
    print("Ranked by conditional MCC, autogrep condition (same metric §7.1's headline table sorts by):")
    print("-" * 130)
    for r in sorted(autogrep_rows, key=lambda r: r["conditional_mcc"] or -1, reverse=True):
        cm = f"{r['conditional_mcc']:.3f}" if r["conditional_mcc"] is not None else "n/a"
        print(f"  {r['label']:65s} MCC={cm}")


if __name__ == "__main__":
    main()
