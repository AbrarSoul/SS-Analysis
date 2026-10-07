"""
Correction (2026-10-06 audit, Step 4): builds the explicit 5-row table the audit requires for every
condition, using the CORRECTED data throughout (results_corrected/, Finding 1's fix):

1. Compilation rate -- did the model produce an executable rule at all (regardless of correctness)?
2. Acceptance coverage -- of requested cases, how many produced a rule passing VISIBLE validation?
3. Conditional MCC/VGR/FPR -- quality of ACCEPTED rules only (the pooled metrics this project has
   reported throughout) -- explicitly labeled conditional, never used alone to crown a winner.
4. End-to-end hidden-positive detection rate -- hidden vulnerable variant samples correctly detected
   / ALL such samples across every REQUESTED case (not just accepted ones) -- a case with no
   accepted rule contributes its full expected sample count as misses, never silently excluded.
5. End-to-end successful rule rate -- requested cases meeting every correctness requirement (this is
   exactly ESR, already computed with the right denominator throughout this project -- relabeled
   here for clarity, not recomputed differently).

Missing/invalid rules are never silently excluded from rows 4-5's denominators, and never given
true-negative credit for a scan that never ran -- a case with no accepted rule contributes 0 TPs to
row 4 (both of its expected hidden-vulnerable samples count as misses) and 0 to row 5's numerator.

Correction (2026-10-07 audit round 2, Priority 3+4+7): now uses pipeline/eligible_cases.py's frozen
150-case eligible-supported population (not analyze_section22.supported_case_ids()'s uncorrected
153, which has no CASE-0166/ground-truth exclusions applied) for every row in this file.

Correction (2026-10-07 audit round 2, Priority 7 + new finding): the primary benchmark's "autogrep"
condition's top-level `yaml_valid`/`validation_error` fields do NOT measure "did the model's
candidate rule compile" -- they measure "did the candidate survive Autogrep's internal retry loop,
including a repo-checkout step that failed transiently (`validation_error ==
"repo not available for validation"`) for 60-77% of cases across all 8 models, verified against
generation_log.jsonl's attempt_trail (see Correction_Log.md, 2026-10-07 entry "Finding 2"). Every
trail entry under that error still reports yaml_valid=True, proving the candidate itself was fine --
the repo simply wasn't checked out yet when the validator tried to run semgrep against it, within
the 3-retry budget. No discrimination-failure (valid YAML + repo available + wrong verdict) appears
anywhere in any of the 8 models' logs: EVERY non-accepted record resolves to either a parse/schema
failure or this repo-unavailable infra failure. `compiled_candidate` below recovers the true
attempted-candidate compile signal from attempt_trail (did ANY retry produce valid YAML); `accepted`
is unchanged (still requires a repo-available run that actually passed); `parse_fail_count` and
`infra_fail_count` make the previously-invisible breakdown explicit, per the audit's Priority 7
instruction not to let acceptance coverage stand in for an unrecoverable compile rate -- here it IS
recoverable, so we recover it rather than mark it unavailable.
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, rate
from analyze_section22 import PRIMARY_MODEL_DIRS, C2_MODEL_DIRS
from eligible_cases import eligible_supported_cases, VERSION as ELIGIBLE_VERSION

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RESULTS_CORRECTED = ROOT / "results_corrected"

EXPECTED_HIDDEN_VULN_PER_CASE = 2  # variant_vulnerable_1 + variant_vulnerable_2, by bundle design


def classify_rejection(validation_error):
    s = str(validation_error)
    if "Rule failed to detect vulnerability" in s or "Rule incorrectly detected vulnerability" in s:
        return "discrimination_failure"
    return "compile_or_schema_failure"


def primary_table_row(label, model_dir, condition, case_filter):
    gen = [json.loads(l) for l in (RESULTS / "runs_phase5_primary" / model_dir / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / "runs_phase5_primary" / model_dir / "sample_execution_log.jsonl").read_text().splitlines()]
    gen_c = {g["case_id"]: g for g in gen if g["condition"] == condition and g["case_id"] in case_filter}
    smp_by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == condition:
            smp_by_case[s["case_id"]].append(s)

    n_requested = len(case_filter)
    n_accepted = sum(1 for g in gen_c.values() if g["yaml_valid"] and g["semgrep_valid"])

    # Recovered attempted-candidate compile signal (condition == "autogrep" only needs this; "raw"
    # has no retry loop, so its own top-level yaml_valid is already the real compile signal).
    n_compiled_candidate = sum(
        1 for g in gen_c.values()
        if g["yaml_valid"] or any(a["yaml_valid"] for a in (g.get("attempt_trail") or []))
    )
    n_parse_fail = sum(1 for g in gen_c.values() if g.get("validation_error") == "failed to parse/sanitize into a rule")
    n_infra_fail = sum(1 for g in gen_c.values() if g.get("validation_error") == "repo not available for validation")

    accepted_samples = []
    for cid, g in gen_c.items():
        if g["yaml_valid"] and g["semgrep_valid"]:
            accepted_samples.extend(smp_by_case.get(cid, []))
    cond_mcc = mcc(confusion_from_samples(accepted_samples)) if accepted_samples else None

    e2e_tp, e2e_total = 0, 0
    esr_hits = 0
    for cid in case_filter:
        g = gen_c.get(cid)
        executable = g is not None and g["yaml_valid"] and g["semgrep_valid"]
        case_samples = smp_by_case.get(cid, []) if executable else []
        variants = [s for s in case_samples if s["sample_type"].startswith("variant_vulnerable")]
        e2e_total += EXPECTED_HIDDEN_VULN_PER_CASE
        e2e_tp += sum(1 for s in variants if s["outcome"] == "TP")
        if executable and case_samples:
            vgr_vals = [s for s in variants]
            vuln = next((s for s in case_samples if s["sample_type"] == "original_vulnerable"), None)
            patched = next((s for s in case_samples if s["sample_type"] == "original_patched"), None)
            if vuln and patched and vuln["outcome"] == "TP" and patched["outcome"] == "TN" and vgr_vals and all(v["outcome"] == "TP" for v in vgr_vals):
                fps = sum(1 for s in case_samples if s["label"] == "negative" and s["outcome"] == "FP")
                if fps == 0:
                    esr_hits += 1

    return {
        "label": label, "n_requested": n_requested,
        "compilation_rate": rate(n_compiled_candidate, n_requested),
        "acceptance_coverage": rate(n_accepted, n_requested),
        "conditional_mcc": cond_mcc,
        "e2e_hidden_detection_rate": rate(e2e_tp, e2e_total), "e2e_tp": e2e_tp, "e2e_total": e2e_total,
        "e2e_success_rate": rate(esr_hits, n_requested), "esr_hits": esr_hits,
        "parse_fail": n_parse_fail, "infra_fail": n_infra_fail, "condition": condition,
    }


def is_semgrep_parse_error(ve):
    if ve is None:
        return False
    s = str(ve)
    return "Rule parse error" in s or "Invalid pattern" in s or "Syntax error" in s


def multiagent_table_row(label, results_subdir, variant, case_filter):
    log_name = "c2_episode_log.jsonl" if "c2" in results_subdir else ("c3_episode_log.jsonl" if "c3" in results_subdir else "c4_episode_log.jsonl")
    ep_path = (RESULTS / results_subdir / variant / log_name) if variant else (RESULTS / results_subdir / log_name)
    ep = [json.loads(l) for l in ep_path.read_text().splitlines()]
    smp_path = (RESULTS_CORRECTED / results_subdir / variant / "sample_execution_log.jsonl") if variant else (RESULTS_CORRECTED / results_subdir / "sample_execution_log.jsonl")
    smp = [json.loads(l) for l in smp_path.read_text().splitlines()]
    smp_by_case = defaultdict(list)
    for s in smp:
        smp_by_case[s["case_id"]].append(s)

    ep_by_case = {e["case_id"]: e for e in ep if e["case_id"] in case_filter}
    n_requested = len(case_filter)
    n_compiled = sum(1 for e in ep_by_case.values() if e["accepted"] or classify_rejection(e.get("validation_error")) == "discrimination_failure")
    n_accepted = sum(1 for e in ep_by_case.values() if e["accepted"])

    accepted_samples = []
    for cid, e in ep_by_case.items():
        if e["accepted"]:
            accepted_samples.extend(smp_by_case.get(cid, []))
    cond_mcc = mcc(confusion_from_samples(accepted_samples)) if accepted_samples else None

    e2e_tp, e2e_total = 0, 0
    esr_hits = 0
    for cid in case_filter:
        e = ep_by_case.get(cid)
        executable = e is not None and e["accepted"]
        case_samples = smp_by_case.get(cid, []) if executable else []
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
        "compilation_rate": rate(n_compiled, n_requested),
        "acceptance_coverage": rate(n_accepted, n_requested),
        "conditional_mcc": cond_mcc,
        "e2e_hidden_detection_rate": rate(e2e_tp, e2e_total), "e2e_tp": e2e_tp, "e2e_total": e2e_total,
        "e2e_success_rate": rate(esr_hits, n_requested), "esr_hits": esr_hits,
    }


def print_row(r):
    cm = f"{r['conditional_mcc']:.3f}" if r["conditional_mcc"] is not None else "n/a (0 accepted)"
    note = ""
    if r.get("condition") == "autogrep":
        note = f"  [of non-accepted: parse_fail={r['parse_fail']} infra_fail(repo unavailable)={r['infra_fail']}]"
    print(f"{r['label']:38s} n={r['n_requested']:4d}  "
          f"compile={r['compilation_rate']*100:5.1f}%  "
          f"accept={r['acceptance_coverage']*100:5.1f}%  "
          f"cond.MCC={cm:>8s}  "
          f"e2e-detect={r['e2e_hidden_detection_rate']*100:5.1f}% ({r['e2e_tp']}/{r['e2e_total']})  "
          f"e2e-success={r['e2e_success_rate']*100:5.1f}% ({r['esr_hits']}/{r['n_requested']})"
          f"{note}")


def main():
    supported = eligible_supported_cases()
    print(f"eligible_cases.py version {ELIGIBLE_VERSION} -- {len(supported)} eligible supported cases "
          f"(Priority 2+3 corrections: CASE-0166 dataset exclusion + 3 ground-truth exclusions)")
    print()
    print("Note on the autogrep condition's 'compile' column: recovered from attempt_trail (did ANY")
    print("retry produce valid YAML), not the top-level yaml_valid field, which conflates a genuine")
    print("compile failure with the validator's repo-checkout step never becoming available within")
    print("the 3-retry budget (see Correction_Log.md 'Finding 2', 2026-10-07). Raw-condition rows")
    print("follow directly after each model's autogrep row for direct comparison.")

    print("\n" + "=" * 130)
    print(f"PRIMARY BENCHMARK, {len(supported)} eligible supported cases -- autogrep row, raw row, per model")
    print("=" * 130)
    for m, dirname in PRIMARY_MODEL_DIRS.items():
        print_row(primary_table_row(m, dirname, "autogrep", supported))
        print_row(primary_table_row(m, dirname, "raw", supported))
        print()

    print("=" * 130)
    print(f"C2, {len(supported)} eligible supported cases")
    print("=" * 130)
    for m, dirname in C2_MODEL_DIRS.items():
        print_row(multiagent_table_row(m, "runs_c2_primary", dirname, supported))

    print("\n" + "=" * 130)
    print(f"C3 / C4, {len(supported)} eligible supported cases")
    print("=" * 130)
    print_row(multiagent_table_row("C3-S", "runs_c3", "C3-S", supported))
    print_row(multiagent_table_row("C3-E", "runs_c3", "C3-E", supported))
    print_row(multiagent_table_row("C4-A", "runs_c4", "C4-A", supported))
    print_row(multiagent_table_row("C4-B", "runs_c4", "C4-B", supported))


if __name__ == "__main__":
    main()
