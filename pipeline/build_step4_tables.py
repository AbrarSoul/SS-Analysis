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

Correction (2026-10-07 audit round 2, Priority 7) -- CORRECTED AGAIN, same day: an earlier version
of this comment (and of Correction_Log.md's "Finding 2") claimed the primary benchmark autogrep
condition's high rate of `validation_error == "repo not available for validation"` (60-77% of cases
per model) was a real, previously-undiscovered validator infrastructure failure, and attempted to
"recover" a true compile rate from `attempt_trail`'s per-attempt `yaml_valid` field. **That claim was
wrong and is retracted** -- `Research_Log/Implementation_Log.md` Section 12.30 already documents the
real, pre-existing root cause, found and fixed by the original study team before any audit:
`reconstruct_attempt_trail()` (a diagnostic-only re-evaluation, independent of Autogrep's own real
retry loop) was never updated after Section 12.24's clone-free validator refactor, so it still gates
on `repo_path.exists()` -- which is `False` BY DESIGN for every curated case (a synthetic marker
path, since no clone is needed for curated cases at all). This makes it discard the real per-attempt
outcome and substitute a generic "can't validate" placeholder for every curated case, regardless of
what actually happened. Critically, Implementation_Log.md verified directly that this bug "never
produced a wrong pass, only a wrong failure-reason string" -- every one of the 1,746 affected
top-level records has `semgrep_valid == False`, a REAL rejection, not an infra-blocked one. Since
`attempt_trail` itself is documented there as "unreliable for curated cases," its `yaml_valid` field
is not a trustworthy recovered compile signal either -- the earlier "recovered 87-96% compile rate"
claim is retracted along with the infra-failure story. Per Priority 7's actual instruction ("mark
Autogrep's attempted-candidate compilation rate as unavailable unless recoverable"): it is NOT
recoverable, so `compilation_rate` for the autogrep condition is reported as unavailable (identical
to `acceptance_coverage`, since Autogrep's retry loop only ever returns an already-fully-validated
rule) -- the pre-round-2 manuscript's original framing was correct, for a more precisely-documented
reason than originally stated. `parse_fail`/`infra_fail` below are kept as accurate counts of the
stored `validation_error` STRING (useful for knowing how many are a confirmed parse/schema failure
vs. a real rejection whose specific reason is unrecoverable) but are no longer used to support any
"most of the gap is/isn't discrimination failure" causal claim.
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import confusion_from_samples, mcc, rate, gated_samples
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

    # Autogrep's attempted-candidate compile rate is NOT recoverable (attempt_trail is documented as
    # unreliable for curated cases, Implementation_Log.md Section 12.30) -- its retry loop only ever
    # returns an already-fully-validated rule, so the top-level yaml_valid/semgrep_valid fields can't
    # distinguish "never produced valid YAML" from "produced valid YAML but didn't pass." Per external
    # reviewer feedback (2026-10-07, round 3): reporting 36.0% (say) in BOTH the compile and acceptance
    # columns reads as if compile rate were a real, independently-recovered number that happens to
    # equal acceptance -- it is not recovered at all, so it is reported as None here (printed as
    # "N/A: not recoverable", never a number) rather than a duplicate of acceptance coverage. "raw" has
    # no retry loop, so its own top-level yaml_valid IS the real, trustworthy compile signal and is
    # used directly, unaffected by this.
    if condition == "autogrep":
        n_compiled_candidate = None
    else:
        n_compiled_candidate = sum(1 for g in gen_c.values() if g["yaml_valid"] and not is_semgrep_parse_error(g.get("validation_error")))
    n_parse_fail = sum(1 for g in gen_c.values() if g.get("validation_error") == "failed to parse/sanitize into a rule")
    n_infra_fail = sum(1 for g in gen_c.values() if g.get("validation_error") == "repo not available for validation")

    accepted_samples = []
    for cid, g in gen_c.items():
        accepted_samples.extend(gated_samples(cid, bool(g["yaml_valid"] and g["semgrep_valid"]), smp_by_case))
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
        "compilation_rate": rate(n_compiled_candidate, n_requested) if n_compiled_candidate is not None else None,
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
        accepted_samples.extend(gated_samples(cid, bool(e["accepted"]), smp_by_case))
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
        note = (f"  [of non-accepted: confirmed_parse_fail={r['parse_fail']} "
                 f"real_reject_reason_unrecoverable={r['infra_fail']} (Implementation_Log.md Sec 12.30)]")
    compile_str = f"{r['compilation_rate']*100:5.1f}%" if r["compilation_rate"] is not None else "N/A: not recoverable"
    print(f"{r['label']:38s} n={r['n_requested']:4d}  "
          f"compile={compile_str:>20s}  "
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
    print("Note on the autogrep condition's 'compile' column: printed as 'N/A: not recoverable',")
    print("per Priority 7 and external reviewer feedback (round 3) -- NOT a number, and specifically")
    print("not a duplicate of the acceptance-coverage figure (an earlier version of this table showed")
    print("the same percentage in both columns, which reads as a real recovered number that happens")
    print("to equal acceptance; it is not recovered at all). An even earlier pass wrongly claimed this")
    print("WAS recoverable from attempt_trail and attributed the compile-accept gap to a validator")
    print("infra failure; that was retracted after checking Implementation_Log.md Section 12.30, which")
    print("documents the real cause: a pre-existing, already-fixed-going-forward diagnostic-text bug in")
    print("a function independent of Autogrep's real retry loop -- confirmed to never affect any actual")
    print("pass/fail outcome, only the human-readable reason string for genuine rejections.")
    print("Raw-condition rows follow directly after each model's autogrep row for direct comparison.")

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
