"""
Single source for every number quoted in the MSR 2027 manuscript (Part I benchmark + Part II pilot).

Reuses the project's existing, audited computations unchanged -- it adds no new scoring logic:
  - per-model rows (raw / autogrep, 15 open-weight models + gpt-4o):
      build_full_openai_comparison.table_row
  - iterative repair loop rows (the 8 primary models; called "C2" in the logs):
      build_step4_tables.multiagent_table_row
  - paired significance tests (repository-aware bootstrap, 10,000 resamples, seed 42, Holm):
      analyze_section22_corrected.paired_comparison_corrected / load_c2_corrected
  - sample gating and ESR: analyze_phase5_primary.gated_samples, analyze_section22._esr_from_samples

New in this script (both read-only over existing results):
  1. a first-attempt failure funnel over the raw condition, extending the old
     Paper_Draft_Notes.md Sec. 9 funnel past visible acceptance, on the 150-case eligible population
     and for all 16 models;
  2. the Part II 2x2 pilot's paired analysis, as fixed before execution in
     Research_Log/Diagnostic_20261010/CD_Pilot_Allocation_20261014_v1/Readiness.md
     ("average each case's success over its three repeats before calculating paired gains/losses;
     24 requested cases primary, 11 probe-eligible cases reported separately").

Self-checks (the script stops if any fails):
  - funnel's final stage equals table_row's esr_hits for every model;
  - the original 8 models reproduce the published 0/8 ESR and 2/8 conditional-MCC significance counts;
  - Part II per-run complete-success totals equal each run's own summary.json.

Usage:
    python pipeline/paper_results.py                      # compute, print, write results_paper/*.json
    python pipeline/paper_results.py --tex OUT/numbers.tex  # additionally write LaTeX macros
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_section22_corrected as S22  # noqa: E402
from analyze_phase5_primary import confusion_from_samples, gated_samples, load_manifest, mcc  # noqa: E402
from analyze_section22 import C2_MODEL_DIRS, PRIMARY_MODEL_DIRS  # noqa: E402
from build_full_openai_comparison import MODEL_RUNS, is_semgrep_parse_error, table_row  # noqa: E402
from build_step4_tables import multiagent_table_row  # noqa: E402
from eligible_cases import VERSION as ELIGIBLE_VERSION, eligible_supported_cases  # noqa: E402
from eligible_cases import load_manifest as load_dataset_manifest  # noqa: E402  (CASE-0166 excluded)
from stats_section22 import holm_correct  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RESULTS_CORRECTED = ROOT / "results_corrected"
OUT_DIR = ROOT / "results_paper"
PART2_DIR = RESULTS / "diagnostic_20261010"

PROPRIETARY = {"gpt-4o"}
# 2026-10-15: the C2 iterative loop, run for the 7 follow-up models + gpt-4o (pipeline/run_c2.py),
# kept in its own "iterative_followup" condition rather than merged into C2_MODEL_DIRS's "iterative" --
# same convention as gptlab_config.py's separate FOLLOWUP_MODEL_HOSTS, so this later campaign is never
# silently conflated with the original 8-model primary study's audited iterative results.
C2_FOLLOWUP_MODEL_DIRS = {
    "qwen3-coder:30b": "qwen3-coder_30b__c2",
    "gpt-oss:20b": "gpt-oss_20b__c2",
    "opencoder:8b-instruct-q4_K_M": "opencoder_8b-instruct-q4_K_M__c2",
    "granite-code:8b-instruct-128k-q4_1": "granite-code_8b-instruct-128k-q4_1__c2",
    "llama3.1:8b-instruct-q4_K_M": "llama3.1_8b-instruct-q4_K_M__c2",
    "Mistral-Small-24B-Instruct-2501":  # matches MODEL_RUNS's key for this model, not its raw hf.co/ tag
        "hf.co_lmstudio-community_Mistral-Small-24B-Instruct-2501-GGUF_Q8_0__c2",
    "phi4:14b-q4_K_M": "phi4_14b-q4_K_M__c2",
    "gpt-4o": "gpt-4o__c2",
}
def iter_key(model):
    """Condition key of a model's iterative-loop run (primary 8 vs. later follow-up runs)."""
    return (model, "iterative") if model in C2_MODEL_DIRS else (model, "iterative_followup")


PART2_MODELS = {"qwen3": "Qwen3-Coder-30B", "gpt4o": "GPT-4o"}
PART2_RUNS = {"a": "ab_dev_20261012_v1", "b": "ab_dev_20261012_v1",
              "c": "cd_dev_20261014_v1", "d": "cd_dev_20261014_v1"}
REPS = (1, 2, 3)


def load_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


# ------------------------------------------------------------------------------------------------
# Part I: per-model rows
# ------------------------------------------------------------------------------------------------

def model_rows(cases):
    rows = {}
    for model, (subdir, model_dir) in MODEL_RUNS.items():
        for condition in ("raw", "autogrep"):
            rows[(model, condition)] = table_row(model, subdir, model_dir, condition, cases)
    for model, c2_dir in C2_MODEL_DIRS.items():
        r = multiagent_table_row(model, "runs_c2_primary", c2_dir, cases)
        r["n_accepted"] = round(r["acceptance_coverage"] * r["n_requested"])
        rows[(model, "iterative")] = r
    for model, c2_dir in C2_FOLLOWUP_MODEL_DIRS.items():
        r = multiagent_table_row(model, "runs_c2_followup", c2_dir, cases)
        r["n_accepted"] = round(r["acceptance_coverage"] * r["n_requested"])
        rows[(model, "iterative_followup")] = r
    return rows


# ------------------------------------------------------------------------------------------------
# Part I: one common, location-aware visible gate for every workflow
# ------------------------------------------------------------------------------------------------
# The workflows were run with different acceptance gates:
#   - raw: run_generation.py sets semgrep_valid only if original_vulnerable is a location-correct TP
#     and original_patched is TN (location-aware);
#   - autogrep and the iterative loop: autogrep/rule_validator.validate_rule (any finding on the
#     vulnerable file, none on the patched file -- location-blind).
# Comparing conditional metrics across these gates mixes two definitions of "accepted". The paper
# therefore re-applies the stricter, location-aware gate to every workflow (post hoc, no re-run):
# a case counts as accepted only if the workflow accepted it AND its visible pair is location-correct.
# Complete success (ESR) already required this, so ESR is identical under both gates (self-checked).

def _location_correct(samples):
    by_type = {s["sample_type"]: s for s in samples}
    vuln, patched = by_type.get("original_vulnerable"), by_type.get("original_patched")
    return bool(vuln and patched and vuln["outcome"] == "TP" and patched["outcome"] == "TN")


def _common_gate(accepted_by_case, by_case, cases):
    out = {}
    for cid in cases:
        own = bool(accepted_by_case.get(cid, False))
        samples = gated_samples(cid, own, by_case) if own else []
        ok = own and _location_correct(samples)
        samples = samples if ok else []
        out[cid] = {"own_gate": own, "accepted": ok, "samples": samples,
                    "esr": S22._esr_from_samples(samples, ok)}
    return out


def _load_condition(subdir, model_dir, condition, cases):
    gen = load_jsonl(RESULTS / subdir / model_dir / "generation_log.jsonl")
    smp = load_jsonl(RESULTS_CORRECTED / subdir / model_dir / "sample_execution_log.jsonl")
    accepted = {g["case_id"]: bool(g["yaml_valid"] and g["semgrep_valid"]) for g in gen if g["condition"] == condition}
    by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == condition:
            by_case[s["case_id"]].append(s)
    return _common_gate(accepted, by_case, cases)


def _load_iterative(run_subdir, c2_dir, cases):
    ep = load_jsonl(RESULTS / run_subdir / c2_dir / "c2_episode_log.jsonl")
    smp = load_jsonl(RESULTS_CORRECTED / run_subdir / c2_dir / "sample_execution_log.jsonl")
    by_case = defaultdict(list)
    for s in smp:
        by_case[s["case_id"]].append(s)
    return _common_gate({e["case_id"]: bool(e["accepted"]) for e in ep}, by_case, cases)


def _row_from_cases(data):
    n = len(data)
    accepted = sum(v["accepted"] for v in data.values())
    own = sum(v["own_gate"] for v in data.values())
    samples = [s for v in data.values() for s in v["samples"]]
    # Supervisor review 2026-10-20 (Issue 8, sub-issue 2): conditional_mcc pools all 6 sample types,
    # including original_vulnerable/original_patched -- which are guaranteed correct for every
    # accepted case by construction of the acceptance gate itself. hidden_only_mcc restricts the
    # same confusion-matrix computation to the 4 samples whose outcome is NOT guaranteed by
    # acceptance (the two hidden vulnerable variants, the alternative fix, the benign look-alike),
    # so the metric measures genuine generalization rather than partly measuring the acceptance
    # gate's own definition. Computed with the same confusion_from_samples/mcc functions, same
    # pooling convention, only the input sample set differs.
    hidden_samples = [s for s in samples if s["sample_type"] not in ("original_vulnerable", "original_patched")]
    hidden_tp = sum(1 for s in samples if s["sample_type"].startswith("variant_vulnerable") and s["outcome"] == "TP")
    esr = sum(v["esr"] for v in data.values())
    return {"n_requested": n, "n_accepted": accepted, "n_accepted_own_gate": own,
            "n_wrong_location_own_gate": own - accepted,
            "acceptance": accepted / n, "conditional_mcc": mcc(confusion_from_samples(samples)) if samples else None,
            "hidden_only_mcc": mcc(confusion_from_samples(hidden_samples)) if hidden_samples else None,
            "e2e_tp": hidden_tp, "e2e_total": 2 * n, "e2e_detection": hidden_tp / (2 * n),
            "esr_hits": esr, "esr": esr / n}


def common_gate_data(cases):
    data = {}
    for model, (subdir, model_dir) in MODEL_RUNS.items():
        for condition in ("raw", "autogrep"):
            data[(model, condition)] = _load_condition(subdir, model_dir, condition, cases)
    for model, c2_dir in C2_MODEL_DIRS.items():
        data[(model, "iterative")] = _load_iterative("runs_c2_primary", c2_dir, cases)
    for model, c2_dir in C2_FOLLOWUP_MODEL_DIRS.items():
        data[(model, "iterative_followup")] = _load_iterative("runs_c2_followup", c2_dir, cases)
    return data


# ------------------------------------------------------------------------------------------------
# Part I: significance (raw vs autogrep for all 15 open-weight; raw vs iterative for the 8)
# ------------------------------------------------------------------------------------------------

def _load_condition_own_gate(subdir, model_dir, condition, cases):
    """Each workflow's own gate -- used only to reproduce the published significance counts."""
    gen = load_jsonl(RESULTS / subdir / model_dir / "generation_log.jsonl")
    smp = load_jsonl(RESULTS_CORRECTED / subdir / model_dir / "sample_execution_log.jsonl")
    gen_c = {g["case_id"]: g for g in gen if g["condition"] == condition}
    by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == condition:
            by_case[s["case_id"]].append(s)
    out = {}
    for cid, g in gen_c.items():
        if cid not in cases:
            continue
        executable = bool(g["yaml_valid"] and g["semgrep_valid"])
        samples = gated_samples(cid, executable, by_case)
        out[cid] = {"esr": S22._esr_from_samples(samples, executable), "samples": samples}
    return out


def significance(cases, common):
    manifest = load_manifest()
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    open_models = [m for m in MODEL_RUNS if m not in PROPRIETARY]

    def summarise(results):
        adj_esr = holm_correct([r["esr_boot_p"] for r in results.values()])
        adj_mcc = holm_correct([r["mcc_boot_p"] for r in results.values()])
        per_model = {}
        for (m, r), pe, pm in zip(results.items(), adj_esr, adj_mcc):
            per_model[m] = {k: r[k] for k in ("n_common", "esr_a", "esr_b", "esr_diff", "esr_ci", "esr_boot_p",
                                              "mcc_a", "mcc_b", "mcc_diff", "mcc_ci", "mcc_boot_p")}
            per_model[m]["esr_holm_p"] = pe
            per_model[m]["mcc_holm_p"] = pm
        return {
            "per_model": per_model,
            "n_models": len(results),
            "esr_significant": sum(p < 0.05 for p in adj_esr),
            "mcc_significant": sum(p < 0.05 for p in adj_mcc),
            "mcc_a_higher": sum(r["mcc_a"] > r["mcc_b"] for r in results.values()),
        }

    def compare(a, b, label):
        return S22.paired_comparison_corrected(f"{label} a", a, f"{label} b", b, case_to_repo)

    # Paper: common location-aware gate.
    raw_vs_autogrep = {m: compare(common[(m, "raw")], common[(m, "autogrep")], m) for m in open_models}
    raw_vs_iterative = {m: compare(common[(m, "raw")], common[(m, "iterative")], m) for m in C2_MODEL_DIRS}
    # All 15 open-weight models (primary-8 "iterative" + follow-up "iterative_followup"). For the
    # follow-up models the iterative runs were made later than their single-shot runs, and their first
    # attempts differ for some cases (see first_attempt_agreement), so this comparison mixes the
    # workflow effect with run-to-run variation for those models.
    raw_vs_iterative_all = {m: compare(common[(m, "raw")], common[iter_key(m)], m) for m in open_models}

    # Reconciliation only: each workflow's own gate, original 8 models (must reproduce 0/8 and 2/8).
    own8 = {}
    for m, model_dir in PRIMARY_MODEL_DIRS.items():
        a = _load_condition_own_gate("runs_phase5_primary", model_dir, "raw", cases)
        b = _load_condition_own_gate("runs_phase5_primary", model_dir, "autogrep", cases)
        own8[m] = compare(a, b, m)

    return {
        "raw_vs_autogrep_all15": summarise(raw_vs_autogrep),
        "raw_vs_iterative_8": summarise(raw_vs_iterative),
        "raw_vs_iterative_all15": summarise(raw_vs_iterative_all),
        "own_gate_raw_vs_autogrep_original8": summarise(own8),
    }


# ------------------------------------------------------------------------------------------------
# Part I: paired case-level view for named model-vs-model "equal/indistinguishable count" claims
# ------------------------------------------------------------------------------------------------
# Supervisor review 2026-10-20 (Issue 8, sub-issue 4): an equal or statistically-indistinguishable
# complete-success COUNT between two models says nothing about whether it is the SAME cases
# succeeding. Reuses paired_comparison_corrected()'s own mcnemar_b/mcnemar_c fields (already
# computed for every raw-vs-autogrep/raw-vs-iterative comparison above) for the two specific
# cross-model pairs the manuscript already names in prose (04-results.tex), rather than building new
# bootstrap machinery -- same function, different pair of inputs. Condition is "autogrep", matching
# where both cited counts (7 vs 7, 9 vs 7) are actually reported in Table~\ref{tab:results}.

MODEL_CAPABILITY_PAIRS = {
    "qwen_7b_vs_32b": ("qwen2.5-coder:7b-instruct", "qwen2.5-coder:32b"),
    "deephat_vs_qwen_instruct": ("DeepHat-V1-7B", "qwen2.5-coder:7b-instruct"),
}


def success_rate_ci(model, condition, cases, common):
    """Supervisor review 2026-10-20 (Issue 8, sub-issue 3): a 95% CI around a single model's own
    complete-success (ESR) point estimate, scoped to the primary outcome only per the user's
    explicit choice -- not every metric in the main table. Reuses
    S22.repo_aware_bootstrap_single with the same repo-aware resampling as every other interval
    in this script."""
    manifest = load_manifest()
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    data = common[(model, condition)]

    def esr_fn(cids):
        return sum(data[c]["esr"] for c in cids) / len(cids) if cids else 0.0

    point, lo, hi = S22.repo_aware_bootstrap_single(cases, case_to_repo, esr_fn)
    return {"point": point, "ci_lo": lo, "ci_hi": hi}


def model_capability_overlap(cases):
    manifest = load_manifest()
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    out = {}
    for key, (model_a, model_b) in MODEL_CAPABILITY_PAIRS.items():
        a = _load_condition_own_gate("runs_phase5_primary", PRIMARY_MODEL_DIRS[model_a], "autogrep", cases)
        b = _load_condition_own_gate("runs_phase5_primary", PRIMARY_MODEL_DIRS[model_b], "autogrep", cases)
        r = S22.paired_comparison_corrected(model_a, a, model_b, b, case_to_repo)
        out[key] = {"model_a": model_a, "model_b": model_b, "n_common": r["n_common"],
                    "esr_a": r["esr_a"], "esr_b": r["esr_b"],
                    "a_only": r["mcnemar_b"], "b_only": r["mcnemar_c"],
                    "both": round(r["esr_a"] * r["n_common"]) - r["mcnemar_b"]}
    return out


# ------------------------------------------------------------------------------------------------
# Part I: first-attempt failure funnel (raw condition)
# ------------------------------------------------------------------------------------------------

FUNNEL_STAGES = ("requested", "yaml_parses", "semgrep_loads", "visibly_accepted",
                 "visible_pair_location_correct", "both_hidden_variants_detected", "complete_success")


def funnel_for_model(subdir, model_dir, cases):
    gen = {g["case_id"]: g for g in load_jsonl(RESULTS / subdir / model_dir / "generation_log.jsonl")
           if g["condition"] == "raw"}
    smp = load_jsonl(RESULTS_CORRECTED / subdir / model_dir / "sample_execution_log.jsonl")
    by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == "raw":
            by_case[s["case_id"]].append(s)

    counts = dict.fromkeys(FUNNEL_STAGES, 0)
    for cid in cases:
        counts["requested"] += 1
        g = gen.get(cid)
        if g is None or not g["yaml_valid"]:
            continue
        counts["yaml_parses"] += 1
        if is_semgrep_parse_error(g.get("validation_error")):
            continue
        counts["semgrep_loads"] += 1
        if not g["semgrep_valid"]:
            continue
        counts["visibly_accepted"] += 1
        samples = gated_samples(cid, True, by_case)
        by_type = {s["sample_type"]: s for s in samples}
        vuln, patched = by_type.get("original_vulnerable"), by_type.get("original_patched")
        if not (vuln and patched and vuln["outcome"] == "TP" and patched["outcome"] == "TN"):
            continue
        counts["visible_pair_location_correct"] += 1
        variants = [s for s in samples if s["sample_type"].startswith("variant_vulnerable")]
        if not (variants and all(v["outcome"] == "TP" for v in variants)):
            continue
        counts["both_hidden_variants_detected"] += 1
        if any(s["label"] == "negative" and s["outcome"] == "FP" for s in samples):
            continue
        counts["complete_success"] += 1
    return counts


def failure_funnel(cases, rows):
    per_model = {}
    for model, (subdir, model_dir) in MODEL_RUNS.items():
        counts = funnel_for_model(subdir, model_dir, cases)
        expected = rows[(model, "raw")]["esr_hits"]
        if counts["complete_success"] != expected:
            raise SystemExit(f"Funnel self-check failed for {model}: {counts['complete_success']} != {expected}")
        if counts["visibly_accepted"] != rows[(model, "raw")]["n_accepted"]:
            raise SystemExit(f"Funnel acceptance self-check failed for {model}")
        per_model[model] = counts
    pooled_open = {st: sum(c[st] for m, c in per_model.items() if m not in PROPRIETARY) for st in FUNNEL_STAGES}
    return {"stages": FUNNEL_STAGES, "per_model": per_model, "pooled_open_weight": pooled_open}


# ------------------------------------------------------------------------------------------------
# Part II: 2x2 pilot, paired per-case analysis
# ------------------------------------------------------------------------------------------------

def part2_run_dir(model_key, cell, rep):
    return PART2_DIR / f"{PART2_RUNS[cell]}_{model_key}_r{rep}_{cell}"


def part2():
    out = {}
    for model_key, model_name in PART2_MODELS.items():
        per_cell = {}
        probe_eligible = set()
        for cell in "abcd":
            per_case = defaultdict(lambda: {"raw": [], "iterative": []})
            resources = defaultdict(list)
            for rep in REPS:
                run = part2_run_dir(model_key, cell, rep)
                summary = json.loads((run / "summary.json").read_text())
                episodes = sorted(run.glob("CASE-*/episode.json"))
                if len(episodes) != summary["requested_cases"]:
                    raise SystemExit(f"{run.name}: {len(episodes)} episodes, summary says {summary['requested_cases']}")
                totals = {"raw": 0, "iterative": 0}
                calls = in_tok = out_tok = 0
                for ep_path in episodes:
                    ep = json.loads(ep_path.read_text())
                    for cond in ("raw", "iterative"):
                        # None = no final evaluation (iterative: budget exhausted without an accepted
                        # rule) -- a failure on the all-requested denominator, as in summary.json.
                        ok = bool(ep[cond] and ep[cond]["complete_success"])
                        per_case[ep["case_id"]][cond].append(int(ok))
                        totals[cond] += ok
                    if ep.get("probe_eligible"):
                        probe_eligible.add(ep["case_id"])
                    calls += ep.get("calls_recorded") or 0
                    in_tok += ep.get("input_tokens") or 0
                    out_tok += ep.get("output_tokens") or 0
                for cond in ("raw", "iterative"):
                    if totals[cond] != summary["conditions"][cond]["complete_success"]:
                        raise SystemExit(f"{run.name}/{cond}: episodes sum {totals[cond]} != summary "
                                         f"{summary['conditions'][cond]['complete_success']}")
                resources["calls"].append(calls)
                resources["input_tokens"].append(in_tok)
                resources["output_tokens"].append(out_tok)
                if "development_probes" in summary:
                    resources["probe_scans"].append(summary["development_probes"]["resources"]["probe_scans"])
                    resources["fallback_accepted"].append(summary["development_probes"]["fallback_accepted"])
            per_cell[cell] = {
                "per_case_mean": {cid: {c: mean(v[c]) for c in v} for cid, v in per_case.items()},
                "per_rep_iterative": [sum(per_case[cid]["iterative"][i] for cid in per_case) for i in range(len(REPS))],
                "per_rep_raw": [sum(per_case[cid]["raw"][i] for cid in per_case) for i in range(len(REPS))],
                "resources_per_rep": dict(resources),
            }
            per_cell[cell]["mean_iterative"] = mean(per_cell[cell]["per_rep_iterative"])
            per_cell[cell]["mean_raw"] = mean(per_cell[cell]["per_rep_raw"])

        def paired(x, y, subset=None):
            mx, my = per_cell[x]["per_case_mean"], per_cell[y]["per_case_mean"]
            ids = sorted(set(mx) & set(my) if subset is None else set(mx) & set(my) & subset)
            diffs = {cid: mx[cid]["iterative"] - my[cid]["iterative"] for cid in ids}
            return {"n_cases": len(ids), "mean_count_difference": sum(diffs.values()),
                    "cases_gained": sorted(c for c, d in diffs.items() if d > 0),
                    "cases_lost": sorted(c for c, d in diffs.items() if d < 0)}

        comparisons = {}
        for x, y in (("b", "a"), ("c", "a"), ("d", "b"), ("d", "a"), ("d", "c")):
            comparisons[f"{x}_minus_{y}"] = {"all": paired(x, y),
                                             "probe_eligible": paired(x, y, probe_eligible)}
        out[model_name] = {"cells": per_cell, "comparisons": comparisons,
                           "probe_eligible_cases": sorted(probe_eligible)}
    return out



# ------------------------------------------------------------------------------------------------
# Part I: where accepted rules fail on the hidden samples (common gate)
# ------------------------------------------------------------------------------------------------
# variant_vulnerable_1 = renamed, variant_vulnerable_2 = restructured, variant_safe = alternative fix,
# benign_lookalike = benign look-alike (benchmark/transformation_manifest_final.jsonl, all 300 cases).

HIDDEN_TYPES = {"variant_vulnerable_1": "renamed", "variant_vulnerable_2": "restructured",
                "variant_safe": "alternative_fix", "benign_lookalike": "benign_lookalike"}


def hidden_breakdown(common):
    out = {}
    families = {"raw": [m for m in MODEL_RUNS if m not in PROPRIETARY],
                "autogrep": [m for m in MODEL_RUNS if m not in PROPRIETARY],
                "iterative": list(C2_MODEL_DIRS)}
    for cond, models in families.items():
        c = defaultdict(int)
        for m in models:
            for cid, v in common[(m, cond)].items():
                if not v["accepted"]:
                    continue
                c["accepted"] += 1
                by_type = {s["sample_type"]: s for s in v["samples"]}
                ok = {}
                for st, name in HIDDEN_TYPES.items():
                    s = by_type.get(st)
                    good = bool(s) and s["outcome"] in ("TP", "TN")
                    ok[name] = good
                    c[f"{name}_correct"] += good
                pos_ok = ok["renamed"] and ok["restructured"]
                neg_ok = ok["alternative_fix"] and ok["benign_lookalike"]
                c["both_positive_ok"] += pos_ok
                c["both_negative_ok"] += neg_ok
                c["fail_positive_only"] += (not pos_ok) and neg_ok
                c["fail_negative_only"] += pos_ok and (not neg_ok)
                c["fail_both"] += (not pos_ok) and (not neg_ok)
                c["complete"] += pos_ok and neg_ok
        out[cond] = dict(c)
    return out



# ------------------------------------------------------------------------------------------------
# Threats: overlap with a publicly distributed rule corpus (Autogrep's own 645 example rules)
# ------------------------------------------------------------------------------------------------

def public_rule_overlap(cases, common):
    import re
    shas = set()
    for f in (ROOT / "autogrep" / "filtered_rules").rglob("*"):
        if f.is_file():
            shas.update(re.findall(r"source-url:\s*\S*/commit/([0-9a-f]{40})", f.read_text(errors="ignore")))
    manifest = load_dataset_manifest()
    overlap_all = sorted(c for c, r in manifest.items()
                         if r.get("fixed_commit") in shas or r.get("vulnerable_commit") in shas)
    overlap = [c for c in overlap_all if c in cases]
    rest = [c for c in cases if c not in overlap]
    out = {"corpus_rules_with_sha": len(shas), "overlap_dataset": overlap_all, "overlap_eligible": overlap}
    for cond in ("raw", "autogrep"):
        models = [m for m in MODEL_RUNS if m not in PROPRIETARY]
        def rate(ids):
            hits = sum(common[(m, cond)][c]["esr"] for m in models for c in ids)
            return hits, len(ids) * len(models)
        h1, n1 = rate(overlap)
        h2, n2 = rate(rest)
        out[cond] = {"overlap_hits": h1, "overlap_n": n1, "rest_hits": h2, "rest_n": n2}
    return out


# ------------------------------------------------------------------------------------------------
# Run-to-run agreement: the iterative loop's first call vs the earlier single-shot run
# ------------------------------------------------------------------------------------------------
# Both start from the same prompt at temperature 0. Under the same (legacy) validator, the cases the
# iterative loop accepts on its first call should equal the cases whose single-shot rule passes the
# legacy check -- if the model returned the same first answer in both runs.

def first_attempt_agreement(cases):
    out = {}
    for m in MODEL_RUNS:
        if m in C2_MODEL_DIRS:
            isub, idir = "runs_c2_primary", C2_MODEL_DIRS[m]
        elif m in C2_FOLLOWUP_MODEL_DIRS:
            isub, idir = "runs_c2_followup", C2_FOLLOWUP_MODEL_DIRS[m]
        else:
            continue
        sub, d = MODEL_RUNS[m]
        by = defaultdict(dict)
        for line in (RESULTS_CORRECTED / sub / d / "sample_execution_log.jsonl").read_text().splitlines():
            r = json.loads(line)
            if r["condition"] == "raw":
                by[r["case_id"]][r["sample_type"]] = r
        single = {c for c, v in by.items() if c in cases and v.get("original_vulnerable", {}).get("detected")
                  and not v.get("original_patched", {}).get("detected", True)}
        first = {e["case_id"] for e in load_jsonl(RESULTS / isub / idir / "c2_episode_log.jsonl")
                 if e["case_id"] in cases and str(e["accepted"]) == "True" and str(e["calls_used"]) == "1"}
        out[m] = {"group": "primary" if m in C2_MODEL_DIRS else "followup",
                  "single": len(single), "first_call": len(first), "discordant": len(single ^ first)}
    return out


def scored_hidden_detections(cases):
    """Hidden-variant detections of every scored rule in scope (15 open-weight models, all three
    Part I workflows, 150 cases): any finding in the variant file vs a finding on the annotated
    vulnerable lines. Replaces the study-wide 879/4,063 figure from Paper_Draft_Notes.md Sec. 5."""
    det = wrong = 0
    paths = []
    for m in MODEL_RUNS:
        if m in PROPRIETARY:
            continue
        sub, d = MODEL_RUNS[m]
        paths.append((RESULTS_CORRECTED / sub / d / "sample_execution_log.jsonl", ("raw", "autogrep")))
        isub, idir = (("runs_c2_primary", C2_MODEL_DIRS[m]) if m in C2_MODEL_DIRS
                      else ("runs_c2_followup", C2_FOLLOWUP_MODEL_DIRS[m]))
        paths.append((RESULTS_CORRECTED / isub / idir / "sample_execution_log.jsonl", None))
    for path, conds in paths:
        for line in path.read_text().splitlines():
            r = json.loads(line)
            if r["case_id"] not in cases or (conds and r.get("condition") not in conds):
                continue
            if r["sample_type"].startswith("variant_vulnerable") and r.get("detected"):
                det += 1
                wrong += not r.get("finding_location_correct")
    return {"det": det, "wrong": wrong}

# ------------------------------------------------------------------------------------------------
# LaTeX tables
# ------------------------------------------------------------------------------------------------

DISPLAY = {  # paper-facing name, nominal size
    "qwen2.5-coder:7b-instruct": ("Qwen2.5-Coder-Instruct", "7B"),
    "qwen2.5-coder:32b": ("Qwen2.5-Coder", "32B"),
    "DeepHat-V1-7B": ("DeepHat-V1", "7B"),
    "deepseek-coder:6.7b": ("DeepSeek-Coder", "6.7B"),
    "codegemma:7b": ("CodeGemma", "7B"),
    "magicoder:7b": ("Magicoder", "7B"),
    "yi-coder:9b": ("Yi-Coder", "9B"),
    "codellama:7b-instruct-fp16": ("CodeLlama-Instruct", "7B"),
    "qwen3-coder:30b": ("Qwen3-Coder", "30B"),
    "gpt-oss:20b": ("gpt-oss", "20B"),
    "opencoder:8b-instruct-q4_K_M": ("OpenCoder-Instruct", "8B"),
    "granite-code:8b-instruct-128k-q4_1": ("Granite-Code-Instruct", "8B"),
    "llama3.1:8b-instruct-q4_K_M": ("Llama-3.1-Instruct", "8B"),
    "Mistral-Small-24B-Instruct-2501": ("Mistral-Small-Instruct", "24B"),
    "phi4:14b-q4_K_M": ("Phi-4", "14B"),
    "gpt-4o": ("GPT-4o (reference)", "--"),
}


def _cell_pct(r, key):
    return f"{100 * r[key]:.1f}"


def write_tables(table_dir, crow, p2):
    table_dir = Path(table_dir)
    table_dir.mkdir(parents=True, exist_ok=True)

    # Follow-up 7 models + gpt-4o, C2 iterative loop -- kept as its own table, not merged into the
    # primary-8 iterative column, per C2_FOLLOWUP_MODEL_DIRS's separation rationale.
    lines = ["% Generated by pipeline/paper_results.py -- do not edit by hand.",
             "% C2 iterative loop, follow-up 7 models + gpt-4o; common location-aware gate; sorted by"
             " complete success (ESR)."]
    fu_order = sorted(C2_FOLLOWUP_MODEL_DIRS, key=lambda m: -crow[(m, "iterative_followup")]["esr_hits"])
    for m in fu_order:
        name, size = DISPLAY[m]
        r = crow[(m, "iterative_followup")]
        mcc_s = f"{r['conditional_mcc']:.2f}" if r["conditional_mcc"] is not None else "--"
        lines.append(f"{name} & {size} & {_cell_pct(r, 'acceptance')} & {mcc_s} & "
                      f"{_cell_pct(r, 'e2e_detection')} & {r['esr_hits']} \\\\")
    (table_dir / "tab-followup-iterative-rows.tex").write_text("\n".join(lines) + "\n")

    open_models = [m for m in MODEL_RUNS if m not in PROPRIETARY]
    order = sorted(open_models, key=lambda m: (-crow[(m, "autogrep")]["esr_hits"],
                                               -crow[(m, "autogrep")]["n_accepted"], m))
    lines = ["% Generated by pipeline/paper_results.py -- do not edit by hand.",
             "% Common location-aware gate; 150 eligible cases; rows sorted by Autogrep complete success."]
    def row(m):
        name, size = DISPLAY[m]
        ss, ag = crow[(m, "raw")], crow[(m, "autogrep")]
        it = crow.get(iter_key(m))
        # Supervisor review 2026-10-20 (Issue 5): this was `m not in C2_MODEL_DIRS` -- marking only
        # the 8 follow-up/gpt-4o rows, on the theory that only those models' iterative runs were
        # "added later." Checking the real run_id timestamps for every model shows the gap applies
        # universally: the original 8 primary models' own C2 runs also happened 2-3 days after their
        # raw/autogrep runs (e.g. qwen2.5-coder:7b-instruct 2026-09-28 -> 2026-10-01), not the same
        # session -- just a smaller gap than the follow-up-8/gpt-4o's ~6-7 days. The disclosure needs
        # to cover all 16 models, not 8; see the caption text in 04-results.tex for the corresponding
        # wording ("several days to about a week").
        later = True  # applies to every model; see comment above and Supervisor_Review_20261018.md
        mcc_s = f"{ag['conditional_mcc']:.2f}" if ag["conditional_mcc"] is not None else "--"
        # Supervisor review 2026-10-20 (Issue 8, sub-issue 2): hidden-only MCC, next to the existing
        # pooled MCC column -- see _row_from_cases()'s comment for why the two differ.
        hidden_mcc_s = f"{ag['hidden_only_mcc']:.2f}" if ag["hidden_only_mcc"] is not None else "--"
        it_acc = _cell_pct(it, "acceptance") if it else "--"
        it_succ = (str(it["esr_hits"]) + ("$^\\dagger$" if later else "")) if it else "--"
        return (f"{name} & {size} & {_cell_pct(ss, 'acceptance')} & {ss['esr_hits']} & "
                f"{_cell_pct(ag, 'acceptance')} & {mcc_s} & {hidden_mcc_s} & {_cell_pct(ag, 'e2e_detection')} & {ag['esr_hits']} & "
                f"{it_acc} & {it_succ} \\\\")
    lines += [row(m) for m in order]
    lines.append("\\midrule")
    lines.append(row("gpt-4o"))
    (table_dir / "tab-results-rows.tex").write_text("\n".join(lines) + "\n")

    # Data for the per-model gap figure (figures/fig-gap.tex): Autogrep loop, common gate,
    # open-weight models sorted by acceptance, GPT-4o last. Values in percent.
    gap_order = sorted(open_models, key=lambda m: (-crow[(m, "autogrep")]["acceptance"],
                                                   -crow[(m, "autogrep")]["esr"], m))
    lines = ["% Generated by pipeline/paper_results.py -- do not edit by hand.",
             "% \\gaprow{row}{model}{acceptance %}{complete success %}; Autogrep loop, common gate."]
    for i, m in enumerate(gap_order):
        r = crow[(m, "autogrep")]
        lines.append(f"\\gaprow{{{i}}}{{{DISPLAY[m][0]}}}{{{100 * r['acceptance']:.1f}}}{{{100 * r['esr']:.1f}}}")
    r = crow[("gpt-4o", "autogrep")]
    lines.append(f"\\gaprow{{{len(gap_order) + 0.6:g}}}{{GPT-4o (reference)}}{{{100 * r['acceptance']:.1f}}}{{{100 * r['esr']:.1f}}}")
    (table_dir / "fig-gap-rows.tex").write_text("\n".join(lines) + "\n")

    q, g = p2["Qwen3-Coder-30B"], p2["GPT-4o"]
    labels = {"a": ("A", "YAML", "pair"), "b": ("B", "typed", "pair"),
              "c": ("C", "YAML", "+probes"), "d": ("D", "typed", "+probes")}
    lines = ["% Generated by pipeline/paper_results.py -- do not edit by hand.",
             "% Complete successes out of 24 after the repair loop; per-repetition values and mean;",
             "% mean generation calls per repetition."]
    for c in "abcd":
        letter, cons, fb = labels[c]
        def fmt(d):
            cell = d["cells"][c]
            reps = "/".join(str(x) for x in cell["per_rep_iterative"])
            calls = mean(cell["resources_per_rep"]["calls"])
            return f"{reps} & {cell['mean_iterative']:.1f} & {calls:.0f}"
        lines.append(f"{letter} & {cons} & {fb} & {fmt(q)} & {fmt(g)} \\\\")
    (table_dir / "tab-part2-rows.tex").write_text("\n".join(lines) + "\n")


# ------------------------------------------------------------------------------------------------
# LaTeX macros
# ------------------------------------------------------------------------------------------------

def pct(x, digits=1):
    return f"{100 * x:.{digits}f}"


def write_tex(path, cases, crow, sig, funnel, p2, hb, contam, agree, scored, overlap, success_ci):
    """All Part I macros use the common location-aware gate (crow)."""
    open_models = [m for m in MODEL_RUNS if m not in PROPRIETARY]
    part1 = {k: r for k, r in crow.items() if k[0] not in PROPRIETARY}
    ratios = [r["esr_hits"] / r["n_accepted"] for r in part1.values() if r["n_accepted"]]
    mccs = [r["conditional_mcc"] for r in part1.values() if r["conditional_mcc"] is not None]
    hidden_mccs = [r["hidden_only_mcc"] for r in part1.values() if r["hidden_only_mcc"] is not None]
    auto_own = sum(part1[(m, "autogrep")]["n_accepted_own_gate"] for m in open_models)
    auto_wrong = sum(part1[(m, "autogrep")]["n_wrong_location_own_gate"] for m in open_models)
    feedback_up = sum(part1[(m, "autogrep")]["n_accepted"] > part1[(m, "raw")]["n_accepted"] for m in open_models)
    manifest = load_dataset_manifest()
    pooled = funnel["pooled_open_weight"]
    q, g = p2["Qwen3-Coder-30B"]["cells"], p2["GPT-4o"]["cells"]

    macros = {
        "NumCases": len(manifest),
        "NumRepos": len({r["repository"] for r in manifest.values()}),
        "NumEligible": len(cases),
        "NumOpenModels": len(open_models),
        "NumIterModels": len(C2_MODEL_DIRS),
        "AcceptMin": pct(min(r["acceptance"] for r in part1.values())),
        "AcceptMax": pct(max(r["acceptance"] for r in part1.values())),
        "CondMCCMin": f"{min(mccs):.2f}",
        "CondMCCMax": f"{max(mccs):.2f}",
        "HiddenMCCMin": f"{min(hidden_mccs):.2f}",
        "HiddenMCCMax": f"{max(hidden_mccs):.2f}",
        "DetectMin": pct(min(r["e2e_detection"] for r in part1.values())),
        "DetectMax": pct(max(r["e2e_detection"] for r in part1.values())),
        "SuccessMax": pct(max(r["esr"] for r in part1.values())),
        "AcceptedPassMax": f"{100 * max(ratios):.0f}",
        "GPTFourAcceptAuto": pct(crow[("gpt-4o", "autogrep")]["acceptance"]),
        "GPTFourSuccessAuto": pct(crow[("gpt-4o", "autogrep")]["esr"]),
        "AutogrepOwnAccepted": auto_own,
        "AutogrepWrongLocation": auto_wrong,
        "AutogrepWrongLocationPct": pct(auto_wrong / auto_own),
        "FeedbackAcceptUp": feedback_up,
        "SigESRAutogrep": sig["raw_vs_autogrep_all15"]["esr_significant"],
        "SigMCCAutogrep": sig["raw_vs_autogrep_all15"]["mcc_significant"],
        "RawMCCHigherAutogrep": sig["raw_vs_autogrep_all15"]["mcc_a_higher"],
        "SigESRIterative": sig["raw_vs_iterative_8"]["esr_significant"],
        "SigESRIterativeAll": sig["raw_vs_iterative_all15"]["esr_significant"],
        "SigMCCIterativeAll": sig["raw_vs_iterative_all15"]["mcc_significant"],
        "IterAcceptUp": sum(crow[iter_key(m)]["n_accepted"] > crow[(m, "raw")]["n_accepted"] for m in open_models),
        "IterSameAsAutoPrimary": sum(crow[(m, "iterative")]["esr_hits"] == crow[(m, "autogrep")]["esr_hits"]
                                     for m in C2_MODEL_DIRS),
        "IterVsAutoMaxDiffFollowup": max(abs(crow[iter_key(m)]["esr_hits"] - crow[(m, "autogrep")]["esr_hits"])
                                         for m in open_models if m not in C2_MODEL_DIRS),
        "FirstDiscordantMaxPrimary": max(v["discordant"] for v in agree.values() if v["group"] == "primary"),
        "FirstDiscordantMaxFollowup": max(v["discordant"] for v in agree.values() if v["group"] == "followup"),
        "FirstDiscordantMaxFollowupModel": DISPLAY[max((m for m in agree if agree[m]["group"] == "followup"),
                                                       key=lambda m: agree[m]["discordant"])][0],
        "ScoredDetections": scored["det"], "ScoredDetWrong": scored["wrong"],
        "ScoredDetWrongPct": pct(scored["wrong"] / scored["det"]),
    }
    # models whose single-shot vs iterative complete-success difference is significant (Holm over 15)
    it_sig = [m for m, r in sig["raw_vs_iterative_all15"]["per_model"].items() if r["esr_holm_p"] < 0.05]
    if it_sig:
        m0 = it_sig[0]
        r0 = sig["raw_vs_iterative_all15"]["per_model"][m0]
        macros.update({
            "IterSigModel": DISPLAY[m0][0],
            "IterSigRawN": crow[(m0, "raw")]["esr_hits"], "IterSigIterN": crow[iter_key(m0)]["esr_hits"],
            "IterSigAutoN": crow[(m0, "autogrep")]["esr_hits"],
            "IterSigHolmP": f"{r0['esr_holm_p']:.3f}",
            "IterSigDiscordant": agree[m0]["discordant"],
        })
    macros.update({
        "SigMCCIterative": sig["raw_vs_iterative_8"]["mcc_significant"],
        "FunnelRequested": pooled["requested"],
        "FunnelYAMLPct": pct(pooled["yaml_parses"] / pooled["requested"]),
        "FunnelLoadsPct": pct(pooled["semgrep_loads"] / pooled["requested"]),
        "FunnelAcceptedPct": pct(pooled["visibly_accepted"] / pooled["requested"]),
        "FunnelHiddenPct": pct(pooled["both_hidden_variants_detected"] / pooled["requested"]),
        "FunnelSuccessPct": pct(pooled["complete_success"] / pooled["requested"]),
        "QwenA": f"{q['a']['mean_iterative']:.1f}", "QwenB": f"{q['b']['mean_iterative']:.1f}",
        "QwenC": f"{q['c']['mean_iterative']:.1f}", "QwenD": f"{q['d']['mean_iterative']:.1f}",
        "GPTA": f"{g['a']['mean_iterative']:.1f}", "GPTB": f"{g['b']['mean_iterative']:.1f}",
        "GPTC": f"{g['c']['mean_iterative']:.1f}", "GPTD": f"{g['d']['mean_iterative']:.1f}",
        "PartTwoCases": len(q["a"]["per_case_mean"]),
        "PartTwoProbeCases": len(p2["Qwen3-Coder-30B"]["probe_eligible_cases"]),
    })
    ag = hb["autogrep"]
    macros.update({
        "HidAccepted": ag["accepted"],
        "HidRenamedPct": pct(ag["renamed_correct"] / ag["accepted"]),
        "HidRestructuredPct": pct(ag["restructured_correct"] / ag["accepted"]),
        "HidAltFixPct": pct(ag["alternative_fix_correct"] / ag["accepted"]),
        "HidBenignPct": pct(ag["benign_lookalike_correct"] / ag["accepted"]),
        "HidFailPosOnlyPct": pct(ag["fail_positive_only"] / ag["accepted"]),
        "HidFailNegOnlyPct": pct(ag["fail_negative_only"] / ag["accepted"]),
        "HidFailBothPct": pct(ag["fail_both"] / ag["accepted"]),
        "HidCompletePct": pct(ag["complete"] / ag["accepted"]),
    })
    fu = {m: crow[(m, "iterative_followup")] for m in C2_FOLLOWUP_MODEL_DIRS}
    fu_esr = [r["esr"] for r in fu.values()]
    macros.update({
        "FollowupIterNumModels": len(fu),
        "FollowupIterSuccessMin": pct(min(fu_esr)),
        "FollowupIterSuccessMax": pct(max(fu_esr)),
        "FollowupIterSuccessMaxModel": DISPLAY[max(fu, key=lambda m: fu[m]["esr"])][0],
        "FollowupIterBeatsPrimaryBestN": sum(
            fu[m]["esr_hits"] > max(crow[(pm, "iterative")]["esr_hits"] for pm in C2_MODEL_DIRS) for m in fu
        ),
        "PrimaryIterSuccessMax": pct(max(crow[(pm, "iterative")]["esr"] for pm in C2_MODEL_DIRS)),
    })
    per = {m: c for m, c in funnel["per_model"].items() if m not in PROPRIETARY}
    yaml_rates = [c["yaml_parses"] / c["requested"] for c in per.values()]
    load_rates = [c["semgrep_loads"] / c["requested"] for c in per.values()]
    macros.update({
        "FunnelYAMLMinPct": pct(min(yaml_rates)), "FunnelYAMLMaxPct": pct(max(yaml_rates)),
        "FunnelLoadsMinPct": pct(min(load_rates)), "FunnelLoadsMaxPct": pct(max(load_rates)),
        "FunnelLoadsN": pooled["semgrep_loads"], "FunnelAcceptedN": pooled["visibly_accepted"],
        "FunnelYAMLN": pooled["yaml_parses"], "FunnelHiddenN": pooled["both_hidden_variants_detected"],
        "FunnelSuccessN": pooled["complete_success"],
        "FunnelLoadsRejectedPct": pct((pooled["semgrep_loads"] - pooled["visibly_accepted"]) / pooled["semgrep_loads"]),
    })
    gains = [part1[(m, "autogrep")]["esr_hits"] - part1[(m, "raw")]["esr_hits"] for m in open_models]
    yaml_sorted = sorted(yaml_rates)
    macros.update({
        "SuccRawTotal": hb["raw"]["complete"], "SuccAutoTotal": hb["autogrep"]["complete"],
        "MaxSuccGain": max(gains), "NumSuccLoss": sum(x < 0 for x in gains),
        "FunnelYAMLSecondMinPct": pct(yaml_sorted[1]),
    })
    def thousands(n):
        return f"{n:,}".replace(",", "{,}")
    for name, stage in (("Requested", "requested"), ("YAML", "yaml_parses"), ("Loads", "semgrep_loads"),
                        ("Accepted", "visibly_accepted"), ("Hidden", "both_hidden_variants_detected"),
                        ("Success", "complete_success")):
        macros[f"Funnel{name}Fmt"] = thousands(pooled[stage])
    ca = contam["autogrep"]
    macros.update({
        "OverlapDataset": len(contam["overlap_dataset"]), "OverlapEligible": len(contam["overlap_eligible"]),
        "OverlapSuccPct": pct(ca["overlap_hits"] / ca["overlap_n"]) if ca["overlap_n"] else "--",
        "RestSuccPct": pct(ca["rest_hits"] / ca["rest_n"]),
    })
    for key, d in (("Qwen", q), ("GPT", g)):
        for c in "abcd":
            macros[f"{key}Raw{c.upper()}"] = f"{d[c]['mean_raw']:.1f}"
            macros[f"{key}Calls{c.upper()}"] = f"{mean(d[c]['resources_per_rep']['calls']):.0f}"
    o1, o2 = overlap["qwen_7b_vs_32b"], overlap["deephat_vs_qwen_instruct"]
    # Self-check added 2026-10-20 during Phase 1 re-verification: 04-results.tex's prose says "each
    # model solving \QwenPairAOnly{} cases the other does not" -- citing ONE macro for BOTH
    # directions, relying on a_only == b_only (both happen to be 3 right now). If a future rerun
    # ever breaks that tie, the prose would silently become wrong while still compiling cleanly, since
    # QwenPairBOnly is defined but never actually read by the .tex text. Fail loudly instead, forcing
    # the prose to be revisited rather than letting an unchecked assumption go stale.
    if o1["a_only"] != o1["b_only"]:
        raise SystemExit(
            f"04-results.tex's Qwen-pair sentence assumes a_only == b_only (currently "
            f"{o1['a_only']} == {o1['b_only']}); it no longer holds ({o1['a_only']} != "
            f"{o1['b_only']}) -- rewrite that sentence to cite QwenPairAOnly and QwenPairBOnly "
            f"separately before regenerating.")
    macros.update({
        "QwenPairCommon": o1["both"], "QwenPairAOnly": o1["a_only"], "QwenPairBOnly": o1["b_only"],
        "DeepHatPairCommon": o2["both"], "DeepHatPairAOnly": o2["a_only"], "DeepHatPairBOnly": o2["b_only"],
    })
    bow, g4 = success_ci["best_open_weight"], success_ci["gpt4o"]
    macros.update({
        "SuccessMaxCILo": pct(bow["ci_lo"]), "SuccessMaxCIHi": pct(bow["ci_hi"]),
        "GPTFourSuccessCILo": pct(g4["ci_lo"]), "GPTFourSuccessCIHi": pct(g4["ci_hi"]),
    })
    lines = ["% Generated by pipeline/paper_results.py -- do not edit by hand.",
             f"% eligible_cases.py {ELIGIBLE_VERSION}; Part I under the common location-aware gate"]
    lines += [f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in macros.items()]
    Path(path).write_text("\n".join(lines) + "\n")
    return macros


# ------------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tex", help="also write LaTeX macros to this path")
    ap.add_argument("--tables", help="also write LaTeX table rows into this directory")
    args = ap.parse_args()

    cases = eligible_supported_cases()
    rows = model_rows(cases)                      # each workflow's own gate (published tables)
    common = common_gate_data(cases)
    crow = {k: _row_from_cases(v) for k, v in common.items()}
    for k, r in crow.items():
        if r["esr_hits"] != rows[k]["esr_hits"]:
            raise SystemExit(f"ESR self-check failed for {k}: {r['esr_hits']} != {rows[k]['esr_hits']}")
        if r["n_accepted_own_gate"] != rows[k]["n_accepted"]:
            raise SystemExit(f"Own-gate acceptance self-check failed for {k}")
    sig = significance(cases, common)

    o8 = sig["own_gate_raw_vs_autogrep_original8"]
    if (o8["esr_significant"], o8["mcc_significant"]) != (0, 2):
        raise SystemExit(f"Significance self-check failed: original 8 give {o8['esr_significant']}/8 ESR, "
                         f"{o8['mcc_significant']}/8 MCC; published values are 0/8 and 2/8")

    funnel = failure_funnel(cases, rows)
    p2 = part2()
    hb = hidden_breakdown(common)
    contam = public_rule_overlap(cases, common)
    agree = first_attempt_agreement(cases)
    scored = scored_hidden_detections(cases)
    overlap = model_capability_overlap(cases)
    # Primary-outcome CI (Issue 8, sub-issue 3): the best open-weight model under the condition
    # that achieves SuccessMax, and gpt-4o's matching autogrep value -- identified directly rather
    # than assumed, since \SuccessMax's own max() is over every (model, condition) pair.
    best_key = max((k for k in crow if k[0] not in PROPRIETARY), key=lambda k: crow[k]["esr"])
    success_ci = {
        "best_open_weight": {"model": best_key[0], "condition": best_key[1],
                              **success_rate_ci(best_key[0], best_key[1], cases, common)},
        "gpt4o": {"model": "gpt-4o", "condition": "autogrep",
                  **success_rate_ci("gpt-4o", "autogrep", cases, common)},
    }

    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "model_rows_common_gate.json").write_text(json.dumps(
        {f"{m}|{c}": r for (m, c), r in crow.items()}, indent=1))
    (OUT_DIR / "model_rows_own_gate.json").write_text(json.dumps(
        {f"{m}|{c}": r for (m, c), r in rows.items()}, indent=1))
    (OUT_DIR / "significance.json").write_text(json.dumps(sig, indent=1))
    (OUT_DIR / "failure_funnel.json").write_text(json.dumps(funnel, indent=1))
    (OUT_DIR / "part2_pilot.json").write_text(json.dumps(p2, indent=1))
    (OUT_DIR / "hidden_breakdown.json").write_text(json.dumps(hb, indent=1))
    (OUT_DIR / "public_rule_overlap.json").write_text(json.dumps(contam, indent=1))
    (OUT_DIR / "first_attempt_agreement.json").write_text(json.dumps(agree, indent=1))
    (OUT_DIR / "scored_hidden_detections.json").write_text(json.dumps(scored, indent=1))
    (OUT_DIR / "model_capability_overlap.json").write_text(json.dumps(overlap, indent=1))
    (OUT_DIR / "success_rate_ci.json").write_text(json.dumps(success_ci, indent=1))

    print(f"eligible_cases.py {ELIGIBLE_VERSION}: {len(cases)} cases; all self-checks passed")
    print("\nCommon location-aware gate (acc / ESR / cond-MCC); own-gate wrong-location rejects in brackets:")
    for (m, c), r in crow.items():
        cm = f"{r['conditional_mcc']:.3f}" if r["conditional_mcc"] is not None else "  n/a"
        print(f"  {m[:34]:34s} {c:9s} {r['n_accepted']:3d} / {r['esr_hits']:2d} / {cm}  "
              f"detect {100 * r['e2e_detection']:4.1f}%  [{r['n_wrong_location_own_gate']}]")
    for name in ("raw_vs_autogrep_all15", "raw_vs_iterative_8", "own_gate_raw_vs_autogrep_original8"):
        s = sig[name]
        print(f"{name}: ESR significant {s['esr_significant']}/{s['n_models']}, cond-MCC significant "
              f"{s['mcc_significant']}/{s['n_models']}, raw cond-MCC higher {s['mcc_a_higher']}/{s['n_models']}")
    print("\nC2 iterative loop, follow-up 7 models + gpt-4o (descriptive; kept separate from the "
          "audited primary-8, no significance testing run on this set):")
    for m in C2_FOLLOWUP_MODEL_DIRS:
        r = crow[(m, "iterative_followup")]
        cm = f"{r['conditional_mcc']:.3f}" if r["conditional_mcc"] is not None else "  n/a"
        print(f"  {m[:34]:34s} accepted {r['n_accepted']:3d}  complete-success(ESR) {r['esr_hits']:2d}  "
              f"cond-MCC {cm}  detect {100 * r['e2e_detection']:4.1f}%")
    print("\nFirst-attempt funnel (raw), pooled over 15 open-weight models:")
    pooled = funnel["pooled_open_weight"]
    for st in FUNNEL_STAGES:
        print(f"  {st:32s} {pooled[st]:5d}  {100 * pooled[st] / pooled['requested']:5.1f}%")
    print("\nPart II, mean complete successes of 24 (iterative / raw):")
    for model, d in p2.items():
        print(f"  {model}: " + "  ".join(f"{c.upper()} {d['cells'][c]['mean_iterative']:.2f}/{d['cells'][c]['mean_raw']:.2f}"
                                         for c in "abcd"))
        for k, v in d["comparisons"].items():
            a = v["all"]
            print(f"    {k}: diff {a['mean_count_difference']:+.2f} cases, gained {len(a['cases_gained'])}, "
                  f"lost {len(a['cases_lost'])}")
    print("\nHidden-sample breakdown among accepted rules (pooled):")
    for cond, c in hb.items():
        print(f"  {cond}: " + ", ".join(f"{k}={v}" for k, v in c.items()))
    print("\nPublic-rule overlap:", json.dumps(contam))
    print("\nModel-vs-model paired capability overlap (equal/indistinguishable count claims):")
    for key, r in overlap.items():
        print(f"  {key}: {r['model_a']} {r['esr_a']*r['n_common']:.0f} vs {r['model_b']} "
              f"{r['esr_b']*r['n_common']:.0f} -- common={r['both']} a_only={r['a_only']} b_only={r['b_only']}")
    print("\nPrimary-outcome (complete success) 95% CI:")
    for key, r in success_ci.items():
        print(f"  {key} ({r['model']}/{r['condition']}): {100*r['point']:.1f}% "
              f"[{100*r['ci_lo']:.1f}%, {100*r['ci_hi']:.1f}%]")
    if args.tables:
        write_tables(args.tables, crow, p2)
        print(f"wrote tables to {args.tables}")
    if args.tex:
        write_tex(args.tex, cases, crow, sig, funnel, p2, hb, contam, agree, scored, overlap, success_ci)
        print(f"\nwrote {args.tex}")


if __name__ == "__main__":
    main()
