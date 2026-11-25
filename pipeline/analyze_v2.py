"""
Run v2 analysis (Research_Log/Run_v2_Specification.md, section 10). Written and tested on simulated results BEFORE
the run; the run's results then go through it unchanged. Anything added after seeing results must be labelled
exploratory and kept out of this file.

Results layout (written by the run entrypoint):
  RUN_DIR/manifest.json                                   {"cases": [...], "part1_models": [...], ...}
  RUN_DIR/part1/<model_key>/episodes.jsonl                one run_v2_episode.Episode per case (to_dict())
  RUN_DIR/stability/rep<r>/<model_key>/episodes.jsonl     single-shot episodes at temperature 0.2
  RUN_DIR/part2/<cell>/rep<r>/<model_key>/episodes.jsonl  Part II episodes (cells A-D)

Definitions (fixed here, before the run):
  accepted          the workflow's attempts include one that passed the run v2 visible gate
  complete success  accepted, and that rule's six sample outcomes are all correct: TP on the three vulnerable
                    samples (location by the chosen method), TN on the three safe ones. Any ERROR outcome (scan not
                    "ok") is not correct.
  denominator       every requested case; a missing episode counts as not accepted and is reported
  hidden breakdown  over accepted rules: detection of the renamed and restructured variants, false positives on
                    the alternative fix and the look-alike; conditional MCC over these four hidden samples only
                    (ERROR counts as FN on a vulnerable sample, FP on a safe one)
  location methods  "overlap" (primary), "contained", "start_line" (v1) -- sensitivity only
  statistics        Wilson 95% intervals; repository-aware bootstrap (10,000 resamples, seed 42) for intervals on
                    rates and paired differences; exact McNemar on paired complete success; Holm across all
                    workflow comparisons. Part II: each case's success averaged over its repeats before pairing.

Usage: .venv/bin/python3 pipeline/analyze_v2.py RUN_DIR [--n-boot 10000]   -> RUN_DIR/analysis/*.json + summary.md
"""
import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_section22_corrected import repo_aware_bootstrap, repo_aware_bootstrap_single  # noqa: E402
from stats_section22 import holm_correct, mcnemar_exact  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
POSITIVE = ("original_vulnerable", "variant_vulnerable_1", "variant_vulnerable_2")
NEGATIVE = ("original_patched", "variant_safe", "benign_lookalike")
HIDDEN = ("variant_vulnerable_1", "variant_vulnerable_2", "variant_safe", "benign_lookalike")
PART1_WORKFLOWS = ("single_shot", "autogrep", "iterative")
PART1_PAIRS = (("single_shot", "autogrep"), ("autogrep", "iterative"), ("single_shot", "iterative"))
PART2_WORKFLOWS = ("single_shot", "autogrep")       # Part II: first attempt, and the 3-attempt repair loop
PART2_CONTRASTS = {"C-A": ("C", "A"), "D-B": ("D", "B"), "B-A": ("B", "A"), "D-C": ("D", "C")}
LOCATION_METHODS = ("overlap", "contained", "start_line")
N_BOOT = 10000


# ---------------------------------------------------------------- loading
def read_jsonl(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def load_run(run_dir):
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    run = {"manifest": manifest, "part1": {}, "stability": defaultdict(dict), "part2": defaultdict(lambda: defaultdict(dict))}
    for f in sorted((run_dir / "part1").glob("*/episodes.jsonl")):
        run["part1"][f.parent.name] = {e["case_id"]: e for e in read_jsonl(f)}
    for f in sorted((run_dir / "stability").glob("rep*/*/episodes.jsonl")):
        run["stability"][f.parent.name][int(f.parent.parent.name[3:])] = {e["case_id"]: e for e in read_jsonl(f)}
    for f in sorted((run_dir / "part2").glob("*/rep*/*/episodes.jsonl")):
        cell, rep, model = f.parent.parent.parent.name, int(f.parent.parent.name[3:]), f.parent.name
        run["part2"][model][cell][rep] = {e["case_id"]: e for e in read_jsonl(f)}
    return run


def case_to_repo(cases):
    out = {}
    for cid in cases:
        meta = json.loads((ROOT / "benchmark" / "cases" / cid / "metadata.json").read_text())
        out[cid] = meta.get("repository") or cid
    return out


# ---------------------------------------------------------------- per-case outcomes
def sample_outcome(rec, method="overlap"):
    """Outcome of one sample record under a location method (records store all three verdicts)."""
    if rec.get("scan_status") not in (None, "ok"):
        return "ERROR"
    if rec["label"] == "negative":
        return "FP" if rec["detected"] else "TN"
    if not rec["detected"]:
        return "FN"
    verdicts = rec.get("location_by_method")
    ok = rec.get("finding_location_correct") if verdicts is None else verdicts.get(method)
    return "FN" if ok is False else "TP"


def case_result(ep, workflow, method="overlap"):
    """{"accepted", "complete", "outcomes" (accepted rule's six outcomes or None)} for one episode and workflow."""
    if ep is None:
        return {"accepted": False, "complete": False, "outcomes": None, "missing": True}
    wf = ep["workflows"][workflow]
    k = wf["accepted_attempt"]
    if k is None:
        return {"accepted": False, "complete": False, "outcomes": None, "missing": False}
    recs = ep["samples"].get(str(k)) or ep["samples"].get(k) or []
    outcomes = {r["sample_type"]: sample_outcome(r, method) for r in recs}
    complete = (len(outcomes) == 6 and all(outcomes[s] == "TP" for s in POSITIVE)
                and all(outcomes[s] == "TN" for s in NEGATIVE))
    return {"accepted": True, "complete": complete, "outcomes": outcomes, "missing": False}


# ---------------------------------------------------------------- statistics helpers
def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def mcc_from(tp, fp, fn, tn):
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return None if den == 0 else (tp * tn - fp * fn) / den


def hidden_breakdown(results):
    """Over accepted rules: per-sample detection / false-positive rates and conditional MCC (hidden samples only)."""
    acc = [r["outcomes"] for r in results if r["accepted"] and r["outcomes"]]
    n = len(acc)
    out = {"n_accepted": n}
    for s in HIDDEN:
        good = "TP" if s in POSITIVE else "TN"
        hits = sum(o.get(s) == good for o in acc)
        key = "detected" if s in POSITIVE else "false_positive"
        out[s] = {key: (hits if s in POSITIVE else n - hits), "n": n}
    tp = sum(o.get(s) == "TP" for o in acc for s in HIDDEN if s in POSITIVE)
    fn = sum(o.get(s) in ("FN", "ERROR") for o in acc for s in HIDDEN if s in POSITIVE)
    tn = sum(o.get(s) == "TN" for o in acc for s in HIDDEN if s in NEGATIVE)
    fp = sum(o.get(s) in ("FP", "ERROR") for o in acc for s in HIDDEN if s in NEGATIVE)
    out["conditional_mcc"] = mcc_from(tp, fp, fn, tn)
    out["confusion"] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
    return out


# ---------------------------------------------------------------- Part I
def part1_table(run, n_boot=N_BOOT, method="overlap"):
    cases = run["manifest"]["cases"]
    repo = case_to_repo(cases)
    rows = {}
    for model, eps in run["part1"].items():
        for wf in PART1_WORKFLOWS:
            res = {c: case_result(eps.get(c), wf, method) for c in cases}
            n = len(cases)
            acc = sum(r["accepted"] for r in res.values())
            comp = sum(r["complete"] for r in res.values())
            _, blo, bhi = repo_aware_bootstrap_single(cases, repo, lambda ids: sum(res[c]["complete"] for c in ids) / len(ids),
                                                      n_boot=n_boot)
            errors = sum(1 for r in res.values() if r["outcomes"] and "ERROR" in r["outcomes"].values())
            rows[f"{model}|{wf}"] = {
                "model": model, "workflow": wf, "n_requested": n,
                "n_missing": sum(r["missing"] for r in res.values()),
                "accepted": acc, "accepted_rate": acc / n, "accepted_wilson": wilson(acc, n),
                "complete": comp, "complete_rate": comp / n, "complete_wilson": wilson(comp, n),
                "complete_repo_bootstrap": (blo, bhi),
                "accepted_with_error_sample": errors,
                "hidden": hidden_breakdown(list(res.values())),
            }
    return rows


def workflow_comparisons(run, n_boot=N_BOOT, method="overlap"):
    cases = run["manifest"]["cases"]
    repo = case_to_repo(cases)
    out = []
    for model, eps in run["part1"].items():
        res = {wf: {c: case_result(eps.get(c), wf, method)["complete"] for c in cases} for wf in PART1_WORKFLOWS}
        for a, b in PART1_PAIRS:
            wins_a = sum(res[a][c] and not res[b][c] for c in cases)
            wins_b = sum(res[b][c] and not res[a][c] for c in cases)
            diff, lo, hi, _ = repo_aware_bootstrap(cases, repo, lambda ids, w=a: sum(res[w][c] for c in ids) / len(ids),
                                                   lambda ids, w=b: sum(res[w][c] for c in ids) / len(ids), n_boot=n_boot)
            out.append({"model": model, "a": a, "b": b, "a_only": wins_a, "b_only": wins_b,
                        "rate_diff": diff, "repo_bootstrap_ci": (lo, hi), "mcnemar_p": mcnemar_exact(wins_a, wins_b)})
    for row, adj in zip(out, holm_correct([r["mcnemar_p"] for r in out]) if out else []):
        row["holm_p"] = adj
    return out


def location_sensitivity(run):
    cases = run["manifest"]["cases"]
    return {f"{m}|{wf}": {meth: sum(case_result(eps.get(c), wf, meth)["complete"] for c in cases) for meth in LOCATION_METHODS}
            for m, eps in run["part1"].items() for wf in PART1_WORKFLOWS}


FUNNEL = ("requested", "rule_parsed", "rule_runs", "visible_pair_ok", "visible_pair_at_location",
          "both_variants_detected", "complete_success")


def first_attempt_funnel(run, method="overlap"):
    cases = run["manifest"]["cases"]
    per_model, stages = {}, {}
    for model, eps in run["part1"].items():
        cnt = dict.fromkeys(FUNNEL, 0)
        st = Counter()
        for c in cases:
            cnt["requested"] += 1
            ep = eps.get(c)
            if not ep or not ep["attempts"]:
                st["missing"] += 1
                continue
            a1 = ep["attempts"][0]
            for a in ep["attempts"]:
                st[a["failure_stage"] or "rule_parsed"] += 1
            if a1["rule"] is None:
                continue
            cnt["rule_parsed"] += 1
            if set((a1["gate_scan_status"] or {}).values()) != {"ok"}:
                continue
            cnt["rule_runs"] += 1
            if not a1["accepted_visible_only"]:
                continue
            cnt["visible_pair_ok"] += 1
            if not a1["accepted"]:
                continue
            cnt["visible_pair_at_location"] += 1
            r = case_result(ep, "single_shot", method)
            if r["outcomes"] and all(r["outcomes"].get(s) == "TP" for s in ("variant_vulnerable_1", "variant_vulnerable_2")):
                cnt["both_variants_detected"] += 1
            if r["complete"]:
                cnt["complete_success"] += 1
        per_model[model], stages[model] = cnt, dict(st)
    return {"stages": FUNNEL, "per_model": per_model, "attempt_failure_stages": stages}


def model_overlap(run, workflow="autogrep", method="overlap", public_rule_cases=()):
    cases = run["manifest"]["cases"]
    solved = {m: {c for c in cases if case_result(eps.get(c), workflow, method)["complete"]} for m, eps in run["part1"].items()}
    per_case = {c: sorted(m for m in solved if c in solved[m]) for c in cases}
    pub = [c for c in cases if c in set(public_rule_cases)]
    return {"workflow": workflow, "solved_by_any": sum(bool(v) for v in per_case.values()),
            "solved_by_none": sum(not v for v in per_case.values()),
            "models_per_case": Counter(len(v) for v in per_case.values()),
            "public_rule_cases": pub,
            "solve_rate_public": (sum(len(per_case[c]) for c in pub) / (len(pub) * len(solved))) if pub and solved else None,
            "solve_rate_rest": (sum(len(per_case[c]) for c in cases if c not in pub) / ((len(cases) - len(pub)) * len(solved)))
            if solved and len(cases) > len(pub) else None}


def stability(run, method="overlap"):
    cases = run["manifest"]["cases"]
    out = {}
    for model, reps in run["stability"].items():
        r_ids = sorted(reps)
        vec = {c: [case_result(reps[r].get(c), "single_shot", method)["complete"] for r in r_ids] for c in cases}
        rates = [sum(vec[c][i] for c in cases) / len(cases) for i in range(len(r_ids))]
        consistent = sum(len(set(v)) == 1 for v in vec.values())
        out[model] = {"repeats": r_ids, "complete_rate_per_repeat": rates,
                      "cases_consistent_across_repeats": consistent, "n_cases": len(cases),
                      "fleiss_kappa": fleiss_kappa([sum(v) for v in vec.values()], len(r_ids))}
    return out


def fleiss_kappa(successes_per_case, raters):
    """Fleiss' kappa for a binary outcome, with `raters` repeats per case."""
    n, k = len(successes_per_case), raters
    if n == 0 or k < 2:
        return None
    p_yes = sum(successes_per_case) / (n * k)
    pe = p_yes ** 2 + (1 - p_yes) ** 2
    pi = [(s * (s - 1) + (k - s) * (k - s - 1)) / (k * (k - 1)) for s in successes_per_case]
    pbar = sum(pi) / n
    return None if pe == 1 else (pbar - pe) / (1 - pe)


# ---------------------------------------------------------------- Part II
def part2(run, n_boot=N_BOOT, method="overlap"):
    cases = run["manifest"].get("part2_cases", run["manifest"]["cases"])
    repo = case_to_repo(cases)
    out = {}
    for model, cells in run["part2"].items():
        mean = {}                    # (cell, workflow) -> {case: mean success over repeats}
        cost = {}
        probe_eligible = set()
        for cell, reps in cells.items():
            for wf in PART2_WORKFLOWS:
                mean[(cell, wf)] = {c: sum(case_result(reps[r].get(c), wf, method)["complete"] for r in reps) / len(reps)
                                    for c in cases}
            eps = [e for r in reps.values() for e in r.values()]
            cost[cell] = {"episodes": len(eps),
                          "mean_calls": sum(len(e["attempts"]) for e in eps) / len(eps) if eps else None,
                          "mean_input_tokens": sum(sum(a["input_tokens"] for a in e["attempts"]) for e in eps) / len(eps) if eps else None,
                          "mean_output_tokens": sum(sum(a["output_tokens"] for a in e["attempts"]) for e in eps) / len(eps) if eps else None}
            probe_eligible |= {e["case_id"] for e in eps if e.get("probe_eligible")}
        res = {"cost": cost, "probe_eligible_cases": sorted(probe_eligible), "contrasts": {}}
        for subset_name, subset in (("all", cases), ("probe_eligible", [c for c in cases if c in probe_eligible])):
            for wf in PART2_WORKFLOWS:
                for name, (x, y) in PART2_CONTRASTS.items():
                    if (x, wf) not in mean or (y, wf) not in mean or not subset:
                        continue
                    mx, my = mean[(x, wf)], mean[(y, wf)]
                    diff, lo, hi, _ = repo_aware_bootstrap(subset, repo, lambda ids, m=mx: sum(m[c] for c in ids) / len(ids),
                                                           lambda ids, m=my: sum(m[c] for c in ids) / len(ids), n_boot=n_boot)
                    res["contrasts"][f"{subset_name}|{wf}|{name}"] = {
                        "n_cases": len(subset), "rate_x": sum(mx[c] for c in subset) / len(subset),
                        "rate_y": sum(my[c] for c in subset) / len(subset), "diff": diff, "repo_bootstrap_ci": (lo, hi),
                        "cases_gained": sum(mx[c] > my[c] for c in subset), "cases_lost": sum(mx[c] < my[c] for c in subset)}
                if all((c_, wf) in mean for c_ in "ABCD") and subset:
                    inter = {c: (mean[("D", wf)][c] - mean[("C", wf)][c]) - (mean[("B", wf)][c] - mean[("A", wf)][c]) for c in subset}
                    diff, lo, hi, _ = repo_aware_bootstrap(subset, repo, lambda ids: sum(inter[c] for c in ids) / len(ids),
                                                           lambda ids: 0.0, n_boot=n_boot)
                    res["contrasts"][f"{subset_name}|{wf}|interaction"] = {"n_cases": len(subset), "diff": diff,
                                                                           "repo_bootstrap_ci": (lo, hi)}
        out[model] = res
    return out


# ---------------------------------------------------------------- report
def public_rule_cases(cases):
    """Cases whose fix commit already has a rule in Autogrep's public corpus (same method as v1's paper_results)."""
    import re
    shas = set()
    for f in (ROOT / "autogrep" / "filtered_rules").rglob("*"):
        if f.is_file():
            shas.update(re.findall(r"source-url:\s*\S*/commit/([0-9a-f]{40})", f.read_text(errors="ignore")))
    out = []
    for cid in cases:
        meta = json.loads((ROOT / "benchmark" / "cases" / cid / "metadata.json").read_text())
        if {meta.get("fixed_commit"), meta.get("vulnerable_commit")} & shas:
            out.append(cid)
    return out


def analyze(run_dir, n_boot=N_BOOT, allow_non_real=False):
    run = load_run(run_dir)
    mode = run["manifest"].get("mode", "real")
    if mode != "real" and not allow_non_real:
        raise SystemExit(f"{run_dir} is a {mode} run: its results are never analysed (use allow_non_real only to "
                         "test the pipeline itself)")
    cases = run["manifest"]["cases"]
    result = {
        "part1_table": part1_table(run, n_boot),
        "workflow_comparisons": workflow_comparisons(run, n_boot),
        "location_sensitivity": location_sensitivity(run),
        "first_attempt_funnel": first_attempt_funnel(run),
        "model_overlap": {wf: model_overlap(run, wf, public_rule_cases=public_rule_cases(cases)) for wf in PART1_WORKFLOWS},
        "stability": stability(run),
        "part2": part2(run, n_boot),
    }
    out = Path(run_dir) / "analysis"
    out.mkdir(exist_ok=True)
    for k, v in result.items():
        (out / f"{k}.json").write_text(json.dumps(v, indent=1, default=lambda o: dict(o) if isinstance(o, Counter) else str(o)))
    (out / "summary.md").write_text(summary_md(result))
    return result


def _pct(x):
    return "–" if x is None else f"{100 * x:.1f}%"


def summary_md(result):
    lines = ["# Run v2 results (generated by pipeline/analyze_v2.py)", "",
             "| Model | Workflow | Accepted | Complete success (Wilson 95%) | Renamed | Restructured | Cond. MCC |",
             "|---|---|---|---|---|---|---|"]
    for row in result["part1_table"].values():
        h = row["hidden"]
        n = h["n_accepted"]
        ren = h["variant_vulnerable_1"]["detected"] / n if n else None
        res = h["variant_vulnerable_2"]["detected"] / n if n else None
        lo, hi = row["complete_wilson"]
        lines.append(f"| {row['model']} | {row['workflow']} | {row['accepted']}/{row['n_requested']} | "
                     f"{row['complete']}/{row['n_requested']} ({_pct(row['complete_rate'])}; {_pct(lo)}–{_pct(hi)}) | "
                     f"{_pct(ren)} | {_pct(res)} | {'–' if h['conditional_mcc'] is None else f'{h['conditional_mcc']:.3f}'} |")
    lines += ["", "| Model | Comparison | Only A | Only B | McNemar p | Holm p |", "|---|---|---|---|---|---|"]
    for r in result["workflow_comparisons"]:
        lines.append(f"| {r['model']} | {r['a']} vs {r['b']} | {r['a_only']} | {r['b_only']} | {r['mcnemar_p']:.4f} | {r['holm_p']:.4f} |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--n-boot", type=int, default=N_BOOT)
    ap.add_argument("--allow-non-real", action="store_true", help="pipeline tests only: analyse a smoke or dry run")
    a = ap.parse_args(argv)
    analyze(a.run_dir, a.n_boot, a.allow_non_real)
    print((Path(a.run_dir) / "analysis" / "summary.md").read_text())


if __name__ == "__main__":
    main()
