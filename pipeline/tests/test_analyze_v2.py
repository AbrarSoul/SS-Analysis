"""
Run v2 analysis (pipeline/analyze_v2.py), tested on a SIMULATED run before any real result exists.

The simulated episodes have hand-chosen outcomes, so every number below was worked out by hand:
  six cases for model M:
    c1  attempt 1 accepted, all six samples correct          -> complete in every workflow
    c2  attempt 1 unparseable, attempt 2 accepted, correct   -> complete in autogrep and iterative only
    c3  attempts 1-3 rejected, attempt 4 accepted, correct   -> complete in iterative only
    c4  attempt 1 accepted, restructured variant missed      -> accepted, not complete
    c5  attempt 1 accepted, look-alike flagged (FP)          -> accepted, not complete
    c6  missing episode                                      -> counts as not accepted
One real episode (fake model, real pinned Semgrep) checks that the analysis reads what run_v2_episode writes.
"""
import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("GPTLAB_API_KEY", "not-used-offline-test")
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep"), str(Path(__file__).resolve().parent)]

import analyze_v2 as A  # noqa: E402
import run_v2_settings as S  # noqa: E402

CASES = S.eligible_cases()[:6]
ALL_OK = {"original_vulnerable": "TP", "original_patched": "TN", "variant_vulnerable_1": "TP",
          "variant_vulnerable_2": "TP", "variant_safe": "TN", "benign_lookalike": "TN"}


def rec(sample_type, outcome, status="ok", loc=None):
    label = "positive" if sample_type in A.POSITIVE else "negative"
    detected = outcome in ("TP", "FP") or (outcome == "FN_LOC")
    r = {"sample_type": sample_type, "label": label, "detected": detected, "scan_status": status}
    if label == "positive":
        lbm = loc or {"overlap": outcome == "TP", "contained": outcome == "TP", "start_line": outcome == "TP"}
        r["location_by_method"] = lbm if detected else None
        r["finding_location_correct"] = lbm["overlap"] if detected else None
    return r


def attempt(i, accepted, parsed=True, visible_only=None, stage=None, within=True, tokens=(100, 50)):
    return {"index": i, "accepted": accepted, "rule": {"id": "r"} if parsed else None,
            "failure_stage": None if parsed else (stage or "yaml_parse"),
            "accepted_visible_only": accepted if visible_only is None else visible_only,
            "gate_scan_status": {"original_vulnerable": "ok", "original_patched": "ok"} if parsed else None,
            "within_iterative_budget": within, "input_tokens": tokens[0], "output_tokens": tokens[1]}


def episode(cid, attempts, samples_by_attempt, probe_eligible=None):
    import run_v2_episode as E
    from types import SimpleNamespace
    wf = E.derive_workflows([SimpleNamespace(**a) for a in attempts])
    return {"case_id": cid, "attempts": attempts, "workflows": wf, "probe_eligible": probe_eligible,
            "samples": {str(k): [rec(s, o, **kw) for s, o, kw in v] for k, v in samples_by_attempt.items()}}


def six(**over):
    """The six (sample_type, outcome, kwargs) triples, all correct unless overridden."""
    out = []
    for s, o in ALL_OK.items():
        val = over.get(s, o)
        out.append((s, val[0], val[1]) if isinstance(val, tuple) else (s, val, {}))
    return out


def simulated_part1():
    c1, c2, c3, c4, c5, _ = CASES
    loc_overlap_only = {"overlap": True, "contained": False, "start_line": False}
    return {
        c1: episode(c1, [attempt(1, True)], {1: six(original_vulnerable=("TP", {"loc": loc_overlap_only}))}),
        c2: episode(c2, [attempt(1, False, parsed=False), attempt(2, True)], {2: six()}),
        c3: episode(c3, [attempt(1, False), attempt(2, False), attempt(3, False), attempt(4, True)],
                    {1: six(), 2: six(), 3: six(), 4: six()}),
        c4: episode(c4, [attempt(1, True)], {1: six(variant_vulnerable_2="FN")}),
        c5: episode(c5, [attempt(1, True)], {1: six(benign_lookalike="FP")}),
    }


def write_run(tmp, part1=None, stability=None, part2=None, part2_cases=None):
    (tmp / "manifest.json").write_text(json.dumps({"cases": CASES, "part2_cases": part2_cases or CASES}))
    for model, eps in (part1 or {}).items():
        d = tmp / "part1" / model
        d.mkdir(parents=True)
        (d / "episodes.jsonl").write_text("".join(json.dumps(e) + "\n" for e in eps.values()))
    for model, reps in (stability or {}).items():
        for r, eps in reps.items():
            d = tmp / "stability" / f"rep{r}" / model
            d.mkdir(parents=True)
            (d / "episodes.jsonl").write_text("".join(json.dumps(e) + "\n" for e in eps.values()))
    for model, cells in (part2 or {}).items():
        for cell, reps in cells.items():
            for r, eps in reps.items():
                d = tmp / "part2" / cell / f"rep{r}" / model
                d.mkdir(parents=True)
                (d / "episodes.jsonl").write_text("".join(json.dumps(e) + "\n" for e in eps.values()))
    return A.load_run(tmp)


# ---------------------------------------------------------------- statistics helpers
def test_wilson_and_mcc_and_fleiss():
    lo, hi = A.wilson(1, 10)
    assert round(lo, 4) == 0.0179 and round(hi, 4) == 0.4042
    assert A.mcc_from(7, 1, 1, 7) == pytest.approx(0.75)
    assert A.fleiss_kappa([3, 3, 0, 0], 3) == pytest.approx(1.0)          # perfectly consistent repeats
    assert A.fleiss_kappa([1, 2, 1, 2], 3) < 0                            # less agreement than chance


# ---------------------------------------------------------------- Part I
def test_part1_rates(tmp_path):
    run = write_run(tmp_path, part1={"M": simulated_part1()})
    t = A.part1_table(run, n_boot=200)
    got = {wf: (t[f"M|{wf}"]["accepted"], t[f"M|{wf}"]["complete"]) for wf in A.PART1_WORKFLOWS}
    assert got == {"single_shot": (3, 1), "autogrep": (4, 2), "iterative": (5, 3)}
    assert t["M|single_shot"]["n_requested"] == 6 and t["M|single_shot"]["n_missing"] == 1
    lo, hi = t["M|iterative"]["complete_repo_bootstrap"]
    assert lo <= 0.5 <= hi


def test_hidden_breakdown_and_conditional_mcc(tmp_path):
    run = write_run(tmp_path, part1={"M": simulated_part1()})
    h = A.part1_table(run, n_boot=200)["M|autogrep"]["hidden"]       # accepted: c1, c2, c4, c5
    assert h["n_accepted"] == 4
    assert h["variant_vulnerable_1"]["detected"] == 4 and h["variant_vulnerable_2"]["detected"] == 3
    assert h["variant_safe"]["false_positive"] == 0 and h["benign_lookalike"]["false_positive"] == 1
    assert h["confusion"] == {"tp": 7, "fp": 1, "fn": 1, "tn": 7} and h["conditional_mcc"] == pytest.approx(0.75)


def test_workflow_comparisons(tmp_path):
    run = write_run(tmp_path, part1={"M": simulated_part1()})
    cmp = {(r["a"], r["b"]): r for r in A.workflow_comparisons(run, n_boot=200)}
    assert (cmp[("single_shot", "autogrep")]["a_only"], cmp[("single_shot", "autogrep")]["b_only"]) == (0, 1)
    assert (cmp[("autogrep", "iterative")]["a_only"], cmp[("autogrep", "iterative")]["b_only"]) == (0, 1)
    assert (cmp[("single_shot", "iterative")]["a_only"], cmp[("single_shot", "iterative")]["b_only"]) == (0, 2)
    assert cmp[("single_shot", "iterative")]["rate_diff"] == pytest.approx(-2 / 6)
    assert all(r["holm_p"] >= r["mcnemar_p"] for r in cmp.values())


def test_location_sensitivity(tmp_path):
    run = write_run(tmp_path, part1={"M": simulated_part1()})
    s = A.location_sensitivity(run)["M|single_shot"]
    assert s == {"overlap": 1, "contained": 0, "start_line": 0}       # c1's finding only overlaps the bug lines


def test_error_sample_is_never_complete(tmp_path):
    p1 = simulated_part1()
    c1 = CASES[0]
    p1[c1] = episode(c1, [attempt(1, True)], {1: six(variant_safe=("TN", {"status": "not_scanned"}))})
    run = write_run(tmp_path, part1={"M": p1})
    t = A.part1_table(run, n_boot=200)["M|single_shot"]
    assert t["complete"] == 0 and t["accepted_with_error_sample"] == 1


def test_first_attempt_funnel(tmp_path):
    run = write_run(tmp_path, part1={"M": simulated_part1()})
    f = A.first_attempt_funnel(run)
    assert f["per_model"]["M"] == {"requested": 6, "rule_parsed": 4, "rule_runs": 4, "visible_pair_ok": 3,
                                   "visible_pair_at_location": 3, "both_variants_detected": 2, "complete_success": 1}
    assert f["attempt_failure_stages"]["M"]["yaml_parse"] == 1 and f["attempt_failure_stages"]["M"]["missing"] == 1


def test_model_overlap(tmp_path):
    run = write_run(tmp_path, part1={"M": simulated_part1(), "N": {CASES[0]: simulated_part1()[CASES[0]]}})
    o = A.model_overlap(run, "autogrep", public_rule_cases=[CASES[0]])
    assert o["solved_by_any"] == 2 and o["solved_by_none"] == 4
    assert o["solve_rate_public"] == 1.0 and o["solve_rate_rest"] == pytest.approx(1 / 10)


# ---------------------------------------------------------------- stability
def test_stability(tmp_path):
    good = lambda c: episode(c, [attempt(1, True)], {1: six()})
    bad = lambda c: episode(c, [attempt(1, False)], {1: six()})
    c1, c2, c3 = CASES[:3]
    reps = {1: {c1: good(c1), c2: good(c2), c3: bad(c3)}, 2: {c1: good(c1), c2: bad(c2), c3: bad(c3)},
            3: {c1: good(c1), c2: good(c2), c3: bad(c3)}}
    run = write_run(tmp_path, stability={"M": reps})
    s = A.stability(run)["M"]
    assert s["complete_rate_per_repeat"] == pytest.approx([2 / 6, 1 / 6, 2 / 6])
    assert s["cases_consistent_across_repeats"] == 5                      # c2 flips; c4-c6 missing = consistent fail


# ---------------------------------------------------------------- Part II
def test_part2_contrasts(tmp_path):
    c1, c2, c3, c4 = CASES[:4]
    good = lambda c, pe=None: episode(c, [attempt(1, True)], {1: six()}, probe_eligible=pe)
    bad = lambda c, pe=None: episode(c, [attempt(1, False), attempt(2, False), attempt(3, False)], {}, probe_eligible=pe)
    def cell(successes, pe=None):        # successes: {case: number of repeats (of 3) that succeed}
        return {r: {c: (good(c, pe) if r <= successes.get(c, 0) else bad(c, pe)) for c in (c1, c2, c3, c4)} for r in (1, 2, 3)}
    part2 = {"M": {"A": cell({c1: 3}), "B": cell({c1: 3, c2: 3}),
                   "C": cell({c1: 3, c3: 1}, pe=True), "D": cell({c1: 3, c2: 3, c3: 3}, pe=True)}}
    run = write_run(tmp_path, part2=part2, part2_cases=[c1, c2, c3, c4])
    res = A.part2(run, n_boot=200)["M"]
    con = res["contrasts"]
    assert con["all|single_shot|B-A"]["diff"] == pytest.approx(1 / 4)
    assert con["all|single_shot|C-A"]["diff"] == pytest.approx((1 / 3) / 4)          # c3 succeeds in 1 of 3 repeats
    assert con["all|single_shot|D-B"]["diff"] == pytest.approx(1 / 4)
    assert con["all|single_shot|C-A"]["cases_gained"] == 1 and con["all|single_shot|C-A"]["cases_lost"] == 0
    assert res["probe_eligible_cases"] == sorted([c1, c2, c3, c4])
    assert res["cost"]["A"]["mean_calls"] == pytest.approx((3 * 1 + 9 * 3) / 12)


def test_part2_interaction_by_hand(tmp_path):
    c1, c2 = CASES[:2]
    good = lambda c: episode(c, [attempt(1, True)], {1: six()})
    bad = lambda c: episode(c, [attempt(1, False)], {})
    full = lambda ok: {1: {c: (good(c) if c in ok else bad(c)) for c in (c1, c2)}}
    # A: none, B: c1, C: c1, D: c1+c2  ->  per case (D-C)-(B-A): c1 (1-1)-(1-0) = -1; c2 (1-0)-(0-0) = 1; mean 0
    run = write_run(tmp_path, part2={"M": {"A": full(set()), "B": full({c1}), "C": full({c1}), "D": full({c1, c2})}},
                    part2_cases=[c1, c2])
    assert A.part2(run, n_boot=200)["M"]["contrasts"]["all|single_shot|interaction"]["diff"] == pytest.approx(0.0)


# ---------------------------------------------------------------- end to end, and the real episode shape
def test_analyze_end_to_end(tmp_path):
    write_run(tmp_path, part1={"M": simulated_part1()})
    result = A.analyze(tmp_path, n_boot=200)
    assert (tmp_path / "analysis" / "summary.md").exists() and (tmp_path / "analysis" / "part1_table.json").exists()
    assert "| M | iterative | 5/6 | 3/6" in (tmp_path / "analysis" / "summary.md").read_text()
    assert result["part2"] == {}


def test_reads_a_real_episode(tmp_path):
    import test_run_v2_issue5 as T5
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    for stem, text in {"vulnerable_source": T5.VULN, "patched_source": T5.SAFE, "variant_vulnerable_01": T5.VULN,
                       "variant_vulnerable_02": T5.VULN, "variant_safe_01": T5.SAFE, "benign_lookalike": T5.SAFE}.items():
        (case_dir / f"{stem}.py").write_text(text)
    ep, _, _ = T5._run(case_dir, [T5.NOT_YAML, T5.GOOD])
    d = json.loads(json.dumps(ep.to_dict()))                 # exactly what the runner will write and read back
    assert A.case_result(d, "single_shot")["accepted"] is False
    r = A.case_result(d, "autogrep")
    assert r["accepted"] and r["complete"] and r["outcomes"] == ALL_OK
