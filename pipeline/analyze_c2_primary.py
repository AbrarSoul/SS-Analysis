"""
C2 vs Phase 5 (raw / autogrep) comparison -- design Section 20: "the main causal multi-agent
comparison is C2 versus C3 using the same model and budget." C3 doesn't exist yet, so this is an
interim comparison against Phase 5's existing single-agent conditions instead: does giving a model
an iterative repair loop under Section 20's explicit multi-call budget (C2) do any better than
Autogrep's own retry loop (the "autogrep" condition, a looser/different budget) or a single shot
("raw")?

Reuses analyze_phase5_primary.py's pooled-confusion machinery (confusion_from_samples, mcc, rate,
per_case_vgr_fpr) directly -- same formulas, same Section 21.9 "pool everything, don't macro-average"
convention -- applied to results/runs_c2_primary/*/{c2_episode_log,sample_execution_log}.jsonl, and to
Phase 5's own results restricted to the SAME 153 supported cases C2 was run on (not all 300), so the
comparison is apples-to-apples in case scope even though it can't yet be apples-to-apples in budget
(C2's Section 20 budget is richer than and different from autogrep's own retry-count-only budget --
flagged, not glossed over).
"""
import glob
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import (
    load_manifest, confusion_from_samples, mcc, rate, per_case_vgr_fpr, analyze_model,
)

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
RESULTS_ROOT = Path(__file__).resolve().parent.parent / "results"
CODELLAMA = "codellama:7b-instruct-fp16"


def load_c2_run_dir(d: Path):
    episodes = [json.loads(l) for l in (d / "c2_episode_log.jsonl").read_text().splitlines()]
    samples = [json.loads(l) for l in (d / "sample_execution_log.jsonl").read_text().splitlines()]
    return episodes, samples


def analyze_c2_model(episodes, samples):
    n_cases = len(episodes)
    accepted = sum(1 for e in episodes if e["accepted"])
    by_case = defaultdict(list)
    for s in samples:
        by_case[s["case_id"]].append(s)

    pds_num = 0
    vgr_values, fpr_values = [], []
    all_samples = []
    for cid, case_samples in by_case.items():
        all_samples.extend(case_samples)
        vgr, fpr, vuln_tp, patched_tn = per_case_vgr_fpr(case_samples)
        if vgr is not None:
            vgr_values.append(vgr)
        if fpr is not None:
            fpr_values.append(fpr)
        if vuln_tp and patched_tn:
            pds_num += 1

    counts = confusion_from_samples(all_samples)
    vgr_num = sum(1 for s in all_samples if s["sample_type"].startswith("variant_vulnerable") and s["outcome"] == "TP")
    vgr_den = sum(1 for s in all_samples if s["sample_type"].startswith("variant_vulnerable"))

    calls = [e["calls_used"] for e in episodes]
    rounds = [e["repair_rounds_used"] for e in episodes]
    stop_reasons = Counter(e["stop_reason"] for e in episodes)

    return {
        "n_cases": n_cases,
        "accepted": accepted,
        "coverage": rate(accepted, n_cases),
        "pds": rate(pds_num, n_cases),
        "vgr_pooled": rate(vgr_num, vgr_den),
        "mcc": mcc(counts),
        "fpr": rate(counts["FP"], counts["FP"] + counts["TN"]),
        "counts": counts,
        "avg_calls": sum(calls) / len(calls),
        "avg_repair_rounds": sum(rounds) / len(rounds),
        "stop_reasons": stop_reasons,
    }


def main():
    manifest = load_manifest()
    c2_dirs = sorted(glob.glob(str(RESULTS_ROOT / "runs_c2_primary" / "*__c2")))
    c2_results = {}
    for d in c2_dirs:
        d = Path(d)
        episodes, samples = load_c2_run_dir(d)
        model = episodes[0]["model_tag"]
        c2_results[model] = analyze_c2_model(episodes, samples)

    # Same 153 case ids C2 actually ran on -- restrict Phase 5's comparison to this exact scope.
    first_episodes = [json.loads(l) for l in (Path(c2_dirs[0]) / "c2_episode_log.jsonl").read_text().splitlines()]
    c2_case_ids = {e["case_id"] for e in first_episodes}
    restricted_manifest = {cid: manifest[cid] for cid in c2_case_ids}
    print(f"C2 ran on {len(c2_case_ids)} cases (expect 153, all 'supported' in the final 300-case set).\n")

    phase5_dirs = sorted(glob.glob(str(RESULTS_ROOT / "runs_phase5_primary" / "*__autogrep_default")))
    phase5_results = {}
    for d in phase5_dirs:
        d = Path(d)
        gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
        smp = [json.loads(l) for l in (d / "sample_execution_log.jsonl").read_text().splitlines()]
        model = gen[0]["model_tag"]
        phase5_results[model] = analyze_model(model, gen, smp, restricted_manifest, {"supported"})

    print("=" * 110)
    print("C2 vs Phase 5 raw/autogrep -- same 153 supported cases, sorted by C2's MCC")
    print("=" * 110)
    print(f"{'model':32} {'C2 cov':>8} {'C2 MCC':>8} {'C2 VGR':>8} {'C2 FPR':>8} "
          f"{'raw MCC':>8} {'autogrep MCC':>13} {'avg calls':>10}")

    rows = []
    for model, c2 in c2_results.items():
        p5 = phase5_results.get(model, {})
        raw_mcc = p5.get("raw", {}).get("mcc")
        autogrep_mcc = p5.get("autogrep", {}).get("mcc")

        def fmt(x):
            return f"{x:.3f}" if x is not None else "  n/a"

        rows.append((c2["mcc"], model,
                     f"{model:32} {fmt(c2['coverage']):>8} {fmt(c2['mcc']):>8} {fmt(c2['vgr_pooled']):>8} {fmt(c2['fpr']):>8} "
                     f"{fmt(raw_mcc):>8} {fmt(autogrep_mcc):>13} {c2['avg_calls']:>10.2f}"))
    rows.sort(reverse=True)
    for _, _, line in rows:
        print(line)

    print(f"\n{'-' * 110}")
    print("C2 resource usage and stop-reason breakdown (153 cases each)")
    print(f"{'-' * 110}")
    print(f"{'model':32} {'avg calls':>10} {'avg repair rounds':>18}  stop_reasons")
    for model, c2 in sorted(c2_results.items(), key=lambda kv: -kv[1]["mcc"]):
        print(f"{model:32} {c2['avg_calls']:>10.2f} {c2['avg_repair_rounds']:>18.2f}  {dict(c2['stop_reasons'])}")

    print(f"\nNote: C2's budget (Section 20: up to 6 calls, 3 repair rounds, 30000/6000 combined token caps, "
          f"10 min wall clock) differs from autogrep's own retry loop (up to 3 attempts, no cumulative token/"
          f"wall-clock cap) -- this is NOT yet a budget-matched comparison (that requires C3 to exist, per "
          f"Section 20's own framing: 'the main causal multi-agent comparison is C2 versus C3'). Reported here "
          f"as the best currently-available reference point, not as the design's intended final comparison.")


if __name__ == "__main__":
    main()
