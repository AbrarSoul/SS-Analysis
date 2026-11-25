"""Bounded closure of known round-3 reproductions and retained coverage; no inference/scans."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
from dev_probe import build_probe, ProbeIneligible, ProbeResult


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    prior_path = Path(__file__).with_name("Dev_Probe_Round3_Evidence_20261013.json")
    prior = json.loads(prior_path.read_text())
    checks = []
    for row in prior["new_counterexamples"]:
        language = row["result"]["language"]
        src = row["input"]
        assert isinstance(build_probe(row["label"], language, src, src), ProbeIneligible)
        # Patched-side protection must also hold when the vulnerable source is safely renamable.
        vulnerable = ("def f():\n    token=1\n    return token\n" if language == "python"
                      else "function f(x) { let token=1; return x+token; }")
        pair = build_probe(row["label"] + "_patched", language, vulnerable, src)
        assert isinstance(pair, ProbeResult) and pair.patched_probe == src and not pair.patched_probe_renamed
        checks.append({"case": row["label"], "vulnerable_result": "ineligible", "patched_result": "valid source unchanged"})
    ts = "function f(x: number=token): number { let token=1; return x+token; }"
    assert isinstance(build_probe("ts_default", "typescript", ts, ts), ProbeIneligible)
    checks.append({"case": "typescript_typed_default", "vulnerable_result": "ineligible"})

    path = ROOT / "results/diagnostic_20261010/_probe_coverage_20261013T011301679535Z/summary.json"
    summary = json.loads(path.read_text())
    inputs = {Path(__file__), prior_path, path, ROOT / "pipeline/dev_probe.py",
              ROOT / "pipeline/tests/test_dev_probe.py", ROOT / "pipeline/probe_coverage_check.py"}
    for cid, e in summary["eligibility"].items():
        ctx_path = ROOT / f"benchmark/model_context/{cid}.json"
        inputs.add(ctx_path)
        ctx = json.loads(ctx_path.read_text())
        r = build_probe(cid, e["language"], ctx["vulnerable_function"], ctx["patched_function"])
        assert isinstance(r, ProbeResult) == e["eligible"]
        if e["eligible"]:
            for side in ("vulnerable_probe", "patched_probe"):
                p = ROOT / e[side + "_path"]
                inputs.add(p)
                assert p.is_relative_to(path.parent / "_probe_inputs")
                assert sha(p) == e[side + "_sha256"] and p.read_text() == getattr(r, side)
    counts, failures = Counter(), []
    for row in summary["per_episode"]:
        e = summary["eligibility"][row["case_id"]]
        raw = path.parent / row["model"].replace(":", "_") / row["condition"] / f'r{row["repeat"]}' / row["case_id"] / "stdout.json"
        inputs.add(raw)
        data = json.loads(raw.read_text())
        assert data["version"] == "1.177.0" and not data["errors"]
        v, p = [str((ROOT / e[k]).resolve()) for k in ("vulnerable_probe_path", "patched_probe_path")]
        assert {v, p} <= set(data["paths"]["scanned"])
        hits = {r["path"] for r in data["results"]}
        vh, ph = v in hits, p in hits
        assert row["scan_ok"] and row["vulnerable_detected"] == vh and row["patched_detected"] == ph
        counts.update(total=1, passed=int(vh and not ph), missed=int(not vh), patched_findings=int(ph))
        if not vh or ph:
            failures.append([row["model"], row["condition"], row["repeat"], row["case_id"]])
    eligible = [c for c, e in summary["eligibility"].items() if e["eligible"]]
    assert counts == prior["coverage_counts"] and len(eligible) == 11
    assert sorted(failures) == sorted(prior["failures"])
    changed = [p for p, digest in prior["reviewed_sha256"].items() if sha(ROOT / p) != digest]
    assert set(changed) == {"pipeline/dev_probe.py", "pipeline/tests/test_dev_probe.py"}
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "known_reproductions": checks,
              "coverage_counts": dict(counts), "eligible_cases": eligible, "failures": failures,
              "covered_accepted": 100, "all_accepted": 195, "uncovered_accepted": 95,
              "prior_results_unchanged": True, "previous_reviewed_inputs_changed": changed,
              "tests": "32 probe tests passed in 0.71s; full suite not rerun by this review",
              "model_calls": 0, "semgrep_scans": 0,
              "scope": "Known counterexamples closed; no exhaustive binding-form certification.",
              "reviewed_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted(inputs)}}
    output = Path(__file__).with_name("Dev_Probe_Closure_Evidence_20261013.json")
    with output.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(json.dumps({k:v for k,v in report.items() if k != "reviewed_sha256"}, indent=2))


if __name__ == "__main__":
    main()
