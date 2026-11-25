"""Verify the third probe revision without inference or new Semgrep scans.

Replays the previous findings, executes two additional binding counterexamples, and recounts
the immutable saved coverage run. Writes a fresh evidence JSON; leaves inputs untouched.
"""
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
import dev_probe as dp


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def python_result(source):
    namespace = {}
    exec(source, namespace)
    value = namespace["f"]()
    return {"type": type(value).__name__, "str": str(value)}


def js_result(source):
    script = "globalThis.token=10;" + source + ";try {console.log(JSON.stringify({value:f()}));} catch(e){console.log(JSON.stringify({error:e.name,message:e.message}));}"
    p = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(p.stdout)


def main():
    prior_path = Path(__file__).with_name("Dev_Probe_Followup_Evidence_20261013.json")
    prior = json.loads(prior_path.read_text())
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "model_calls": 0,
              "semgrep_scans": 0, "previous_counterexamples": [], "new_counterexamples": []}
    for item in prior["remaining_counterexamples"]:
        label = item["label"]
        if label == "java_block_local_vs_field":
            v = "int f() { { int token = 1; } return token; }"
            result = dp.build_probe(label, "java", v, v)
            assert isinstance(result, dp.ProbeIneligible)
            status = "fixed: rejected"
        else:
            result = dp.build_probe(label, "python", item["vulnerable_input"], item["patched_input"])
            if label == "patched_global_reference":
                assert isinstance(result, dp.ProbeResult)
                assert result.patched_probe == item["patched_input"] and not result.patched_probe_renamed
                ns = dict(item["namespace"])
                exec(result.patched_probe, ns)
                assert ns["f"]() == 7
                status = "fixed: valid unchanged patched source still returns 7"
            else:
                assert isinstance(result, dp.ProbeIneligible)
                status = "fixed: rejected"
        report["previous_counterexamples"].append({"label": label, "status": status})
    invalid = dp.build_probe("invalid_patched", "python", "def f():\n    token=1\n    return token\n", "def f(:")
    assert isinstance(invalid, dp.ProbeIneligible)
    report["previous_counterexamples"].append({"label": "invalid_patched", "status": "fixed: rejected"})

    source = "def f():\n    token = 1\n    try:\n        raise ValueError(7)\n    except ValueError as token:\n        return token\n"
    result = dp.build_probe("python_exception_binding", "python", source, source)
    assert isinstance(result, dp.ProbeResult)
    before, after = python_result(source), python_result(result.vulnerable_probe)
    assert before == {"type": "ValueError", "str": "7"} and after == {"type": "int", "str": "1"}
    report["new_counterexamples"].append({"label": "python_exception_binding", "input": source,
        "result": asdict(result), "before": before, "after": after})
    source = "function f(x=token) { let token=1; return x+token; }"
    result = dp.build_probe("javascript_default_scope", "javascript", source, source)
    assert isinstance(result, dp.ProbeResult)
    before, after = js_result(source), js_result(result.vulnerable_probe)
    assert before == {"value": 11} and after["error"] == "ReferenceError"
    report["new_counterexamples"].append({"label": "javascript_default_scope", "input": source,
        "result": asdict(result), "before": before, "after": after})

    path = ROOT / "results/diagnostic_20261010/_probe_coverage_20261013T005231042394Z/summary.json"
    summary = json.loads(path.read_text())
    inputs = {Path(__file__), prior_path, path, ROOT / "pipeline/dev_probe.py",
              ROOT / "pipeline/tests/test_dev_probe.py", ROOT / "pipeline/probe_coverage_check.py"}
    for cid, row in summary["eligibility"].items():
        ctx_path = ROOT / f"benchmark/model_context/{cid}.json"
        inputs.add(ctx_path)
        ctx = json.loads(ctx_path.read_text())
        result = dp.build_probe(cid, row["language"], ctx["vulnerable_function"], ctx["patched_function"])
        assert isinstance(result, dp.ProbeResult) == row["eligible"]
        if row["eligible"]:
            for attr in ("vulnerable_probe", "patched_probe"):
                probe = ROOT / row[attr + "_path"]
                inputs.add(probe)
                assert probe.is_relative_to(path.parent / "_probe_inputs")
                assert sha(probe) == row[attr + "_sha256"]
                assert probe.read_text() == getattr(result, attr)
    counts, groups, failures = Counter(), {}, []
    for row in summary["per_episode"]:
        cid = row["case_id"]
        stdout = path.parent / row["model"].replace(":", "_") / row["condition"] / f'r{row["repeat"]}' / cid / "stdout.json"
        inputs.add(stdout)
        data = json.loads(stdout.read_text())
        assert data["version"] == "1.177.0" and not data["errors"]
        expected = {str((ROOT / summary["eligibility"][cid][k]).resolve()) for k in ("vulnerable_probe_path", "patched_probe_path")}
        assert expected <= set(data["paths"]["scanned"])
        hits = {finding["path"] for finding in data["results"]}
        v = str((ROOT / summary["eligibility"][cid]["vulnerable_probe_path"]).resolve()) in hits
        p = str((ROOT / summary["eligibility"][cid]["patched_probe_path"]).resolve()) in hits
        assert row["scan_ok"] and row["vulnerable_detected"] == v and row["patched_detected"] == p
        counts.update(total=1, passed=int(v and not p), missed=int(not v), patched_findings=int(p))
        groups.setdefault(row["model"] + " / " + row["condition"], Counter()).update(total=1, passed=int(v and not p), missed=int(not v))
        if not v or p:
            failures.append([row["model"], row["condition"], row["repeat"], cid])
    assert counts == {"total": 100, "passed": 94, "missed": 6, "patched_findings": 0}
    assert sorted(failures) == sorted(prior["failures"])
    eligible = [cid for cid, row in summary["eligibility"].items() if row["eligible"]]
    assert len(eligible) == 11
    changes = [p for p, digest in prior["reviewed_sha256"].items() if sha(ROOT / p) != digest]
    assert set(changes) == {"pipeline/dev_probe.py", "pipeline/tests/test_dev_probe.py"}
    report.update(coverage_counts=dict(counts), groups=groups, failures=failures,
        eligible_cases=eligible, accepted_episodes=195, uncovered_accepted=95,
        unchanged_failure_set=True, previous_reviewed_inputs_changed=changes,
        reviewed_sha256={str(p.relative_to(ROOT)):sha(p) for p in sorted(inputs)})
    out = Path(__file__).with_name("Dev_Probe_Round3_Evidence_20261013.json")
    with out.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("new_counterexamples", "reviewed_sha256")}, indent=2))
    print("Two additional behavior-changing accepted probes reproduced; evidence:",out.relative_to(ROOT))


if __name__ == "__main__":
    main()
