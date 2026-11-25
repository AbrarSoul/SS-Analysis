"""Follow-up review: retained scans, prior reproductions and remaining scope failures.

No model calls or Semgrep execution. Java/Python executions use tiny synthetic local fixtures.
Creates new evidence exclusively; never changes research inputs or historical results.
"""
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
import dev_probe as dp
import probe_coverage_check as pc


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def py_run(src, namespace):
    ns = dict(namespace)
    try:
        exec(src, ns)
        return {"value": ns["f"]()}
    except Exception as e:
        return {"error": type(e).__name__, "message": str(e)}


def main():
    prior_path = Path(__file__).with_name("Dev_Probe_Review_Evidence_20261013.json")
    prior = json.loads(prior_path.read_text())
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "model_calls": 0,
              "semgrep_scans": 0, "prior_counterexample_status": [], "remaining_counterexamples": []}
    inputs = {Path(__file__), prior_path, ROOT / "pipeline/dev_probe.py",
              ROOT / "pipeline/probe_coverage_check.py", ROOT / "pipeline/tests/test_dev_probe.py",
              ROOT / "autogrep/requirements.txt", ROOT / "pipeline/diagnostic_v2.py"}
    for old in prior["counterexamples"]:
        lang = old["result"]["language"]
        vuln = old.get("vulnerable_input", old.get("input", "def f():\n    token=1\n    return token\n"))
        patched = old.get("patched_input", vuln)
        if old["label"] == "invalid_patched_source_still_eligible":
            patched = "def f(:"
        r = dp.build_probe(old["label"], lang, vuln, patched)
        label = old["label"]
        if label in {"nested_local_changes_global_reference", "local_callee_reference_not_renamed",
                     "block_local_changes_global_reference", "eval_whitespace_bypasses_filter"}:
            assert isinstance(r, dp.ProbeIneligible)
            status = "fixed: rejected"
        elif label in {"patched_parameter_body_only_renamed", "patched_name_collision"}:
            assert isinstance(r, dp.ProbeResult) and r.patched_probe == patched
            status = "fixed counterexample: patched source unchanged"
        elif label == "java_public_interface_renamed":
            assert isinstance(r, dp.ProbeResult) and "int token()" in r.vulnerable_probe
            status = "fixed: method name preserved; runtime covered by current test suite"
        else:
            assert isinstance(r, dp.ProbeResult) and r.patched_probe == "def f(:"
            status = "still open: invalid patched source eligible"
        report["prior_counterexample_status"].append({"label": label, "status": status})

    examples = [
        ("patched_global_reference", "def f():\n    token = 1\n    return token\n",
         "def f():\n    return token\n", {"token": 7}),
        ("python_comprehension_scope", "def f():\n    [token for token in (1,2)]\n    return token\n",
         None, {"token": 10}),
        ("python_default_argument_scope", "def f(x=token):\n    token = 1\n    return x + token\n",
         None, {"token": 10}),
    ]
    for label, vuln, patched, ns in examples:
        r = dp.build_probe(label, "python", vuln, patched or vuln)
        assert isinstance(r, dp.ProbeResult)
        before = py_run(patched or vuln, ns)
        after = py_run(r.patched_probe if patched else r.vulnerable_probe, ns)
        assert "value" in before and after["error"] == "NameError"
        report["remaining_counterexamples"].append({"label": label, "vulnerable_input": vuln,
            "patched_input": patched or vuln, "namespace": ns, "result": asdict(r), "before": before, "after": after})

    method = "int f() { { int token = 1; } return token; }"
    r = dp.build_probe("java_block", "java", method, method)
    assert isinstance(r, dp.ProbeResult)
    with tempfile.TemporaryDirectory(prefix="probe-followup-") as temporary:
        base = Path(temporary)
        outcomes = []
        for name, source in (("Original", method), ("Renamed", r.vulnerable_probe)):
            cls = f"public class {name} {{ int token=10; {source} public static void main(String[] a) {{ System.out.println(new {name}().f()); }} }}"
            path = base / (name + ".java")
            path.write_text(cls)
            compile_ = subprocess.run(["javac", "-d", str(base), str(path)], capture_output=True, text=True, timeout=30)
            outcome = {"class_source": cls, "compile_exit": compile_.returncode, "stderr": compile_.stderr}
            if not compile_.returncode:
                run = subprocess.run(["java", "-cp", str(base), name], capture_output=True, text=True, timeout=30, check=True)
                outcome["stdout"] = run.stdout.strip()
            outcomes.append(outcome)
        assert outcomes[0]["stdout"] == "10" and outcomes[1]["compile_exit"] != 0
        assert "token_renamed" in outcomes[1]["stderr"]
        report["remaining_counterexamples"].append({"label": "java_block_local_vs_field",
            "result": asdict(r), "original": outcomes[0], "probe": outcomes[1]})
        fake = subprocess.CompletedProcess([], 0, json.dumps({"errors": [], "results": [], "paths": {"scanned": []}}), "")
        with patch.object(pc.subprocess, "run", return_value=fake):
            result = pc.scan_probe(base / "rule.yml", base / "v.py", base / "p.py", base / "mockscan")
        assert not result["scan_ok"]
        report["skipped_target_fix"] = result

    path = ROOT / "results/diagnostic_20261010/_probe_coverage_20261013T002146736021Z/summary.json"
    summary = json.loads(path.read_text())
    inputs.add(path)
    for cid, row in summary["eligibility"].items():
        context = ROOT / f"benchmark/model_context/{cid}.json"
        inputs.add(context)
        ctx = json.loads(context.read_text())
        r = dp.build_probe(cid, row["language"], ctx["vulnerable_function"], ctx["patched_function"])
        assert isinstance(r, dp.ProbeResult) == row["eligible"]
        if row["eligible"]:
            for attr in ("vulnerable_probe", "patched_probe"):
                source = ROOT / row[attr + "_path"]
                inputs.add(source)
                assert source.is_relative_to(path.parent / "_probe_inputs")
                assert sha(source) == row[attr + "_sha256"]
                assert source.read_text() == getattr(r, attr)
    counts, failures, groups = Counter(), [], {}
    for row in summary["per_episode"]:
        cid = row["case_id"]
        stdout = path.parent / row["model"].replace(":", "_") / row["condition"] / f'r{row["repeat"]}' / cid / "stdout.json"
        inputs.add(stdout)
        data = json.loads(stdout.read_text())
        assert data["version"] == "1.177.0" and not data["errors"]
        expected = {str((ROOT / summary["eligibility"][cid][k]).resolve()) for k in ("vulnerable_probe_path", "patched_probe_path")}
        assert expected <= set(data["paths"]["scanned"])
        hits = {item["path"] for item in data["results"]}
        v = str((ROOT / summary["eligibility"][cid]["vulnerable_probe_path"]).resolve()) in hits
        p = str((ROOT / summary["eligibility"][cid]["patched_probe_path"]).resolve()) in hits
        assert row["scan_ok"] and row["vulnerable_detected"] == v and row["patched_detected"] == p
        counts.update(total=1, passed=int(v and not p), missed=int(not v), patched_findings=int(p))
        groups.setdefault(row["model"] + " / " + row["condition"], Counter()).update(total=1, passed=int(v and not p), missed=int(not v))
        if not v or p:
            failures.append((row["model"], row["condition"], row["repeat"], cid))
    old_failures = [(r["model"], r["condition"], r["repeat"], r["case_id"]) for r in prior["failures"]]
    assert sorted(failures) == sorted(old_failures)
    assert counts == {"total": 104, "passed": 98, "missed": 6, "patched_findings": 0}
    eligible = [cid for cid, row in summary["eligibility"].items() if row["eligible"]]
    assert len(eligible) == 13
    old_inputs_changed = [p for p, digest in prior["reviewed_sha256"].items() if sha(ROOT / p) != digest]
    assert set(old_inputs_changed) == {"pipeline/dev_probe.py", "pipeline/probe_coverage_check.py",
                                     "pipeline/tests/test_dev_probe.py", "autogrep/requirements.txt"}
    report.update(counts=dict(counts), groups=groups, failures=failures, unchanged_failure_set=True,
        eligible_cases=eligible, accepted_episodes=195, covered_accepted=104, uncovered_accepted=91,
        previous_audit_files_changed=old_inputs_changed,
        reviewed_sha256={str(p.relative_to(ROOT)):sha(p) for p in sorted(inputs)})
    out = Path(__file__).with_name("Dev_Probe_Followup_Evidence_20261013.json")
    with out.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("reviewed_sha256", "remaining_counterexamples")}, indent=2))
    print("Four further scope failures and the still-open invalid-patched case reproduced; evidence:",out.relative_to(ROOT))


if __name__ == "__main__":
    main()
