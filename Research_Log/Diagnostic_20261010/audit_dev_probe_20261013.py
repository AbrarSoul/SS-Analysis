"""Read-only probe review plus executable counterexamples; no model calls or Semgrep runs.

Writes a new evidence JSON exclusively. Synthetic fixtures execute only arithmetic/local code.
This reproduces the reviewed defects; it is not the corrected implementation's regression suite.
"""
import ast
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def python_outcome(source, args="", globals_=None):
    namespace = dict(globals_ or {})
    try:
        exec(source, namespace)
        return {"value": eval(f"f({args})", namespace)}
    except Exception as error:
        return {"error": type(error).__name__, "message": str(error)}


def javascript_outcome(source):
    script = "globalThis.token=10;" + source + "\ntry { console.log(JSON.stringify({value:f()})); } catch(e) { console.log(JSON.stringify({error:e.name,message:e.message})); }"
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def main():
    evidence = {"created_utc": datetime.now(timezone.utc).isoformat(),
                "new_model_calls": 0, "new_semgrep_scans": 0, "counterexamples": []}
    python_examples = [
        ("nested_local_changes_global_reference", "def f():\n    def g():\n        token = 1\n        return token\n    return token + g()\n", None, "", {"token": 10}),
        ("patched_parameter_body_only_renamed", "def f():\n    token = 1\n    return token\n", "def f(token):\n    return token\n", "7", None),
        ("patched_name_collision", "def f():\n    token = 1\n    return token\n", "def f():\n    token = 1\n    token_renamed = 2\n    return token + token_renamed\n", "", None),
    ]
    for label, vulnerable, patched, args, namespace in python_examples:
        result = dp.build_probe(label, "python", vulnerable, patched or vulnerable)
        assert isinstance(result, dp.ProbeResult)
        before = python_outcome(patched or vulnerable, args, namespace)
        after = python_outcome(result.patched_probe if patched else result.vulnerable_probe, args, namespace)
        assert before != after
        evidence["counterexamples"].append({"label": label, "vulnerable_input": vulnerable,
            "patched_input": patched or vulnerable, "result": asdict(result), "before": before, "after": after})
    for label, source in [
        ("local_callee_reference_not_renamed", "function f() { const cb = () => 7; return cb(); }"),
        ("block_local_changes_global_reference", "function f() { { let token = 1; } return token; }"),
        ("eval_whitespace_bypasses_filter", "function f() { let token = 7; const text = String.fromCharCode(116,111,107,101,110); return eval (text); }"),
    ]:
        result = dp.build_probe(label, "javascript", source, source)
        assert isinstance(result, dp.ProbeResult)
        before, after = javascript_outcome(source), javascript_outcome(result.vulnerable_probe)
        assert before != after
        evidence["counterexamples"].append({"label": label, "input": source, "result": asdict(result), "before": before, "after": after})
    source = "int token() { int token = 1; return token; }"
    result = dp.build_probe("java_method_name", "java", source, source)
    assert isinstance(result, dp.ProbeResult) and "int token_renamed()" in result.vulnerable_probe
    evidence["counterexamples"].append({"label": "java_public_interface_renamed", "input": source,
        "result": asdict(result), "verification": "source/CST inspection; no Java compilation claimed"})
    result = dp.build_probe("invalid_patched", "python", "def f():\n    token=1\n    return token\n", "def f(:")
    assert isinstance(result, dp.ProbeResult) and not result.patched_probe_renamed
    try:
        ast.parse(result.patched_probe)
    except SyntaxError:
        evidence["counterexamples"].append({"label": "invalid_patched_source_still_eligible", "result": asdict(result)})
    else:
        raise AssertionError("Expected invalid patched source")
    with tempfile.TemporaryDirectory(prefix="probe-review-") as temporary:
        base = Path(temporary)
        fake = subprocess.CompletedProcess([], 0, json.dumps({"errors": [], "results": [], "paths": {"scanned": []}}), "")
        with patch.object(pc.subprocess, "run", return_value=fake):
            result = pc.scan_probe(base / "rule.yml", base / "vulnerable.py", base / "patched.py", base / "scan")
        assert result["scan_ok"]
        evidence["skipped_targets_mock"] = result

    coverage = ROOT / "results/diagnostic_20261010/_probe_coverage_20261012T233737252844Z/summary.json"
    summary = json.loads(coverage.read_text())
    inputs = {Path(__file__), ROOT / "pipeline/dev_probe.py", ROOT / "pipeline/probe_coverage_check.py",
              ROOT / "pipeline/tests/test_dev_probe.py", ROOT / "pipeline/diagnostic_v2.py",
              ROOT / "autogrep/requirements.txt", coverage}
    counts, group_counts, failures = Counter(), {}, []
    for row in summary["per_episode"]:
        cid = row["case_id"]
        stdout = coverage.parent / row["model"].replace(":", "_") / row["condition"] / f'r{row["repeat"]}' / cid / "stdout.json"
        inputs.add(stdout)
        data = json.loads(stdout.read_text())
        assert data["version"] == "1.177.0" and not data["errors"]
        paths = {str((ROOT / summary["eligibility"][cid][key]).resolve()) for key in ("vulnerable_probe_path", "patched_probe_path")}
        assert paths <= {str(Path(p).resolve()) for p in data["paths"]["scanned"]}
        findings = {str(Path(r["path"]).resolve()) for r in data["results"]}
        vulnerable = str((ROOT / summary["eligibility"][cid]["vulnerable_probe_path"]).resolve()) in findings
        patched = str((ROOT / summary["eligibility"][cid]["patched_probe_path"]).resolve()) in findings
        assert row["scan_ok"] and row["vulnerable_detected"] == vulnerable and row["patched_detected"] == patched
        counts.update(total=1, passed=int(vulnerable and not patched), missed=int(not vulnerable), false_positive=int(patched))
        key = row["model"] + " / " + row["condition"]
        group_counts.setdefault(key, Counter()).update(total=1, passed=int(vulnerable and not patched), missed=int(not vulnerable))
        rule = Path(row["rule_path"])
        episode = rule.parent / "episode.json"
        inputs.update((rule, episode))
        ep = json.loads(episode.read_text())
        assert ep["iterative"]["visible_correct"] and ep["final_rule_sha256"] == sha(rule)
        if not vulnerable or patched:
            failures.append({**row, "calls_already_used": ep["calls_recorded"], "hidden_outcomes":
                [{"sample_type": s["sample_type"], "outcome": s["outcome"]} for s in ep["iterative"]["samples"]]})
    assert counts == {"total": 116, "passed": 110, "missed": 6, "false_positive": 0}
    eligible = []
    for cid, row in summary["eligibility"].items():
        context = ROOT / f"benchmark/model_context/{cid}.json"
        inputs.add(context)
        ctx = json.loads(context.read_text())
        result = dp.build_probe(cid, row["language"], ctx["vulnerable_function"], ctx["patched_function"])
        assert isinstance(result, dp.ProbeResult) == row["eligible"]
        if row["eligible"]:
            eligible.append(cid)
            for attr in ("vulnerable_probe", "patched_probe"):
                probe = ROOT / row[attr + "_path"]
                inputs.add(probe)
                assert probe.read_text() == getattr(result, attr)
    all_episodes = sorted(ROOT.glob("results/diagnostic_20261010/ab_dev_20261012_v1_*/*/episode.json"))
    assert len(all_episodes) == 288
    inputs.update(all_episodes)
    accepted = sum(bool(json.loads(p.read_text())["final_rule_path"]) for p in all_episodes)
    assert accepted == 195
    evidence.update(coverage_summary=str(coverage.relative_to(ROOT)), counts=dict(counts),
        groups=group_counts, failures=failures, eligible_cases=eligible,
        eligible_case_count=len(eligible), accepted_episodes_all_cases=accepted,
        accepted_without_eligible_probe=accepted-counts["total"],
        patched_unchanged=[cid for cid, row in summary["eligibility"].items() if row["eligible"] and not row["patched_probe_renamed"]],
        installed_versions={p: version(p) for p in ("tree_sitter", "tree_sitter_java", "tree_sitter_javascript", "tree_sitter_typescript")})
    allocation = ROOT / "Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/allocation.json"
    allocated = json.loads(allocation.read_text())["input_sha256"]
    assert all(sha(ROOT / p) == digest for p, digest in allocated.items())
    evidence["allocation_inputs_unchanged"] = True
    evidence["reviewed_sha256"] = {str(p.relative_to(ROOT)): sha(p) for p in sorted(inputs)}
    output = Path(__file__).with_name("Dev_Probe_Review_Evidence_20261013.json")
    with output.open("x") as handle:
        json.dump(evidence, handle, indent=2)
        handle.write("\n")
    print(json.dumps({key: value for key, value in evidence.items() if key not in ("reviewed_sha256", "counterexamples", "failures")}, indent=2))
    print(f"Counterexamples retained: {len(evidence['counterexamples'])}; evidence: {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
