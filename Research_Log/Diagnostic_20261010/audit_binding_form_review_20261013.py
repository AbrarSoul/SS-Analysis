"""Verify binding-audit artifacts and reproduce boundary failures; no model/Semgrep calls."""
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
from dev_probe import build_probe, ProbeResult


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "model_calls": 0,
              "semgrep_scans": 0, "counterexamples": []}
    for label, src in [
        ("js_destructuring_declaration", "function f(obj) { var token=1; var {token}=obj; return token; }"),
        ("js_destructuring_assignment", "function f(obj) { var token=1; ({token}=obj); return token; }"),
    ]:
        r = build_probe(label, "javascript", src, src)
        assert isinstance(r, ProbeResult)
        values = []
        for s in (src, r.vulnerable_probe):
            p = subprocess.run(["node", "-e", s+";console.log(f({token:99}));"], capture_output=True, text=True, timeout=30, check=True)
            values.append(p.stdout.strip())
        assert values == ["99", "1"]
        report["counterexamples"].append({"label": label, "input": src, "result": asdict(r), "outputs": values})
    src = "@decorate(token)\ndef f():\n    token = 1\n    return token\n"
    r = build_probe("python_decorator", "python", src, src)
    assert isinstance(r, ProbeResult)
    values = []
    for s in (src, r.vulnerable_probe):
        namespace = {"token": 10, "decorate": lambda value: lambda fn: fn}
        try:
            exec(s, namespace)
            values.append({"value": namespace["f"]()})
        except Exception as error:
            values.append({"error": type(error).__name__, "message": str(error)})
    assert values[0] == {"value": 1} and values[1]["error"] == "NameError"
    report["counterexamples"].append({"label": "python_decorator", "input": src, "result": asdict(r), "outputs": values})

    base = ROOT / "Research_Log/Diagnostic_20261010"
    audit_doc = base / "Dev_Probe_Binding_Form_Audit_20261013.md"
    decisions_path = base / "Dev_Probe_Binding_Audit_Decisions_20261013.json"
    decisions = json.loads(decisions_path.read_text())
    prior_path = base / "Dev_Probe_Closure_Evidence_20261013.json"
    prior = json.loads(prior_path.read_text())
    path = ROOT / "results/diagnostic_20261010/_probe_coverage_20261013T014605839062Z/summary.json"
    summary = json.loads(path.read_text())
    inputs = {Path(__file__), path, audit_doc, decisions_path, prior_path,
              ROOT / "pipeline/dev_probe.py", ROOT / "pipeline/probe_binding_audit_report.py",
              ROOT / "pipeline/tests/test_dev_probe.py", ROOT / "autogrep/requirements.txt"}
    assert sha(ROOT / "pipeline/dev_probe.py") == "120bd1ea86c355ef57b9cad26588c30f1c4eee5ccbaf21407beb6c85739132aa"
    assert sha(ROOT / "pipeline/dev_probe.py") in audit_doc.read_text()
    regenerated = []
    for cid, row in summary["eligibility"].items():
        ctx_path = ROOT / f"benchmark/model_context/{cid}.json"
        inputs.add(ctx_path)
        ctx = json.loads(ctx_path.read_text())
        r = build_probe(cid, row["language"], ctx["vulnerable_function"], ctx["patched_function"])
        assert isinstance(r, ProbeResult) == row["eligible"]
        decision = {"case_id": cid, "language": row["language"], "eligible": row["eligible"]}
        if row["eligible"]:
            decision.update(old_name=r.old_name, new_name=r.new_name, patched_probe_renamed=r.patched_probe_renamed)
            for side in ("vulnerable_probe", "patched_probe"):
                p = ROOT / row[side + "_path"]
                inputs.add(p)
                assert sha(p) == row[side + "_sha256"] and p.read_text() == getattr(r, side)
        else:
            decision["reason"] = r.reason
        regenerated.append(decision)
    assert regenerated == decisions and len(decisions) == 24
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
    assert counts == prior["coverage_counts"] and sorted(failures) == sorted(prior["failures"])
    assert sum(r["eligible"] for r in decisions) == 11
    changed = [p for p, digest in prior["reviewed_sha256"].items() if sha(ROOT / p) != digest]
    assert set(changed) == {"pipeline/dev_probe.py", "pipeline/tests/test_dev_probe.py"}
    report.update(coverage_counts=dict(counts), failures=failures, eligibility="11/24",
        covered_accepted="100/195", uncovered_accepted=95, per_case_decisions_reproduced=True,
        frozen_builder_hash_matches=True, previous_reviewed_inputs_changed=changed,
        versions={"python": platform.python_version(), **{p:version(p) for p in
            ("tree_sitter", "tree_sitter_java", "tree_sitter_javascript", "tree_sitter_typescript")}},
        tests="38 probe tests passed in 1.59s; full 82-test suite not rerun",
        reviewed_sha256={str(p.relative_to(ROOT)):sha(p) for p in sorted(inputs)})
    out = base / "Binding_Form_Audit_Review_Evidence_20261013.json"
    with out.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("counterexamples", "reviewed_sha256")}, indent=2))
    print("Counterexamples retained:",len(report["counterexamples"]))


if __name__ == "__main__":
    main()
