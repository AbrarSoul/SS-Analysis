"""Verify fixed repros, immutable edit report, exact edit spans, and saved coverage.

No model calls or Semgrep execution; new evidence written exclusively. Exact-span validation
uses source diffs, independently of the builder's replacement/isomorphism implementation.
"""
from collections import Counter
from datetime import datetime, timezone
import difflib
import hashlib
import json
from pathlib import Path
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
import dev_probe as dp
import probe_binding_audit_report as pa


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def textsha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def spans(source, output, old, new):
    """All reviewed replacements append _renamed; verify no other normalized-source edits."""
    assert new == old + "_renamed"
    changes = []
    for tag, start, end, out_start, out_end in difflib.SequenceMatcher(None, source, output, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        assert tag == "insert" and start == end and output[out_start:out_end] == "_renamed"
        identifier_start = start-len(old)
        assert source[identifier_start:start] == old
        assert identifier_start == 0 or not (source[identifier_start-1].isalnum() or source[identifier_start-1] == "_")
        assert start == len(source) or not (source[start].isalnum() or source[start] == "_")
        changes.append({"start_character": identifier_start, "end_character": start,
            "line": source.count("\n", 0, identifier_start)+1,
            "column_0_based": identifier_start-source.rfind("\n", 0, identifier_start)-1,
            "old": old, "new": new})
    return changes


def main():
    base = ROOT / "Research_Log/Diagnostic_20261010"
    prior_path = base / "Binding_Form_Audit_Review_Evidence_20261013.json"
    prior = json.loads(prior_path.read_text())
    repros = []
    for case in prior["counterexamples"]:
        result = dp.build_probe(case["label"], case["result"]["language"], case["input"], case["input"])
        assert isinstance(result, dp.ProbeIneligible)
        repros.append({"label": case["label"], "result": "ineligible"})
    # Directly cover the for-target row: unlike the permanent mixed fixture, no earlier
    # simple assignment can be chosen instead of the loop target.
    loop = "def f(items):\n    for token in items:\n        return token\n    return 0\n"
    result = dp.build_probe("for_target", "python", loop, loop)
    assert isinstance(result, dp.ProbeResult) and result.old_name == "token"
    a, b = {}, {}
    exec(loop, a)
    exec(result.vulnerable_probe, b)
    assert a["f"]([5, 6]) == b["f"]([5, 6]) == 5
    nonlocal_src = "def f():\n    nonlocal token\n    token=8\n    return token\n"
    assert isinstance(dp.build_probe("nonlocal", "python", nonlocal_src, nonlocal_src), dp.ProbeIneligible)

    edit_path = base / "Dev_Probe_Binding_Audit_Decisions_20261013T090739177579Z.json"
    edit_rows = json.loads(edit_path.read_text())
    summary_path = ROOT / "results/diagnostic_20261010/_probe_coverage_20261013T090920800445Z/summary.json"
    summary = json.loads(summary_path.read_text())
    audit_doc = base / "Dev_Probe_Binding_Form_Audit_20261013.md"
    inputs = {Path(__file__), prior_path, edit_path, summary_path, audit_doc,
              ROOT / "pipeline/dev_probe.py", ROOT / "pipeline/probe_binding_audit_report.py",
              ROOT / "pipeline/tests/test_dev_probe.py"}
    assert sha(ROOT / "pipeline/dev_probe.py") == "d2d7364a77670e6d448da82bdf895a33aca785e9e08d1fe1941e5fae2af88114"
    assert sha(ROOT / "pipeline/dev_probe.py") in audit_doc.read_text()
    independently_checked = []
    for row in edit_rows:
        cid = row["case_id"]
        ctx_path = ROOT / f"benchmark/model_context/{cid}.json"
        inputs.add(ctx_path)
        ctx = json.loads(ctx_path.read_text())
        assert pa.audit_case(cid, row["language"], ctx["vulnerable_function"], ctx["patched_function"]) == row
        e = summary["eligibility"][cid]
        assert e["eligible"] == row["eligible"]
        if not row["eligible"]:
            continue
        checked = {"case_id": cid, "language": row["language"], "sides": {}}
        for side in ("vulnerable", "patched"):
            source = ctx[side + "_function"]
            p = ROOT / e[side + "_probe_path"]
            inputs.add(p)
            output = p.read_text()
            assert textsha(source) == row[side + "_function_sha256"]
            assert sha(p) == row[side + "_probe_sha256"] == e[side + "_probe_sha256"]
            diff = list(difflib.unified_diff(source.splitlines(), output.splitlines(), lineterm="", n=0))
            assert diff == row[side + "_diff"]
            unchanged = side == "patched" and not row["patched_probe_renamed"]
            if unchanged:
                assert source == output
                normalized = source
                edits = []
            else:
                normalized = textwrap.dedent(source).strip() if row["language"] == "python" else source
                edits = spans(normalized, output, row["old_name"], row["new_name"])
                assert edits
                assert row["new_name"] not in normalized
            checked["sides"][side] = {"unchanged": unchanged,
                "normalization": "dedent-and-strip" if normalized != source else "none",
                "normalized_source_sha256": textsha(normalized), "edits": edits}
        independently_checked.append(checked)
    assert len(edit_rows) == 24 and len(independently_checked) == 11
    counts, failures = Counter(), []
    for row in summary["per_episode"]:
        e = summary["eligibility"][row["case_id"]]
        raw = summary_path.parent / row["model"].replace(":", "_") / row["condition"] / f'r{row["repeat"]}' / row["case_id"] / "stdout.json"
        inputs.add(raw)
        data = json.loads(raw.read_text())
        assert data["version"] == "1.177.0" and not data["errors"]
        v,p = [str((ROOT / e[k]).resolve()) for k in ("vulnerable_probe_path", "patched_probe_path")]
        assert {v,p} <= set(data["paths"]["scanned"])
        hits = {r["path"] for r in data["results"]}
        vh,ph = v in hits,p in hits
        assert row["scan_ok"] and row["vulnerable_detected"] == vh and row["patched_detected"] == ph
        counts.update(total=1, passed=int(vh and not ph), missed=int(not vh), patched_findings=int(ph))
        if not vh or ph:
            failures.append([row["model"],row["condition"],row["repeat"],row["case_id"]])
    assert counts == prior["coverage_counts"] and sorted(failures) == sorted(prior["failures"])
    report = {"created_utc":datetime.now(timezone.utc).isoformat(),"model_calls":0,"semgrep_scans":0,
        "fixed_reproductions":repros,"coverage_counts":dict(counts),"failures":failures,
        "edit_audit_rows_verified":24,"exact_span_checks":independently_checked,
        "additional_checks":["for target itself selected and behavior preserved","nonlocal candidate rejected"],
        "scope":"Source-diff verification plus manual case review; not a general binding-safety proof.",
        "tests":"46 probe tests passed in 1.09s; full suite not rerun",
        "reviewed_sha256":{str(p.relative_to(ROOT)):sha(p) for p in sorted(inputs)}}
    output=base / "Binding_Form_Audit_Closure_Evidence_20261013.json"
    with output.open("x") as f:
        json.dump(report,f,indent=2)
        f.write("\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("reviewed_sha256","exact_span_checks")},indent=2))
    print("Exact normalized-source identifier spans verified for 11 probe pairs.")


if __name__ == "__main__":
    main()
