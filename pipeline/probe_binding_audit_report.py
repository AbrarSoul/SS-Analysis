"""
Bounded binding-safety audit (2026-10-13), deliverable 3: "A review of the actual generated
probes. Record the exact replacements and rejection reasons across the 24 development cases."

REWRITTEN 2026-10-13 in response to Binding_Form_Audit_Review_20261013.md Finding 3: the first
version recorded only case/language/eligible/old_name/new_name -- a decision inventory, not an
edit audit. This version additionally records: (a) a line-level diff of vulnerable_function ->
vulnerable_probe and patched_function -> patched_probe for every eligible case, so the exact
edit spans are independently reviewable without re-running the builder; (b) SHA-256 of every
input/output source, for provenance; (c) for every INELIGIBLE case, a per-raw-candidate exclusion
classification (which specific check rejected each candidate the builder considered and discarded,
not just the overall generic reason string). Output is written to a NEW TIMESTAMPED file every run
(never overwrites a fixed filename -- the prior version's "writes nothing" docstring was wrong,
since it unconditionally overwrote one fixed path; fixed here too).

No model calls, no Semgrep scans -- this only calls `build_probe()` (pure, offline) plus a few of
dev_probe.py's already-existing private helper functions, against the same 24-case development
selection used by `probe_coverage_check.py`.

Usage:
    python pipeline/probe_binding_audit_report.py
"""
import ast
import difflib
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
from eligible_cases import load_manifest
import dev_probe as dp
from dev_probe import build_probe, ProbeResult, ProbeIneligible


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _unified_diff(old_text: str, new_text: str) -> list:
    return list(difflib.unified_diff(old_text.splitlines(), new_text.splitlines(), lineterm="", n=0))


def _py_raw_candidate_names(vulnerable_function: str) -> list:
    """Diagnostic-only reimplementation, deliberately simple: every name EVER assigned (Store
    context) anywhere in the parsed function, at ANY nesting depth -- an over-approximation of
    `_py_candidate_locals`'s real (scope-aware) raw walk, used here only to enumerate "what did the
    builder even consider and reject," never to make an actual accept/reject decision. Returns []
    if the source does not parse (the caller already reports that as a parse failure)."""
    try:
        tree, _ = dp._py_parse(vulnerable_function)
    except SyntaxError:
        return []
    func = dp._py_find_function(tree)
    if func is None:
        return []
    names, seen = [], set()
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id not in seen:
            names.append(node.id)
            seen.add(node.id)
    return names


def _py_classify_exclusion(func, name: str) -> list:
    reasons = []
    if name in dp._py_param_names(func):
        reasons.append("parameter")
    if name in dp._py_names_touched_in_nested_scopes(func):
        reasons.append("touched-in-nested-scope-or-comprehension-or-nested-def/class-name")
    if name in dp._py_global_nonlocal_names(func):
        reasons.append("global/nonlocal-declared")
    if name in dp._py_names_in_signature(func):
        reasons.append("used-in-parameter-default/annotation/decorator-expression")
    if name in dp._py_exception_bound_names(func):
        reasons.append("except-as-binding")
    if name in dp._py_import_bound_names(func):
        reasons.append("import-alias-binding")
    if name in dp._py_match_bound_names(func):
        reasons.append("match-case-capture-binding")
    if dp._py_string_literal_contains(func, name):
        reasons.append("reachable-via-string-literal")
    return reasons or ["not-a-recognized-own-scope-Store-target (e.g. tuple/list-unpack, walrus, comprehension-only, import/match/def name itself)"]


def _ts_classify_exclusion(func, name: str, language: str) -> list:
    reasons = []
    if name in dp._ts_param_names(func, language):
        reasons.append("parameter")
    if name in dp._ts_names_in_signature_defaults(func, language):
        reasons.append("used-in-parameter-default-expression")
    if dp._ts_string_literal_contains(func, name):
        reasons.append("reachable-via-string-literal")
    if dp._ts_shadowed_in_nested_function(func, name, language):
        reasons.append("shadowed-by-or-touched-in-a-nested-function")
    if dp._ts_block_scoped_outside_function_body(func, name, language):
        reasons.append("block-scoped-declaration-outside-function-body")
    if language != "java" and dp._ts_is_called_as_bare_function(func, name):
        reasons.append("called-as-a-bare-function-elsewhere")
    if dp._ts_has_same_named_declaration(func, name):
        reasons.append("same-named-nested-function/class-declaration-exists")
    if dp._ts_has_shorthand_property(func, name):
        reasons.append("used-as-a-shorthand-object-property-or-destructuring-pattern")
    return reasons or ["eligible-but-not-first-tried (an earlier candidate was selected first)"]


def audit_case(cid, language, vulnerable_function, patched_function):
    result = build_probe(cid, language, vulnerable_function, patched_function)
    row = {"case_id": cid, "language": language,
           "vulnerable_function_sha256": _sha256(vulnerable_function),
           "patched_function_sha256": _sha256(patched_function)}

    if isinstance(result, ProbeResult):
        row.update({
            "eligible": True, "old_name": result.old_name, "new_name": result.new_name,
            "patched_probe_renamed": result.patched_probe_renamed,
            "vulnerable_probe_sha256": _sha256(result.vulnerable_probe),
            "patched_probe_sha256": _sha256(result.patched_probe),
            "vulnerable_diff": _unified_diff(vulnerable_function, result.vulnerable_probe),
            "patched_diff": _unified_diff(patched_function, result.patched_probe),
        })
        return row

    assert isinstance(result, ProbeIneligible)
    row["eligible"] = False
    row["reason"] = result.reason
    if "does not parse" in result.reason:
        row["candidate_classification"] = []
        return row

    if language == "python":
        tree, _ = dp._py_parse(vulnerable_function)
        func = dp._py_find_function(tree)
        raw_candidates = _py_raw_candidate_names(vulnerable_function)
        classify = lambda n: _py_classify_exclusion(func, n)
    else:
        tree, func, _ = dp._ts_parse_function_src(vulnerable_function, language)
        raw_candidates = dp._ts_collect_declared_locals(func, language) if func is not None else []
        classify = lambda n: _ts_classify_exclusion(func, n, language)

    row["candidate_classification"] = [{"candidate": n, "excluded_because": classify(n)} for n in raw_candidates]
    return row


def main():
    manifest = load_manifest()
    selection = json.loads((ROOT / "results/diagnostic_20261010/qwen3_v3/selection.json").read_text())
    ids = sorted(selection["case_ids"])

    rows = []
    for cid in ids:
        language = manifest[cid]["language"]
        ctx = json.loads((ROOT / f"benchmark/model_context/{cid}.json").read_text())
        rows.append(audit_case(cid, language, ctx["vulnerable_function"], ctx["patched_function"]))

    print(f"{'case_id':12s} {'language':12s} {'eligible':9s} summary")
    for r in rows:
        if r["eligible"]:
            summary = f"renamed {r['old_name']!r} -> {r['new_name']!r}; patched_renamed={r['patched_probe_renamed']}"
        else:
            n_candidates = len(r.get("candidate_classification", []))
            summary = f"REJECTED ({r['reason']}); {n_candidates} raw candidate(s) classified"
        print(f"{r['case_id']:12s} {r['language']:12s} {str(r['eligible']):9s} {summary}")

    n_eligible = sum(1 for r in rows if r["eligible"])
    print(f"\n{n_eligible}/{len(rows)} cases eligible.")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out_path = ROOT / f"Research_Log/Diagnostic_20261010/Dev_Probe_Binding_Audit_Decisions_{timestamp}.json"
    out_path.write_text(json.dumps(rows, indent=2))
    print(f"\nFull per-case edit audit (diffs, hashes, exclusion classification) written to {out_path}")


if __name__ == "__main__":
    main()
