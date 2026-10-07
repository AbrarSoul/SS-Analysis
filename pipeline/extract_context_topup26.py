"""
Design doc Section 8 Step 5 for the 300-case FINAL dataset (Phase 4):
extract fixed model context (vulnerable/patched function, imports,
containing class, CVE/CWE) for every case that survived Step 3 + Step 4.

Unlike the pilot's per-language scripts (extract_context_python.py /
extract_context_java.py / extract_context_js_ts.py), which used a
hand-curated case_id -> target mapping, this uses auto_locate_target.py to
derive the target function automatically from each case's own patch.diff --
verified against the pilot's 40 hand-checked cases first (see
verify_auto_locate_against_pilot.py: 24/40 exact match, with the rest
falling into well-understood categories, not silent failures).

Every case is written to model_context_topup26/, tagged with a confidence
level:
  - "auto": exactly one function resolved the diff's changes, or one
    candidate was clearly favored over any runner-up (>=2x the changed-line
    weight) -- used as-is.
  - "auto_low_confidence": a function WAS found, but a close runner-up
    candidate existed (ambiguous which one a human would have picked) --
    written with the same content, but flagged for a quick manual check
    rather than silently trusted.
  - "needs_manual": auto-location could not resolve any function at all
    (e.g. the diff doesn't touch any existing function -- verified during
    development that this has no single safe automatic fallback: the
    pilot's own hand answers for this exact situation differed case by
    case, CASE-0010 used the whole file, CASE-0026 used just the changed
    statement). These cases get a manual_review record instead of a
    model_context file, with the diff and metadata a human needs to decide
    quickly.
"""
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auto_locate_target import (
    all_hunk_targets, locate_python, locate_java, locate_js_ts, AutoLocateError,
)

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
STEP3_DIR = BENCH_DIR / "step3_repo_states_topup26"
STEP3_RESULTS_CSV = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4" / "step3_results_topup26.csv"
CWE_DEFS = json.loads((BENCH_DIR / "cwe_definitions.json").read_text())

OUT_DIR = BENCH_DIR / "model_context_topup26"
MANUAL_REVIEW_FILE = BENCH_DIR / "step5_needs_manual_review_topup26.json"

LOCATOR_BY_LANG = {
    "python": locate_python,
    "java": locate_java,
    "javascript": locate_js_ts,
    "typescript": locate_js_ts,
}

# Confidence check needs to see BOTH the winner and runner-up weights, which
# _best_across_hunks() (built for the verification harness, where only the
# winner mattered) doesn't expose -- reimplemented here as a thin wrapper
# rather than changing that function's return shape and risking the
# already-verified behavior it's relied on for.


def _locate_with_confidence(locator, source: str, hunks: list, side: str):
    """Returns (result, confidence) where confidence is "auto",
    "auto_low_confidence", or raises AutoLocateError."""
    # Reuse the real locator logic by calling it once for the winning
    # answer (unchanged, already-verified path)...
    result = locator(source, hunks, side)
    # ...then separately tally each hunk's OWN resolution to see whether a
    # close runner-up existed, without touching the verified selection
    # logic itself.
    if locator is locate_python:
        import ast
        tree = ast.parse(source)

        def resolve_one(hunk):
            target_line = hunk.old_line if side == "old" else hunk.new_line
            candidates = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.lineno <= target_line <= node.end_lineno:
                        candidates.append((node.end_lineno - node.lineno, node))
            if not candidates:
                raise AutoLocateError("no function")
            candidates.sort(key=lambda t: t[0])
            n = candidates[0][1]
            return n.lineno, n.end_lineno, None
    else:
        from auto_locate_target import enumerate_brace_blocks, _looks_method_like
        blocks = enumerate_brace_blocks(source)

        def resolve_one(hunk):
            target_line = hunk.old_line if side == "old" else hunk.new_line
            candidates = [b for b in blocks if b.start_line <= target_line <= b.end_line and _looks_method_like(b.opening_context)]
            if not candidates:
                raise AutoLocateError("no block")
            candidates.sort(key=lambda b: b.end_line - b.start_line)
            b = candidates[0]
            return b.start_line, b.end_line, None

    by_span = {}
    for h in hunks:
        try:
            start, end, _ = resolve_one(h)
        except AutoLocateError:
            continue
        by_span.setdefault((start, end), 0)
        by_span[(start, end)] += h.changed_line_count

    if len(by_span) <= 1:
        return result, "auto"
    weights = sorted(by_span.values(), reverse=True)
    if weights[0] >= 2 * weights[1]:
        return result, "auto"
    return result, "auto_low_confidence"


def get_imports_python(source: str) -> list:
    import ast
    tree = ast.parse(source)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append(f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""))
        elif isinstance(node, ast.ImportFrom) and node.col_offset == 0:
            names = ", ".join(a.name + (f" as {a.asname}" if a.asname else "") for a in node.names)
            out.append(f"from {'.' * (node.level or 0)}{node.module or ''} import {names}")
    return out


def get_imports_brace_lang(source: str) -> list:
    import re
    out = []
    for line in source.splitlines():
        s = line.strip()
        if s.startswith("import "):
            out.append(s)
        elif re.match(r"^(const|let|var)\s+.*=\s*require\(", s):
            out.append(s)
    return out


def main():
    with open(STEP3_RESULTS_CSV) as f:
        ok_case_ids = {row["filename"].replace(".patch", "") for row in csv.DictReader(f) if row["status"] == "ok"}
    print(f"{len(ok_case_ids)} cases with status=ok from Step 3")

    # Clear stale output from a prior run rather than just overwriting what
    # this run produces: a case that used to resolve but is now correctly
    # excluded (e.g. by the size gate below) would otherwise leave its OLD,
    # since-invalidated file sitting there untouched -- found live: after
    # first adding the size gate, the combined case counts looked
    # unchanged, which turned out to be exactly this masking the real
    # effect of the fix (agenticmail's known-bad 1214-line extraction was
    # still present in model_context_topup26/ from before the gate existed).
    if OUT_DIR.exists():
        for f in OUT_DIR.glob("*.json"):
            f.unlink()
    OUT_DIR.mkdir(exist_ok=True)
    manual_review = []
    counts = {"auto": 0, "auto_low_confidence": 0, "needs_manual": 0}

    for case_id in sorted(ok_case_ids):
        case_dir = STEP3_DIR / case_id
        metadata = json.loads((case_dir / "metadata.json").read_text())
        language = metadata["language"]
        diff_text = (case_dir / "patch.diff").read_text()
        vuln_src = (case_dir / "vulnerable_source").read_text()
        patched_src = (case_dir / "patched_source").read_text()

        locator = LOCATOR_BY_LANG[language]

        try:
            hunks = all_hunk_targets(diff_text)
            (vuln_text, class_name), confidence_v = _locate_with_confidence(locator, vuln_src, hunks, "old")
            (patched_text, _), confidence_p = _locate_with_confidence(locator, patched_src, hunks, "new")
        except AutoLocateError as e:
            manual_review.append({"case_id": case_id, "language": language,
                                   "repository": metadata["repository"], "error": str(e)})
            counts["needs_manual"] += 1
            continue
        except Exception as e:
            manual_review.append({"case_id": case_id, "language": language,
                                   "repository": metadata["repository"], "error": f"{type(e).__name__}: {e}"})
            counts["needs_manual"] += 1
            continue

        # A "function" over ~150 lines isn't useful model context regardless
        # of whether the extraction is technically correct -- it either IS
        # a parsing bug (a real one was found live: agenticmail's
        # escapeSqlString, a 3-line function, extracted as 1214 lines
        # spanning several unrelated functions due to a brace-depth
        # desync somewhere later in the file) or it's a genuinely huge
        # single function/IIFE (crypto-js's whole-file UMD wrapper,
        # npm-cli's top-level IIFE) that would just get truncated by the
        # 12,000-char context budget anyway. Routing both cases to manual
        # review rather than trusting either as "confident" turns an
        # open-ended parsing-correctness problem into a bounded data-
        # quality gate.
        MAX_REASONABLE_LINES = 150
        vuln_lines = vuln_text.count("\n") + 1
        patched_lines = patched_text.count("\n") + 1
        if vuln_lines > MAX_REASONABLE_LINES or patched_lines > MAX_REASONABLE_LINES:
            manual_review.append({
                "case_id": case_id, "language": language, "repository": metadata["repository"],
                "error": f"extracted function too large to be useful context "
                         f"(vuln={vuln_lines} lines, patched={patched_lines} lines, "
                         f"limit={MAX_REASONABLE_LINES}) -- likely a brace-depth parsing "
                         f"error, or a genuinely huge single function/IIFE either way",
            })
            counts["needs_manual"] += 1
            continue

        # A vulnerable/patched pair that's IDENTICAL once comments are
        # stripped means no real code difference was captured at all --
        # useless as model context regardless of confidence tagging.
        # Found live (CASE-0045, Dav-Git/Dav-Cogs's ticketer.py): a
        # comment-only hunk tied in weight with, and briefly outranked,
        # the real fix; fixed at the source in auto_locate_target.py
        # (comment-only changed lines now contribute 0 weight), but that
        # alone doesn't help the separate case of a hunk that's a pure
        # insertion of a brand-new function with no deletion anywhere in
        # the diff -- the two-pass tolerant retry can then land on the
        # same unrelated, textually-unchanged neighboring function on
        # BOTH sides (CASE-0121: a new sanitise() appended at end of
        # file resolved to the unchanged changeEntityHashesFromFriendly
        # on both old and new). Same bounded-data-quality-gate principle
        # as the size gate above rather than a further locator change.
        def _strip_comments(text: str) -> str:
            import re
            out = []
            for line in text.splitlines():
                s = re.sub(r"#.*$", "", line) if language == "python" else re.sub(r"//.*$", "", line)
                s = s.strip()
                if s:
                    out.append(s)
            return "\n".join(out)

        if _strip_comments(vuln_text) == _strip_comments(patched_text):
            manual_review.append({
                "case_id": case_id, "language": language, "repository": metadata["repository"],
                "error": "extracted vulnerable/patched functions are identical once comments "
                         "are stripped -- no real code difference captured, useless as model context",
            })
            counts["needs_manual"] += 1
            continue

        confidence = "auto_low_confidence" if "auto_low_confidence" in (confidence_v, confidence_p) else "auto"
        counts[confidence] += 1

        imports = get_imports_python(vuln_src) if language == "python" else get_imports_brace_lang(vuln_src)
        cwe_ids = metadata.get("cwe_ids", [])
        cwe_entries = [{"id": c, "definition": CWE_DEFS.get(c, "(definition not found)")} for c in cwe_ids]
        cve_ids = metadata.get("cve_ids", [])

        result = {
            "case_id": case_id,
            "language": language,
            "cve_id": cve_ids[0] if cve_ids else None,
            "cve_ids_all": cve_ids,
            "cwe": cwe_entries,
            "containing_class_declaration": class_name,
            "imports": imports,
            "vulnerable_function": vuln_text,
            "patched_function": patched_text,
            "unified_diff": diff_text,
            "auto_locate_confidence": confidence,
        }
        (OUT_DIR / f"{case_id}.json").write_text(json.dumps(result, indent=2) + "\n")

    MANUAL_REVIEW_FILE.write_text(json.dumps(manual_review, indent=2) + "\n")

    print(f"\nauto (confident): {counts['auto']}")
    print(f"auto_low_confidence (flagged, still usable): {counts['auto_low_confidence']}")
    print(f"needs_manual (no model_context written): {counts['needs_manual']}")
    print(f"\nWritten to {OUT_DIR}")
    print(f"Manual review list: {MANUAL_REVIEW_FILE}")


if __name__ == "__main__":
    main()
