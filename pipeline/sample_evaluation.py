"""
Stage B (design doc Section 16.2): evaluate a candidate rule against a
case's test-bundle samples, producing granular per-sample results -- not
just Autogrep's internal boolean valid/invalid outcome -- including finding
locations for the location-correctness check (Section 9.3) where available.

Two evaluation paths:
- evaluate_original_pair(): the raw-.patch-file flow (Phase 1's original
  smoke-test path). Checks out the vulnerable/patched commit in a live
  cloned repo, since that flow has no pre-extracted standalone files.
- evaluate_case_bundle(): the curated-case flow (Phase 2 pilot onward).
  Runs directly against the 6 standalone files a benchmark/cases/CASE-XXXX
  directory already has (design doc Section 9) -- no git checkout needed,
  since Section 9 curation already extracted/generated all six. This is
  what actually exercises Section 21's VGR/FPR/BSDR metrics, which need
  the transformed-variant and benign-lookalike samples evaluate_
  original_pair() never had access to.
"""
import re
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import git
import yaml

from result_schema import SampleExecutionRecord

_DIFF_GIT_RE = re.compile(r'^diff --git a/(.+?) b/(.+)$')
_HUNK_RE = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@')


def parse_vulnerable_changed_lines(patch_text: str) -> Dict[str, range]:
    """Parses unified-diff hunk headers to get the changed-line range in the
    ORIGINAL (vulnerable/parent) version of each file, for the finding-
    location-correctness check (Section 9.3). Mirrors the same diff-scanning
    approach patch_processor.py uses to extract file_changes, but captures
    line ranges instead of just changed text."""
    ranges: Dict[str, range] = {}
    current_file = None
    for line in patch_text.split('\n'):
        m = _DIFF_GIT_RE.match(line)
        if m:
            current_file = m.group(1)
            continue
        m = _HUNK_RE.match(line)
        if m and current_file:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) else 1
            new_range = range(start, start + count)
            existing = ranges.get(current_file)
            if existing:
                ranges[current_file] = range(min(existing.start, new_range.start),
                                              max(existing.stop, new_range.stop))
            else:
                ranges[current_file] = new_range
    return ranges


def _finding_lines(results: list) -> List[int]:
    lines = []
    for r in results:
        start = r.get("start", {}).get("line")
        if start is not None:
            lines.append(start)
    return lines


def evaluate_original_pair(
    rule: dict,
    patch_info,
    repo_path: Path,
    rule_validator,
    run_id: str,
    case_id: str,
    model_tag: str,
    condition: str,
    changed_lines_by_file: Optional[Dict[str, range]] = None,
):
    """Re-executes Semgrep directly (reusing RuleValidator._run_semgrep, not
    reimplementing it) against the vulnerable (parent) and patched (fix)
    commit for every changed file in the case.

    Returns (sample_records, rule_error). rule_error is populated only when
    Semgrep itself rejected the rule (e.g. an invalid metavariable) -- as
    opposed to a valid rule that simply produced zero findings -- so callers
    can distinguish "rule never executed" from "rule executed, found
    nothing" rather than conflating both into a bare boolean (see
    Research_Log/Model_Failure_Root_Cause_Analysis.md, Section 4)."""
    repo = git.Repo(repo_path)

    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
        yaml.dump({"rules": [rule]}, tf)
        rule_file = tf.name

    rule_error = None
    try:
        vuln_by_file, patched_by_file = {}, {}

        repo.git.checkout(repo.commit(patch_info.commit_id).parents[0])
        for fc in patch_info.file_changes:
            target = repo_path / fc.file_path
            if not target.exists():
                continue
            results, error = rule_validator._run_semgrep(rule_file, str(target))
            rule_error = rule_error or error
            vuln_by_file[fc.file_path] = results or []

        repo.git.checkout(patch_info.commit_id)
        for fc in patch_info.file_changes:
            target = repo_path / fc.file_path
            if not target.exists():
                continue
            results, error = rule_validator._run_semgrep(rule_file, str(target))
            rule_error = rule_error or error
            patched_by_file[fc.file_path] = results or []
    finally:
        repo.git.checkout(patch_info.commit_id)
        Path(rule_file).unlink(missing_ok=True)

    vuln_results_all = [r for results in vuln_by_file.values() for r in results]
    patched_results_all = [r for results in patched_by_file.values() for r in results]

    location_ok = None
    if vuln_results_all and changed_lines_by_file:
        location_ok = any(
            line in changed_lines_by_file.get(file_path, range(0, 0))
            for file_path, results in vuln_by_file.items()
            for line in _finding_lines(results)
        )

    vulnerable_record = SampleExecutionRecord(
        run_id=run_id, case_id=case_id, model_tag=model_tag, condition=condition,
        sample_type="original_vulnerable", label="positive",
        detected=bool(vuln_results_all), finding_location_correct=location_ok,
        finding_lines=_finding_lines(vuln_results_all) or None,
    )
    patched_record = SampleExecutionRecord(
        run_id=run_id, case_id=case_id, model_tag=model_tag, condition=condition,
        sample_type="original_patched", label="negative",
        detected=bool(patched_results_all),
        finding_lines=_finding_lines(patched_results_all) or None,
    )
    return [vulnerable_record, patched_record], rule_error


# sample_type -> (filename glob prefix, label). File extension is
# resolved per case from patch_info.file_changes[0].language.
_BUNDLE_SAMPLES = (
    ("original_vulnerable", "vulnerable_source", "positive"),
    ("original_patched", "patched_source", "negative"),
    ("variant_vulnerable_1", "variant_vulnerable_01", "positive"),
    ("variant_vulnerable_2", "variant_vulnerable_02", "positive"),
    ("variant_safe", "variant_safe_01", "negative"),
    ("benign_lookalike", "benign_lookalike", "negative"),
)
_EXT_BY_LANGUAGE = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}


def evaluate_case_bundle(
    rule: dict,
    case_dir: Path,
    language: str,
    rule_validator,
    run_id: str,
    case_id: str,
    model_tag: str,
    condition: str,
    vulnerable_lines: Optional[List[int]] = None,
):
    """Runs the generated rule directly against all six of a curated case's
    test-bundle samples (design doc Section 9) -- no git checkout needed,
    since benchmark/cases/CASE-XXXX already has every sample as a standalone
    file. Returns (sample_records, rule_error).

    finding_location_correct is only computed for original_vulnerable,
    using vulnerable_lines (the [start, end] line range recorded in
    benchmark/manifest_frozen.jsonl during Step 7 freezing). The four new
    Section 9 samples (transformed variants, benign look-alike) don't have
    an equivalent per-file line-range annotation yet -- left None
    (unverified) rather than guessed, matching this field's existing
    Optional convention ("meaningful only when label == positive").
    """
    ext = _EXT_BY_LANGUAGE[language]

    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
        yaml.dump({"rules": [rule]}, tf)
        rule_file = tf.name

    rule_error = None
    records = []
    try:
        for sample_type, file_stem, label in _BUNDLE_SAMPLES:
            target = case_dir / f"{file_stem}.{ext}"
            if not target.exists():
                continue  # tolerate a case missing a sample rather than hard-failing the whole bundle
            results, error = rule_validator._run_semgrep(rule_file, str(target))
            rule_error = rule_error or error
            results = results or []

            location_ok = None
            if sample_type == "original_vulnerable" and results and vulnerable_lines:
                lo, hi = vulnerable_lines
                location_ok = any(lo <= line <= hi for line in _finding_lines(results))

            records.append(SampleExecutionRecord(
                run_id=run_id, case_id=case_id, model_tag=model_tag, condition=condition,
                sample_type=sample_type, label=label,
                detected=bool(results), finding_location_correct=location_ok,
                finding_lines=_finding_lines(results) or None,
            ))
    finally:
        Path(rule_file).unlink(missing_ok=True)

    return records, rule_error


# ------------------------------------------------------------------------------------------------
# Run v2 (Research_Log/Run_v2_Specification.md, supervisor Issue 3): location by the finding's full span.
# v1's evaluate_case_bundle() above is left unchanged so every v1 result stays reproducible.
# ------------------------------------------------------------------------------------------------
LOCATION_METHODS = ("overlap", "contained", "start_line")
PRIMARY_LOCATION_METHOD = "overlap"


def _finding_spans(results: list) -> List[List[int]]:
    """[[start_line, end_line], ...] for every finding. A finding without an end line spans its start line."""
    spans = []
    for r in results:
        start = r.get("start", {}).get("line")
        if start is None:
            continue
        end = r.get("end", {}).get("line") or start
        spans.append([start, max(start, end)])
    return spans


def location_verdicts(spans: List[List[int]], ranges) -> Optional[dict]:
    """Whether any finding is at an annotated location, under each method. None if there is nothing to check.

    overlap    (primary)   the finding's span shares at least one line with a range
    contained  (strict)    the finding's span lies entirely inside a range
    start_line (v1's rule) the finding's first line lies inside a range
    """
    if not spans or not ranges:
        return None
    return {
        "overlap": any(s <= hi and e >= lo for s, e in spans for lo, hi in ranges),
        "contained": any(lo <= s and e <= hi for s, e in spans for lo, hi in ranges),
        "start_line": any(lo <= s <= hi for s, _ in spans for lo, hi in ranges),
    }


def evaluate_case_bundle_v2(
    rule: dict,
    case_dir: Path,
    language: str,
    run_id: str,
    case_id: str,
    model_tag: str,
    condition: str,
    location_ranges: Dict[str, list],
    scanner=None,
    only_samples=None,
):
    """Like evaluate_case_bundle(), with these changes for run v2:
    - Issue 3: every positive sample with an annotated range gets a location check (v1 checked only
      original_vulnerable here and added the variants in a later rescoring step), using each finding's full
      span under all three LOCATION_METHODS; the primary one decides finding_location_correct, and all three
      are stored so the analysis can report the others as pre-declared sensitivity checks;
    - Issue 4: Semgrep runs through pipeline/semgrep_runner (the pinned binary, one call for all six samples),
      and every record carries the scan's status. A sample whose scan was not "ok" gets outcome "ERROR".
    location_ranges comes from location_ranges.load_location_ranges(case_id). scanner defaults to
    semgrep_runner.scan (replaceable in tests). only_samples limits the scan to some sample types (the run v2
    acceptance check uses the visible pair only). Returns (records, rule_error); rule_error is set only when
    Semgrep rejected the rule itself."""
    import semgrep_runner
    scanner = scanner or semgrep_runner.scan
    ext = _EXT_BY_LANGUAGE[language]

    samples = [(st, label, str(case_dir / f"{stem}.{ext}")) for st, stem, label in _BUNDLE_SAMPLES
               if (case_dir / f"{stem}.{ext}").exists() and (only_samples is None or st in only_samples)]
    scans = scanner(rule, [t for _, _, t in samples])

    rule_error = None
    records = []
    for sample_type, label, target in samples:
        sr = scans[target]
        if sr.status == "rule_error":
            rule_error = rule_error or sr.message
        spans = _finding_spans(sr.results) if sr.ok else []
        verdicts = location_verdicts(spans, location_ranges.get(sample_type)) if (label == "positive" and sr.ok) else None
        records.append(SampleExecutionRecord(
            run_id=run_id, case_id=case_id, model_tag=model_tag, condition=condition,
            sample_type=sample_type, label=label,
            detected=bool(sr.results),
            finding_location_correct=verdicts[PRIMARY_LOCATION_METHOD] if verdicts else None,
            finding_lines=[s for s, _ in _finding_spans(sr.results)] or None,
            finding_spans=_finding_spans(sr.results) or None,
            location_by_method=verdicts,
            scan_status=sr.status,
            scan_message=sr.message,
        ))
    return records, rule_error
