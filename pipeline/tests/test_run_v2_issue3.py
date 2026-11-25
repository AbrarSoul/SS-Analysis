"""
Run v2, supervisor Issue 3 (Research_Log/Run_v2_Specification.md): location by the finding's full span.

What these tests establish:
- the three location methods behave as documented, including multi-range samples;
- with real pinned Semgrep, a multi-line finding that starts above the annotated lines is "right location"
  under the primary method (overlap) and under v1's rule it was not; all three verdicts are stored;
- every positive sample of the 150 eligible cases has an annotated range, read from the benchmark;
- v1's scoring function and old records are unaffected.
"""
import csv
import json
import subprocess
import sys
import textwrap
from dataclasses import asdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

import sample_evaluation as SE  # noqa: E402
from location_ranges import load_location_ranges, missing_ranges  # noqa: E402
from result_schema import SampleExecutionRecord  # noqa: E402

SEMGREP = str(ROOT / ".venv" / "bin" / "semgrep")
ELIGIBLE = [r["case_id"] for r in csv.DictReader(open(ROOT / "benchmark" / "all_cases_reference.csv"))
            if r["status"].startswith("eligible-150")]


# ---------------------------------------------------------------- the three methods
@pytest.mark.parametrize("spans, ranges, expected", [
    ([[10, 12]], [(10, 12)], {"overlap": True, "contained": True, "start_line": True}),     # exactly on it
    ([[8, 11]], [(10, 12)], {"overlap": True, "contained": False, "start_line": False}),    # starts above
    ([[11, 15]], [(10, 12)], {"overlap": True, "contained": False, "start_line": True}),    # runs past the end
    ([[5, 20]], [(10, 12)], {"overlap": True, "contained": False, "start_line": False}),    # covers it
    ([[13, 14]], [(10, 12)], {"overlap": False, "contained": False, "start_line": False}),  # just after
    ([[1, 2], [30, 30]], [(10, 12), (30, 31)], {"overlap": True, "contained": True, "start_line": True}),  # 2nd range
])
def test_location_methods(spans, ranges, expected):
    assert SE.location_verdicts(spans, ranges) == expected


def test_nothing_to_check_gives_none():
    assert SE.location_verdicts([], [(1, 2)]) is None
    assert SE.location_verdicts([[1, 2]], []) is None
    assert SE.location_verdicts([[1, 2]], None) is None


def test_finding_spans_reads_end_line():
    results = [{"start": {"line": 4}, "end": {"line": 7}}, {"start": {"line": 9}}, {"end": {"line": 3}}]
    assert SE._finding_spans(results) == [[4, 7], [9, 9]]


# ---------------------------------------------------------------- real Semgrep, small made-up case
VULN = textwrap.dedent('''\
    import subprocess

    def run(user_input):
        subprocess.call(
            "ls " + user_input,
            shell=True,
        )
''')
SAFE = textwrap.dedent('''\
    import subprocess

    def run(user_input):
        subprocess.call(["ls", user_input])
''')
RULE = {"id": "t-shell-true", "languages": ["python"], "message": "m", "severity": "ERROR",
        "pattern": "subprocess.call(..., shell=True, ...)"}


class _Validator:
    """Same contract as autogrep's RuleValidator._run_semgrep, calling the pinned Semgrep directly."""
    def _run_semgrep(self, rule_file, target):
        p = subprocess.run([SEMGREP, "--config", rule_file, "--json", "--metrics=off", target],
                           capture_output=True, text=True, timeout=120)
        out = json.loads(p.stdout)
        return out.get("results", []), None


@pytest.fixture()
def made_up_case(tmp_path):
    files = {"vulnerable_source": VULN, "patched_source": SAFE, "variant_vulnerable_01": VULN,
             "variant_vulnerable_02": VULN, "variant_safe_01": SAFE, "benign_lookalike": SAFE}
    for stem, text in files.items():
        (tmp_path / f"{stem}.py").write_text(text)
    return tmp_path


def test_multiline_finding_v2_vs_v1(made_up_case):
    # The call spans lines 4-7; say the annotated vulnerable construct is lines 5-6 (the shell=True string).
    ranges = {"original_vulnerable": [(5, 6)], "variant_vulnerable_1": [(5, 6)], "variant_vulnerable_2": [(20, 22)]}
    recs, err = SE.evaluate_case_bundle_v2(RULE, made_up_case, "python", "r", "CASE-TEST", "m", "raw", ranges)
    assert err is None
    by = {r.sample_type: r for r in recs}
    orig = by["original_vulnerable"]
    assert orig.finding_spans == [[4, 7]]
    assert orig.location_by_method == {"overlap": True, "contained": False, "start_line": False}
    assert orig.finding_location_correct is True and orig.outcome == "TP"
    assert by["variant_vulnerable_2"].finding_location_correct is False and by["variant_vulnerable_2"].outcome == "FN"
    for neg in ("original_patched", "variant_safe", "benign_lookalike"):
        assert by[neg].location_by_method is None and by[neg].outcome == "TN"
    assert all(r.scan_status == "ok" for r in recs)

    # v1's function, same rule and file, with the same annotated lines: start line 4 is outside 5-6.
    v1, _ = SE.evaluate_case_bundle(RULE, made_up_case, "python", _Validator(), "r", "CASE-TEST", "m", "raw",
                                    vulnerable_lines=[5, 6])
    v1_orig = {r.sample_type: r for r in v1}["original_vulnerable"]
    assert v1_orig.finding_location_correct is False and v1_orig.outcome == "FN"
    assert v1_orig.finding_spans is None                          # v1 records keep their old shape


# ---------------------------------------------------------------- benchmark annotations
def test_every_eligible_positive_sample_has_a_range():
    assert len(ELIGIBLE) == 150
    assert missing_ranges(ELIGIBLE) == []


def test_ranges_match_v1_sources():
    manifest = {}
    for line in (ROOT / "benchmark" / "manifest_frozen_final.jsonl").read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            manifest[r["case_id"]] = r.get("vulnerable_lines")
    for cid in ELIGIBLE:
        rng = load_location_ranges(cid)
        assert rng["original_vulnerable"] == [tuple(manifest[cid])], cid
        for v in ("variant_vulnerable_1", "variant_vulnerable_2"):
            assert all(lo <= hi for lo, hi in rng[v]), (cid, v)


def test_second_ranges_are_loaded():
    two = sorted(c for c in ELIGIBLE if any(len(v) > 1 for v in load_location_ranges(c).values()))
    assert two == ["CASE-0163", "CASE-0173", "CASE-0235", "CASE-0239"]
    assert len(load_location_ranges("CASE-0163")["variant_vulnerable_2"]) == 2


# ---------------------------------------------------------------- old records unaffected
def test_old_records_still_load_and_derive_the_same_outcome():
    old = {"run_id": "r", "case_id": "C", "model_tag": "m", "condition": "raw", "sample_type": "original_vulnerable",
           "label": "positive", "detected": True, "finding_location_correct": False, "finding_lines": [4], "outcome": None}
    rec = SampleExecutionRecord(**old)
    assert rec.outcome == "FN" and rec.finding_spans is None and rec.location_by_method is None
    assert rec.scan_status is None                                   # Issue 4's field, also absent in v1 records
    assert set(asdict(rec)) == set(old) | {"finding_spans", "location_by_method", "scan_status", "scan_message"}
