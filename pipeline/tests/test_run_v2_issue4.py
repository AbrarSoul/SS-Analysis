"""
Run v2, supervisor Issue 4 (Research_Log/Run_v2_Specification.md): a scan that did not fully happen is never
scored as "scanned, nothing found"; Semgrep is the pinned binary.

What these tests establish, with the real pinned Semgrep:
- each scan situation gets its own status (ok, target_parse_error, not_scanned, rule_error, semgrep_failure);
- in scoring, any non-ok scan makes the sample's outcome "ERROR" -- a wrong-language rule no longer "passes"
  the safe samples, and a sample with a syntax error is not scored on the part Semgrep could read;
- Semgrep skips parsing files that lack a rule's literal text, so the preflight probe has none;
- the preflight finds exactly the known broken benchmark files (to be empty at the freeze).
"""
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

import sample_evaluation as SE  # noqa: E402
import semgrep_runner as SR  # noqa: E402
import target_preflight as TP  # noqa: E402

OK_PY = "import os\ndef f(x):\n    os.system(x)\n"
BROKEN_PY = "import os\ndef f(x)\n    os.system(x\n"
TS = "const a: number = 1;\nfunction g(x: string) { eval(x); }\n"


def _rule(pattern, lang="python"):
    return {"id": "t", "languages": [lang], "message": "m", "severity": "ERROR", "pattern": pattern}


@pytest.fixture()
def files(tmp_path):
    for name, text in {"ok.py": OK_PY, "broken.py": BROKEN_PY, "t.ts": TS}.items():
        (tmp_path / name).write_text(text)
    return tmp_path


def test_pinned_version():
    SR.assert_pinned_version()


def test_wrong_version_is_refused(tmp_path):
    fake = tmp_path / "semgrep"
    fake.write_text("#!/bin/sh\necho 1.140.0\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(RuntimeError, match="1.140.0"):
        SR.assert_pinned_version(fake)


def test_statuses_with_real_semgrep(files):
    ok = SR.scan_one(_rule("os.system(...)"), str(files / "ok.py"))
    assert ok.status == "ok" and [r["start"]["line"] for r in ok.results] == [3]

    broken = SR.scan_one(_rule("os.system(...)"), str(files / "broken.py"))
    assert broken.status == "target_parse_error" and "Syntax error" in broken.message

    wrong_lang = SR.scan_one(_rule("eval(...)"), str(files / "t.ts"))     # python rule, TypeScript file
    assert wrong_lang.status == "not_scanned" and wrong_lang.results == []

    bad_rule = SR.scan_one(_rule("os.system($X"), str(files / "ok.py"))
    assert bad_rule.status == "rule_error" and bad_rule.exit_code == 2


def test_one_call_many_targets(files):
    targets = [str(files / n) for n in ("ok.py", "broken.py", "t.ts")]
    out = SR.scan(_rule("os.system(...)"), targets)
    assert [out[t].status for t in targets] == ["ok", "target_parse_error", "not_scanned"]


def test_unreadable_output_is_a_failure():
    out = SR.classify("not json", 139, ["a.py"])
    assert out["a.py"].status == "semgrep_failure"


def test_literal_probe_misses_broken_file_but_preflight_probe_does_not(files):
    # Documents the Semgrep behaviour the preflight depends on.
    target = str(files / "broken.py")
    assert SR.scan_one(_rule("zz_preflight_probe_zz(...)"), target).status == "ok"   # never parsed
    assert SR.scan_one(_rule(TP.PROBE_PATTERN), target).status == "target_parse_error"
    probe = SR.scan_one(TP.probe_rule("python"), target)                              # the preflight's real probe
    assert probe.status == "target_parse_error" and probe.results == []
    assert SR.scan_one(TP.probe_rule("python"), str(files / "ok.py")).status == "ok"


# ---------------------------------------------------------------- scoring
@pytest.fixture()
def case_with_broken_safe_sample(tmp_path):
    vuln = textwrap.dedent('''\
        import os
        def run(x):
            os.system(x)
    ''')
    safe = textwrap.dedent('''\
        import subprocess
        def run(x):
            subprocess.run(["ls", x])
    ''')
    files = {"vulnerable_source": vuln, "patched_source": safe, "variant_vulnerable_01": vuln,
             "variant_vulnerable_02": vuln, "variant_safe_01": safe,
             "benign_lookalike": "import os\ndef run(x)\n    os.system('ls'\n"}     # syntax error, contains the literal
    for stem, text in files.items():
        (tmp_path / f"{stem}.py").write_text(text)
    return tmp_path


RANGES = {"original_vulnerable": [(3, 3)], "variant_vulnerable_1": [(3, 3)], "variant_vulnerable_2": [(3, 3)]}


def test_broken_sample_is_error_not_clean(case_with_broken_safe_sample):
    recs, err = SE.evaluate_case_bundle_v2(_rule("os.system(...)"), case_with_broken_safe_sample, "python",
                                           "r", "CASE-TEST", "m", "raw", RANGES)
    by = {r.sample_type: r for r in recs}
    assert err is None
    assert by["benign_lookalike"].scan_status == "target_parse_error" and by["benign_lookalike"].outcome == "ERROR"
    assert by["original_vulnerable"].outcome == "TP" and by["original_patched"].outcome == "TN"


def test_wrong_language_rule_never_passes_safe_samples(case_with_broken_safe_sample):
    recs, err = SE.evaluate_case_bundle_v2(_rule("eval(...)", lang="javascript"), case_with_broken_safe_sample,
                                           "python", "r", "CASE-TEST", "m", "raw", RANGES)
    assert {r.scan_status for r in recs} == {"not_scanned"}
    assert {r.outcome for r in recs} == {"ERROR"}          # v1 would have scored the three safe samples TN


def test_rule_error_is_reported(case_with_broken_safe_sample):
    recs, err = SE.evaluate_case_bundle_v2(_rule("os.system($X"), case_with_broken_safe_sample, "python",
                                           "r", "CASE-TEST", "m", "raw", RANGES)
    assert err and {r.outcome for r in recs} == {"ERROR"}


# ---------------------------------------------------------------- benchmark preflight
# Known broken sample files, found independently in October (Supervisor_Response_Table_20261020.md, Issue 4)
# and again by this preflight. The ground-truth review decides to repair or exclude each case; at the freeze
# this set must be empty, and this test is then updated in the same commit as the benchmark correction.
KNOWN_BROKEN = {
    ("CASE-0055", "vulnerable_source.py"), ("CASE-0055", "patched_source.py"),
    ("CASE-0055", "variant_vulnerable_01.py"), ("CASE-0055", "variant_vulnerable_02.py"),
    ("CASE-0298", "vulnerable_source.ts"), ("CASE-0298", "patched_source.ts"),
    ("CASE-0298", "variant_vulnerable_01.ts"), ("CASE-0298", "variant_vulnerable_02.ts"),
    ("CASE-0298", "variant_safe_01.ts"),
}


def test_preflight_finds_exactly_the_known_broken_files():
    failures = TP.preflight(TP.eligible_cases())
    assert {(c, f) for c, f, _, _ in failures} == KNOWN_BROKEN
    assert {s for _, _, s, _ in failures} == {"target_parse_error"}
