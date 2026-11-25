"""
Run v2 freeze check (Research_Log/Run_v2_Specification.md, supervisor Issue 4): every sample file of every case
in the run must parse cleanly under pinned Semgrep in its own language. A file that does not parse would be
scored on whatever part Semgrep could read, which no rule can be blamed or credited for.

Usage (from the repo root):
    .venv/bin/python3 pipeline/target_preflight.py            # the 150 eligible cases
    .venv/bin/python3 pipeline/target_preflight.py CASE-0055  # chosen cases
Exit code 1 if any file fails. The freeze checklist requires this to pass on the frozen benchmark.

Note: some parsers recover from syntax errors without reporting them (observed with Java), so passing this
check is necessary, not sufficient; the ground-truth review's compile checks (Stage 1) cover the rest.
"""
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import semgrep_runner  # noqa: E402
from sample_evaluation import _BUNDLE_SAMPLES, _EXT_BY_LANGUAGE  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "benchmark" / "cases"
# The probe must contain no literal text: Semgrep skips parsing any file that lacks a rule's literals, while
# still listing it under paths.scanned (checked 2026-11-25: a probe named zz_preflight_probe_zz(...) let a file
# with a syntax error pass, even with --optimizations none). `$F(...)` matches any call, so every file is parsed;
# the metavariable-regex then discards every match, so the output stays small (matching every call in 900 files
# made one run take many minutes).
PROBE_PATTERN = "$F(...)"


def probe_rule(lang):
    return {"id": "preflight-probe", "languages": [lang], "message": "probe", "severity": "INFO",
            "patterns": [{"pattern": PROBE_PATTERN},
                         {"metavariable-regex": {"metavariable": "$F", "regex": "^\\b$"}}]}


def eligible_cases():
    return [r["case_id"] for r in csv.DictReader(open(ROOT / "benchmark" / "all_cases_reference.csv"))
            if r["status"].startswith("eligible-150")]


def case_language(case_id):
    return json.loads((CASES / case_id / "metadata.json").read_text())["language"]


def preflight(case_ids):
    """[(case_id, sample_file, status, message)] for every sample that did not scan "ok"."""
    by_lang = defaultdict(list)
    for cid in case_ids:
        lang = case_language(cid)
        for _, stem, _ in _BUNDLE_SAMPLES:
            f = CASES / cid / f"{stem}.{_EXT_BY_LANGUAGE[lang]}"
            if f.exists():
                by_lang[lang].append((cid, str(f)))
    failures = []
    for lang, items in sorted(by_lang.items()):
        scans = semgrep_runner.scan(probe_rule(lang), [f for _, f in items], timeout=600)
        for cid, f in items:
            sr = scans[f]
            if not sr.ok:
                failures.append((cid, Path(f).name, sr.status, (sr.message or "")[:200]))
    return failures


def main(argv):
    semgrep_runner.assert_pinned_version()
    ids = argv or eligible_cases()
    failures = preflight(ids)
    for cid, name, status, msg in failures:
        print(f"{cid}  {name:28s} {status:20s} {msg}")
    print(f"{len(ids)} cases checked; {len(failures)} sample files failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
