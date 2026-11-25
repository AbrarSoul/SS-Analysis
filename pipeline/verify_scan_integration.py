"""
Integration check for the diagnostic_v2.py evaluator fixes (Research_Direction_20261011.md item 1):
re-scans qwen3_v3's ALREADY-SAVED rule files through the UPDATED scan()/report() (now with .tsx
staging + merged location ranges built in, instead of needing a separate rescore_qwen3_v3_corrected.py
pass) and confirms it reproduces the already-independently-verified 6/24 complete_success. No new
model calls -- every rule replayed here was already generated and saved by the real qwen3_v3 run.

Rewritten 2026-10-12 after an independent review found this script printed "(expected 6)" without
ever asserting it -- exit code 0 was not actually evidence the expectation held; a silent
regression could have passed unnoticed. Now asserts the aggregate count, the exact set of
per-case complete successes (not just the total, which could hide a same-count-different-cases
swap), and per-condition scan-error counts, failing loudly (non-zero exit, AssertionError) on any
disagreement. Also writes a timestamped, versioned summary (not a fixed scratch path) recording
input hashes and the engine version actually used, so a run of this script is itself retained
evidence, not just a transient terminal check.

Rewritten again, same day, after a follow-up review flagged that the recorded `semgrep_version`
came from a bare `subprocess.run(["--version"])` call with no `env=` override -- semgrep's launcher
delegates to pysemgrep via PATH (see diagnostic_v2.py's own semgrep_env() comment), so without
prepending .venv/bin, this call could silently report an unrelated system-wide installation's
version instead of the one actually used for the scans two lines below. Did not reproduce a wrong
version in the environment this was fixed in, but the fix costs nothing and removes a real,
previously-documented class of bug from this one remaining call site. Now uses dv2.semgrep_env(out),
the same construction every actual scan in this script already goes through.

Usage:
    python pipeline/verify_scan_integration.py
"""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
import diagnostic_v2 as dv2
from eligible_cases import load_manifest

RUN_DIR = ROOT / "results/diagnostic_20261010/qwen3_v3"
SEMGREP = ROOT / ".venv/bin/semgrep"

EXPECTED_ITERATIVE_COMPLETE_SUCCESS = 6
EXPECTED_ITERATIVE_SCAN_ERRORS = 0
EXPECTED_RAW_SCAN_ERRORS = 1  # down from the historical 2, since .tsx staging now resolves CASE-0298's raw attempt cleanly
EXPECTED_SUCCESSFUL_CASES = {"CASE-0323", "CASE-0276", "CASE-0221", "CASE-0134", "CASE-0136", "CASE-0220"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = ROOT / "results/diagnostic_20261010" / f"_verify_scan_integration_{timestamp}"
    out.mkdir(parents=True, exist_ok=False)

    manifest = load_manifest()
    ann = dv2.load_merged_ann()
    selection = json.loads((RUN_DIR / "selection.json").read_text())
    ids = selection["case_ids"]

    version = subprocess.run([str(SEMGREP), "--version"], capture_output=True, text=True,
                              env=dv2.semgrep_env(out)).stdout.strip()

    episodes = []
    successful_cases = set()
    for cid in ids:
        ep_old = json.loads((RUN_DIR / cid / "episode.json").read_text())
        attempt1_rule = RUN_DIR / cid / "attempt_1" / "rule.yml"
        raw_eval = dv2.scan(attempt1_rule, cid, manifest, ann, out / cid / "raw_hidden", hidden=True) if attempt1_rule.exists() else None
        final_rule_path = ep_old.get("final_rule_path")
        it_eval = dv2.scan(Path(final_rule_path), cid, manifest, ann, out / cid / "iterative_hidden", hidden=True) if final_rule_path else None
        episodes.append({"case_id": cid, "raw": raw_eval, "iterative": it_eval})
        if it_eval and it_eval["complete_success"]:
            successful_cases.add(cid)

    rep = dv2.report(episodes, ids, "model")
    print(json.dumps(rep["conditions"], indent=2))

    actual_cs = rep["conditions"]["iterative"]["complete_success"]
    actual_raw_errors = rep["conditions"]["raw"]["scan_errors"]
    actual_it_errors = rep["conditions"]["iterative"]["scan_errors"]

    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "semgrep_version": version,
        "source_run_dir": str(RUN_DIR.relative_to(ROOT)),
        "selection_sha256": sha(RUN_DIR / "selection.json"),
        "report_conditions": rep["conditions"],
        "successful_cases": sorted(successful_cases),
        "expected_iterative_complete_success": EXPECTED_ITERATIVE_COMPLETE_SUCCESS,
        "expected_successful_cases": sorted(EXPECTED_SUCCESSFUL_CASES),
        "assertions_passed": None,  # filled in below, before writing
    }

    try:
        assert actual_cs == EXPECTED_ITERATIVE_COMPLETE_SUCCESS, (
            f"iterative complete_success = {actual_cs}, expected {EXPECTED_ITERATIVE_COMPLETE_SUCCESS}")
        assert successful_cases == EXPECTED_SUCCESSFUL_CASES, (
            f"successful case set differs: got {sorted(successful_cases)}, "
            f"expected {sorted(EXPECTED_SUCCESSFUL_CASES)} (same COUNT could still hide a different-cases swap)")
        assert actual_raw_errors == EXPECTED_RAW_SCAN_ERRORS, (
            f"raw scan_errors = {actual_raw_errors}, expected {EXPECTED_RAW_SCAN_ERRORS}")
        assert actual_it_errors == EXPECTED_ITERATIVE_SCAN_ERRORS, (
            f"iterative scan_errors = {actual_it_errors}, expected {EXPECTED_ITERATIVE_SCAN_ERRORS}")
        summary["assertions_passed"] = True
    except AssertionError as e:
        summary["assertions_passed"] = False
        summary["failure"] = str(e)
        (out / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"\nFAILED: {e}")
        sys.exit(1)

    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nPASSED: iterative complete_success = {actual_cs}, exact case set matches, "
          f"raw scan_errors = {actual_raw_errors}, iterative scan_errors = {actual_it_errors}")
    print(f"Summary written to {out / 'summary.json'}")


if __name__ == "__main__":
    main()
