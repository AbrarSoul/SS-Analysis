"""
Design doc Section 8 Step 4 (automated portion) for the 300-case FINAL
dataset (Phase 4) -- identical procedure to curate_step4_fetch_advisories.py,
pointed at the final batch's Step 3 output instead of the pilot's. See that
script's docstring for the full rationale (this is a pre-filter, not a claim
of full automated verification; refactor-only and CWE-disagreement cases are
flagged for human review, not auto-excluded).
"""
import json
import re
import subprocess
import time
from pathlib import Path

CASES_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "step3_repo_states_topup15"
OUT_LOG = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4" / "step4_advisory_results_topup15.json"

COMMENT_PATTERNS = {
    "python": re.compile(r"^\s*#"),
    "java": re.compile(r"^\s*(//|/\*|\*)"),
    "javascript": re.compile(r"^\s*(//|/\*|\*)"),
    "typescript": re.compile(r"^\s*(//|/\*|\*)"),
}
IMPORT_PATTERNS = {
    "python": re.compile(r"^\s*(import |from .+ import)"),
    "java": re.compile(r"^\s*import "),
    "javascript": re.compile(r"^\s*(import |const .+ = require\()"),
    "typescript": re.compile(r"^\s*(import |const .+ = require\()"),
}


def fetch_advisory(cve_id: str) -> dict:
    try:
        result = subprocess.run(
            ["gh", "api", f"advisories?cve_id={cve_id}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip()}
        data = json.loads(result.stdout)
        return {"advisories": data}
    except Exception as e:
        return {"error": str(e)}


def is_refactor_only(diff_text: str, language: str) -> bool:
    comment_re = COMMENT_PATTERNS.get(language)
    import_re = IMPORT_PATTERNS.get(language)
    changed_lines = [ln[1:] for ln in diff_text.split("\n")
                      if (ln.startswith("+") or ln.startswith("-"))
                      and not ln.startswith("+++") and not ln.startswith("---")]
    if not changed_lines:
        return False
    for line in changed_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if comment_re and comment_re.match(line):
            continue
        if import_re and import_re.match(line):
            continue
        return False
    return True


def main():
    case_dirs = sorted(d for d in CASES_DIR.iterdir() if d.is_dir())
    print(f"Found {len(case_dirs)} cases with Step 3 output")

    # Resume support (Step 3's own scripts didn't need this since GitHub API
    # calls are fast; at 300 candidates here it's cheap insurance against an
    # interruption forcing a full 300-candidate re-fetch from scratch).
    results = {}
    if OUT_LOG.exists():
        results = json.loads(OUT_LOG.read_text())
        print(f"Resuming: {len(results)} already processed in a prior run")

    for i, case_dir in enumerate(case_dirs, 1):
        metadata_file = case_dir / "metadata.json"
        diff_file = case_dir / "patch.diff"
        if not metadata_file.exists() or not diff_file.exists():
            continue
        metadata = json.loads(metadata_file.read_text())
        case_id = metadata["case_id"]
        if case_id in results:
            continue
        print(f"[{i}/{len(case_dirs)}] {case_id}")

        cve_ids = metadata.get("cve_ids", [])
        advisories_by_cve = {}
        for cve_id in cve_ids:
            advisories_by_cve[cve_id] = fetch_advisory(cve_id)
            time.sleep(0.1)  # polite pacing even with the higher authenticated limit

        diff_text = diff_file.read_text()
        refactor_flag = is_refactor_only(diff_text, metadata["language"])

        github_cwes = set()
        any_reviewed = False
        for cve_id, adv in advisories_by_cve.items():
            for a in adv.get("advisories", []):
                # GitHub's advisories API nests CWEs as a list of
                # {"cwe_id": ..., "name": ...} objects under "cwes" -- NOT a
                # flat "cwe_ids" list (there is no such key in the real
                # response). The original version of this check looked for
                # "cwe_ids" and silently got [] on every single advisory,
                # making cwe_disagreement_flag permanently unable to fire.
                # Found live: reprocessing the already-cached raw advisory
                # data (no new API calls needed) corrected github_cwes for
                # 254 of 300 cases and surfaced 19 real CWE disagreements
                # that had been invisible the whole time.
                github_cwes.update(c["cwe_id"] for c in (a.get("cwes") or []) if c.get("cwe_id"))
                if a.get("type") == "reviewed" or a.get("github_reviewed_at"):
                    any_reviewed = True
        morefixes_cwes = set(metadata.get("cwe_ids", []))
        cwe_overlap = bool(github_cwes & morefixes_cwes)
        cwe_disagreement = bool(github_cwes) and bool(morefixes_cwes) and not cwe_overlap

        results[case_id] = {
            "cve_ids": cve_ids,
            "advisories_by_cve": advisories_by_cve,
            "refactor_only_heuristic": refactor_flag,
            "morefixes_cwes": sorted(morefixes_cwes),
            "github_cwes": sorted(github_cwes),
            "cwe_overlap": cwe_overlap,
            "cwe_disagreement_flag": cwe_disagreement,
            "any_github_reviewed_advisory": any_reviewed,
        }
        # Write incrementally, same reasoning as Step 3's resume support --
        # an interruption should never cost more than the single in-flight case.
        OUT_LOG.write_text(json.dumps(results, indent=2))

    n_refactor = sum(1 for r in results.values() if r["refactor_only_heuristic"])
    n_cwe_disagree = sum(1 for r in results.values() if r["cwe_disagreement_flag"])
    n_no_advisory = sum(1 for r in results.values()
                         if all("error" in a or not a.get("advisories") for a in r["advisories_by_cve"].values()))

    print()
    print(f"Total cases processed: {len(results)}")
    print(f"Flagged refactor-only (heuristic): {n_refactor}")
    print(f"Flagged CWE disagreement: {n_cwe_disagree}")
    print(f"No advisory found at all: {n_no_advisory}")
    print(f"Results written to {OUT_LOG}")


if __name__ == "__main__":
    main()
