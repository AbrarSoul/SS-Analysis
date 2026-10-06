"""
Re-verification tool for Section 9 progress: after any exclusion+topup+
re-freeze cycle, case IDs can shift for every case sorting after the
excluded one (found three times now -- Section 12.14/12.15 of
Implementation_Log.md). Re-running the whole manifest by hand each time
is error-prone (guessing which cases are "close enough" to the exclusion
point to check missed a shift once already, when a new candidate's name
sorted earlier than expected due to case-sensitive ASCII ordering).

Instead of maintaining a hand-written expected-repository dict, this
extracts the repository name each build_bundle_caseNNNN.py script says
it's for directly from its own docstring (the "(Owner/repo, CVE-...)"
line every script starts with), and compares it against what that case
ID's metadata.json currently says. Run this after every re-freeze, before
resuming Section 9 case-by-case work.
"""
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "pipeline" / "section9_final"
CASES_DIR = REPO_ROOT / "benchmark" / "cases"

_DOCSTRING_REPO_RE = re.compile(r"\(([A-Za-z0-9._-]+/[A-Za-z0-9._-]+),")


def main():
    mismatches = []
    checked = 0
    for script_path in sorted(SCRIPTS_DIR.glob("build_bundle_case*.py")):
        m = re.match(r"build_bundle_case(\d{4})\.py", script_path.name)
        if not m:
            continue
        case_id = f"CASE-{m.group(1)}"
        text = script_path.read_text()
        repo_match = _DOCSTRING_REPO_RE.search(text)
        if not repo_match:
            print(f"WARNING: could not find expected repo in {script_path.name}'s docstring, skipping")
            continue
        expected_repo = repo_match.group(1)

        metadata_path = CASES_DIR / case_id / "metadata.json"
        if not metadata_path.exists():
            mismatches.append((case_id, expected_repo, "NO metadata.json AT ALL"))
            continue
        actual_repo = json.loads(metadata_path.read_text())["repository"]
        checked += 1
        if actual_repo != expected_repo:
            mismatches.append((case_id, expected_repo, actual_repo))

    print(f"Checked {checked} built Section 9 cases against their build script's own docstring.")
    if mismatches:
        print(f"\nMISMATCHES FOUND: {len(mismatches)} -- case IDs shifted, bundles need relocating before continuing.")
        for case_id, expected, actual in mismatches:
            print(f"  {case_id}: script expects {expected!r}, metadata.json now says {actual!r}")
    else:
        print("All clear -- every built case still maps to the repository its bundle script was written for.")


if __name__ == "__main__":
    main()
