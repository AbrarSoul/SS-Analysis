"""
Builds a consolidated, human-readable review packet per language: for every
Step-3-surviving case, the real advisory description (GitHub or NVD
fallback), the real diff, and basic metadata -- everything needed to
actually judge Section 8 Step 4's five criteria by reading, not scripting.
"""
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data" / "morefixes_v4"
CASES_DIR = ROOT / "benchmark" / "step3_repo_states"
STEP4_RESULTS = json.loads((DATA_DIR / "step4_advisory_results.json").read_text())

OUT_DIR = ROOT / "data" / "morefixes_v4" / "review_packets"
OUT_DIR.mkdir(exist_ok=True)


def get_description(case_id: str) -> tuple:
    v = STEP4_RESULTS.get(case_id, {})
    for cve_id, adv in v.get("advisories_by_cve", {}).items():
        for a in adv.get("advisories", []):
            reviewed = a.get("type") == "reviewed" or bool(a.get("github_reviewed_at"))
            return (cve_id, a.get("description") or a.get("summary") or "", "GitHub", reviewed)
    for cve_id, nvd in v.get("nvd_fallback", {}).items():
        if nvd.get("found"):
            return (cve_id, nvd.get("description", ""), "NVD", None)
    return (None, "(no description available)", None, None)


def main():
    by_language = defaultdict(list)
    for case_dir in sorted(CASES_DIR.iterdir()):
        if not case_dir.is_dir():
            continue
        metadata_file = case_dir / "metadata.json"
        diff_file = case_dir / "patch.diff"
        if not metadata_file.exists() or not diff_file.exists():
            continue
        metadata = json.loads(metadata_file.read_text())
        by_language[metadata["language"]].append((case_dir, metadata))

    for language, cases in by_language.items():
        out_path = OUT_DIR / f"{language}_review_packet.txt"
        with open(out_path, "w") as f:
            for case_dir, metadata in cases:
                case_id = metadata["case_id"]
                cve_id, description, source, reviewed = get_description(case_id)
                refactor_flag = STEP4_RESULTS.get(case_id, {}).get("refactor_only_heuristic", False)
                diff_text = (case_dir / "patch.diff").read_text()

                f.write("=" * 100 + "\n")
                f.write(f"CASE: {case_id}\n")
                f.write(f"Repository: {metadata['repository']}\n")
                f.write(f"CVE: {cve_id}  CWE(morefixes): {metadata.get('cwe_ids')}\n")
                f.write(f"Advisory source: {source} (github_reviewed={reviewed})\n")
                f.write(f"Refactor-only heuristic flag: {refactor_flag}\n")
                f.write(f"Changed file: {metadata['changed_file']}\n")
                f.write(f"Vulnerable commit: {metadata['vulnerable_commit']}\n")
                f.write(f"Fixed commit: {metadata['fixed_commit']}\n")
                f.write(f"\nADVISORY DESCRIPTION:\n{description}\n")
                f.write(f"\nDIFF (length {len(diff_text)} chars):\n{diff_text}\n\n")

        print(f"{language}: {len(cases)} cases -> {out_path}")


if __name__ == "__main__":
    main()
