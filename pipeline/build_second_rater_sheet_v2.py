"""
Builds a FRESH, previously-unused second-rater blinded sample -- a clean redo of the
2026-09/2026-10 second-rater check, using 45 DIFFERENT cases than the first sample (which had some
case-level detail exposed during the 2026-10-06/07 audit conversation, and was rated from
summaries only). Zero overlap with the first sample's 45 cases, guaranteed by explicit exclusion.

Usage: python pipeline/build_second_rater_sheet_v2.py
Writes: benchmark/second_rater_v2/sample_blinded.csv, answer_key_DO_NOT_OPEN_UNTIL_RATED.json
(README_rubric.md is copied unchanged from the original -- the rubric itself isn't case-specific).
"""
import ast
import json
import random
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT / "benchmark"
OUT_DIR = BENCH_DIR / "second_rater_v2"
OUT_DIR.mkdir(exist_ok=True)

PREVIOUS_SAMPLE_CASES = set()
old_csv = BENCH_DIR / "second_rater" / "sample_blinded.csv"
if old_csv.exists():
    import csv
    PREVIOUS_SAMPLE_CASES = {r["case_id"] for r in csv.DictReader(open(old_csv))}

EXCLUDED_POST_HOC = {"CASE-0166"}  # excluded during the audit, don't resample it


def extract_mechanism_summary(case_id: str) -> str:
    script = ROOT / "pipeline" / "section9_final" / f"build_bundle_case{case_id.split('-')[1]}.py"
    if not script.exists():
        return ""
    try:
        doc = ast.get_docstring(ast.parse(script.read_text()))
    except (SyntaxError, ValueError):
        return ""
    if not doc:
        return ""
    lines = doc.strip().splitlines()
    # drop the "Section 9 ground-truth test bundle: CASE-XXXX" header and the "(repo, CVE...)" line
    body = lines[2:] if len(lines) > 2 else lines
    return " ".join(l.strip() for l in body if l.strip())


def main():
    manifest = [json.loads(l) for l in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines()]
    manifest = [r for r in manifest if r["case_id"] not in EXCLUDED_POST_HOC]
    by_label = {"supported": [], "partially_supported": [], "unsupported": []}
    for r in manifest:
        if r["case_id"] in PREVIOUS_SAMPLE_CASES:
            continue
        by_label[r["semgrep_representability"]].append(r)

    rng = random.Random(20261007)  # fresh seed, distinct from whatever the original sheet used
    quota = {"supported": 20, "partially_supported": 15, "unsupported": 10}
    chosen = []
    for label, n in quota.items():
        pool = by_label[label]
        if len(pool) < n:
            raise SystemExit(f"Not enough remaining {label} cases: need {n}, have {len(pool)}")
        chosen.extend(rng.sample(pool, n))

    rng.shuffle(chosen)

    answer_key = {}
    csv_rows = []
    for r in chosen:
        cid = r["case_id"]
        answer_key[cid] = {
            "pattern_or_taint": r["pattern_or_taint"],
            "structural_or_context_heavy": r["context_complexity"],
            "semgrep_representability": r["semgrep_representability"],
        }
        cwe = ";".join(r.get("cwe_ids") or []) or "(none)"
        patch_size = f"+{r['patch_size_added']}/-{r['patch_size_deleted']}"
        summary = extract_mechanism_summary(cid) or "(no build-script summary available -- read the diff directly)"
        csv_rows.append({
            "case_id": cid, "language": r["language"], "repository": r["repository"],
            "cwe": cwe, "lines_changed(+/-)": patch_size,
            "diff_file": f"benchmark/cases/{cid}/patch.diff",
            "mechanism_summary": summary,
            "YOUR_pattern_or_taint": "", "YOUR_structural_or_context_heavy": "",
            "YOUR_semgrep_representability": "", "YOUR_notes": "",
        })

    import csv
    fieldnames = ["row", "case_id", "language", "repository", "cwe", "lines_changed(+/-)", "diff_file",
                  "mechanism_summary", "YOUR_pattern_or_taint", "YOUR_structural_or_context_heavy",
                  "YOUR_semgrep_representability", "YOUR_notes"]
    with open(OUT_DIR / "sample_blinded.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, row in enumerate(csv_rows, 1):
            row["row"] = i
            writer.writerow(row)

    (OUT_DIR / "answer_key_DO_NOT_OPEN_UNTIL_RATED.json").write_text(json.dumps(answer_key, indent=1))

    rubric_src = BENCH_DIR / "second_rater" / "README_rubric.md"
    if rubric_src.exists():
        shutil.copy(rubric_src, OUT_DIR / "README_rubric.md")

    print(f"Wrote {len(chosen)} fresh cases to {OUT_DIR}/sample_blinded.csv")
    print(f"Zero overlap with the previous sample: "
          f"{len(set(c['case_id'] for c in chosen) & PREVIOUS_SAMPLE_CASES)} shared case(s)")


if __name__ == "__main__":
    main()
