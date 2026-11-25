#!/usr/bin/env python3
"""Prepare review/webapp/data/ for the review server (run from anywhere, before `fly deploy`).

  data/case_bundle.zip   the 154 case folders + stage1.json (built by review/webapp/make_case_bundle.py)
  data/case_index.json   blind-safe case list: public CVE facts and Stage 1 flag names only.
                         Leaves out why a case is in Batch 1 (chosen from model outcomes), earlier
                         exclusion reasons, and vulnerable_lines (the server reveals those per case,
                         only after the judge locks their own bug location).
  data/example_record.md the worked example shown in Help (review/examples/records/R1/CASE-0075.md)

Contains no model results.
"""
import csv, json, shutil, subprocess, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "data"
EXAMPLE_CASE = "CASE-0075"


def main():
    OUT.mkdir(exist_ok=True)
    subprocess.run([sys.executable, str(ROOT / "review/webapp/make_case_bundle.py"), str(OUT / "case_bundle.zip")], check=True)
    z = zipfile.ZipFile(OUT / "case_bundle.zip")
    ac = list(csv.DictReader(open(ROOT / "review/auto_checks/auto_checks.csv")))
    ref = {r["case_id"]: r for r in csv.DictReader(open(ROOT / "benchmark/all_cases_reference.csv"))}
    index = []
    for a in ac:
        cid, r = a["case_id"], ref[a["case_id"]]
        md = json.loads(z.read(f"cases/{cid}/metadata.json"))
        ghsa = md.get("ghsa_id") or ""
        index.append({
            "id": cid, "b": 1 if a["priority_38"] == "yes" else 2, "ex": a["status"].startswith("excluded"),
            "lang": a["language"], "cve": a["cve_id"], "cwe": [c for c in a["cwe_ids"].split(";") if c],
            "repo": r["repository"], "file": r["changed_file"],
            "rep": r["semgrep_representability"], "pt": r["pattern_or_taint"], "cx": r["context_complexity"],
            "v": r["vulnerable_commit"], "f": r["fixed_commit"], "ghsa": ghsa if ghsa.startswith("GHSA-") else "",
            "flags": [f for f in a["flags"].split(";") if f], "example": cid == EXAMPLE_CASE,
        })
    index.sort(key=lambda o: (o["b"], o["id"]))
    (OUT / "case_index.json").write_text(json.dumps(index, separators=(",", ":")))
    shutil.copyfile(ROOT / f"review/examples/records/R1/{EXAMPLE_CASE}.md", OUT / "example_record.md")
    print(f"data/: {len(index)} cases ({sum(o['b'] == 1 for o in index)} in Batch 1), example {EXAMPLE_CASE}")


if __name__ == "__main__":
    main()
