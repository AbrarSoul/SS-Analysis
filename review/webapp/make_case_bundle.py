#!/usr/bin/env python3
"""Pack the 154 review cases into one zip that the review server (review/webapp/server.py) loads at start.

Contents:
  cases/<CASE>/...   the case folder as-is (samples, patch.diff, metadata.json), no __pycache__
  stage1.json        Stage 1 auto-check flags and notes per case (the server sends the notes only after
                     the judge locks their own bug location, because they quote vulnerable_lines)

Contains no model results. Normally run by build_data.py; by hand (from the repo root):
  python3 review/webapp/make_case_bundle.py [OUT.zip]   (default: review/webapp/data/case_bundle.zip)
"""
import csv, json, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "benchmark" / "cases"
AUTO = ROOT / "review" / "auto_checks" / "auto_checks.csv"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "review" / "webapp" / "data" / "case_bundle.zip"


def main():
    rows = list(csv.DictReader(open(AUTO)))
    stage1 = {r["case_id"]: {"flags": [f for f in r["flags"].split(";") if f], "notes": r["notes"]} for r in rows}
    n_files = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for cid in stage1:
            d = CASES / cid
            if not d.is_dir():
                sys.exit(f"missing case folder: {d}")
            for f in sorted(d.iterdir()):
                if f.is_file() and not f.name.endswith(".pyc"):
                    z.write(f, f"cases/{cid}/{f.name}")
                    n_files += 1
        z.writestr("stage1.json", json.dumps(stage1, indent=0))
        z.writestr("BUNDLE_INFO.txt", f"{len(stage1)} cases, {n_files} files. Load this zip in the review site.\n")
    print(f"{OUT}: {len(stage1)} cases, {n_files} files, {OUT.stat().st_size/1e6:.1f} MB")


if __name__ == "__main__":
    main()
