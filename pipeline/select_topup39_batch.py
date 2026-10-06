"""
Top-up 39 selection: 1 java replacement for CASE-0337 (xwiki DefaultHQLStatementValidator typo-only diff); topup38's four java candidates were all merge commits flagged at Step 3. See exclusion_log.csv.
"""
import csv
import random
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4"
CANDIDATES_CSV = DATA_DIR / "candidates_deduplicated.csv"
TARGET_LANG_FILE = DATA_DIR / "target_language_candidates.txt"
DEDUP_LOG = DATA_DIR / "dedup_log.csv"
PILOT_BATCH_CSV = DATA_DIR / "pilot_batch_selection.csv"
FINAL_BATCH_CSV = DATA_DIR / "final_batch_selection.csv"
TOPUP_BATCH_CSV = DATA_DIR / "topup_batch_selection.csv"
TOPUP2_BATCH_CSV = DATA_DIR / "topup2_batch_selection.csv"
TOPUP3_BATCH_CSV = DATA_DIR / "topup3_batch_selection.csv"
TOPUP4_BATCH_CSV = DATA_DIR / "topup4_batch_selection.csv"
TOPUP5_BATCH_CSV = DATA_DIR / "topup5_batch_selection.csv"
TOPUP6_BATCH_CSV = DATA_DIR / "topup6_batch_selection.csv"
TOPUP7_BATCH_CSV = DATA_DIR / "topup7_batch_selection.csv"
TOPUP8_BATCH_CSV = DATA_DIR / "topup8_batch_selection.csv"
TOPUP9_BATCH_CSV = DATA_DIR / "topup9_batch_selection.csv"
TOPUP10_BATCH_CSV = DATA_DIR / "topup10_batch_selection.csv"
TOPUP11_BATCH_CSV = DATA_DIR / "topup11_batch_selection.csv"
TOPUP12_BATCH_CSV = DATA_DIR / "topup12_batch_selection.csv"

TOPUP13_BATCH_CSV = DATA_DIR / "topup13_batch_selection.csv"
TOPUP14_BATCH_CSV = DATA_DIR / "topup14_batch_selection.csv"
TOPUP15_BATCH_CSV = DATA_DIR / "topup15_batch_selection.csv"
TOPUP16_BATCH_CSV = DATA_DIR / "topup16_batch_selection.csv"
TOPUP17_BATCH_CSV = DATA_DIR / "topup17_batch_selection.csv"
TOPUP18_BATCH_CSV = DATA_DIR / "topup18_batch_selection.csv"
TOPUP19_BATCH_CSV = DATA_DIR / "topup19_batch_selection.csv"
TOPUP20_BATCH_CSV = DATA_DIR / "topup20_batch_selection.csv"
TOPUP21_BATCH_CSV = DATA_DIR / "topup21_batch_selection.csv"
TOPUP22_BATCH_CSV = DATA_DIR / "topup22_batch_selection.csv"
TOPUP23_BATCH_CSV = DATA_DIR / "topup23_batch_selection.csv"
TOPUP24_BATCH_CSV = DATA_DIR / "topup24_batch_selection.csv"
TOPUP25_BATCH_CSV = DATA_DIR / "topup25_batch_selection.csv"
TOPUP31_BATCH_CSV = DATA_DIR / "topup35_batch_selection.csv"
OUT_BATCH = DATA_DIR / "topup39_batch_selection.csv"

# original id of the last built case CASE-0332 (typescript/whyour qinglong); only later-sorting candidates keep built ids stable
AFTER_ID = "github.com_whyour_qinglong_6bec52dca158481258315ba0fc2f11206df7b719"

RANDOM_SEED = 20260928009  # fixed for reproducibility; distinct from all prior seeds

GROUP_BY_LANG = {
    "python": "python",
    "java": "java",
    "javascript": "javascript_typescript",
    "typescript": "javascript_typescript",
}

# CASE-0327 was javascript. Oversampled at ~3x to comfortably survive this batch's own Step 3/4/5 attrition
# even though only 1 is needed.
PER_GROUP_TARGET = {
    "java": 10,
}


def main():
    random.seed(RANDOM_SEED)

    lang_by_filename = {}
    with open(TARGET_LANG_FILE) as f:
        for line in f:
            fn, langs = line.rstrip("\n").split("\t")
            lang_by_filename[fn] = langs.split(",")

    near_dup_filenames = set()
    with open(DEDUP_LOG) as f:
        for row in csv.DictReader(f):
            if row["dedup_reason"] == "near_duplicate_content_different_commits":
                near_dup_filenames.update(row["filenames"].split(";"))

    already_tried = set()
    for csv_path in [PILOT_BATCH_CSV, FINAL_BATCH_CSV] + sorted(p_ for p_ in DATA_DIR.glob("topup*_batch_selection.csv") if p_ != OUT_BATCH):
        with open(csv_path) as f:
            for row in csv.DictReader(f):
                already_tried.add(row["filename"])
    print(f"Excluding {len(already_tried)} filenames already tried (pilot + final + topup..topup35)")

    with open(CANDIDATES_CSV) as f:
        candidates = list(csv.DictReader(f))

    import zipfile
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "autogrep"))
    from patch_processor import PatchProcessor
    from config import Config
    pp = PatchProcessor(Config())

    eligible_by_group_cwe = defaultdict(lambda: defaultdict(list))
    with zipfile.ZipFile(DATA_DIR / "patch-files2026-06-20.zip") as zf:
        namelist = {Path(n).name: n for n in zf.namelist() if n.endswith(".patch")}
        for r in candidates:
            fn = r["filename"]
            if fn in near_dup_filenames or fn in already_tried:
                continue
            if r["max_score"] != "1337":
                continue
            if not fn.startswith("github.com_") or fn <= AFTER_ID:
                continue
            entry = namelist.get(fn)
            if entry is None:
                continue
            content = zf.read(entry).decode("utf-8", errors="replace")
            touched = [ln.split()[-1][2:] for ln in content.split("\n")
                       if ln.startswith("diff --git") and len(ln.split()) >= 4]
            recognized = [t for t in touched if pp.get_language_from_file(t)]
            if len(recognized) != 1:
                continue
            # skip patches whose only touched code file is a test file (no production change to learn from)
            low = recognized[0].lower()
            if "/test/" in low or "/tests/" in low or "/__tests__/" in low or Path(low).name.startswith("test_") \
                    or Path(low).stem.endswith(("test", "tests", "spec")):
                continue

            langs = lang_by_filename.get(fn, [])
            cwe_ids = [c for c in r["cwe_ids"].split(";") if c]
            primary_cwe = cwe_ids[0] if cwe_ids else "NO_CWE"
            groups_hit = set(GROUP_BY_LANG[lang] for lang in langs if lang in GROUP_BY_LANG)
            for group in groups_hit:
                if group not in PER_GROUP_TARGET:
                    continue
                eligible_by_group_cwe[group][primary_cwe].append((r, [l for l in langs if GROUP_BY_LANG.get(l) == group]))

    selected = []
    for group in sorted(eligible_by_group_cwe.keys()):
        target = PER_GROUP_TARGET[group]
        cwe_groups = eligible_by_group_cwe[group]
        total_eligible = sum(len(v) for v in cwe_groups.values())
        print(f"\n{group}: {total_eligible} eligible, target {target}")

        chosen = []
        cwe_pools = {c: list(v) for c, v in cwe_groups.items()}
        for pool in cwe_pools.values():
            random.shuffle(pool)
        cwe_cycle = list(cwe_pools.keys())
        i = 0
        while len(chosen) < target and any(cwe_pools.values()):
            cwe = cwe_cycle[i % len(cwe_cycle)]
            if cwe_pools[cwe]:
                chosen.append(cwe_pools[cwe].pop())
            i += 1
            if i > 200000:
                break
        selected.extend(chosen)
        print(f"  Selected {len(chosen)}/{target}")

    with open(OUT_BATCH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["filename", "repo_url", "hash", "cve_ids", "cwe_ids", "max_score", "language"])
        for r, langs in selected:
            for lang in langs:
                writer.writerow([r["filename"], r["repo_url"], r["hash"], r["cve_ids"], r["cwe_ids"], r["max_score"], lang])

    print(f"\nTotal selected for top-up batch: {len(selected)}")
    print(f"Written to {OUT_BATCH}")


if __name__ == "__main__":
    main()
