"""
Top-up selection for the 300-case final dataset: after Steps 3-5, three
groups (Python, Java, JavaScript+TypeScript) landed short of the 100-per-
group target because 36 of the original 375-candidate batch turned out to
have no usable, automatically-extractable context (genuine dependency-
version-only changes, module-level-only changes, and two files that don't
even parse as modern Python -- a mislabeled Cython file and one using
legacy Python 2 octal-literal syntax). Rather than force those 36 into the
schema or hand-resolve each one, pulls fresh replacement candidates from
the same eligible pool used for the original 375, at the same ~80%
oversampling rate, excluding every candidate already tried (both the
pilot's 96 AND all 375 from the original final batch) so nothing gets
selected twice.

Per-group top-up target set from the actual shortfall after Step 5:
Python needs +16 (84 usable of 100), Java needs +10 (90 of 100),
JavaScript+TypeScript needs +10 (90 of 100) -- oversampled at the same
~1.5x-2x margin as the original batch selection to comfortably cover that
shortfall even after this batch's own Step 3/4/5 attrition.
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

OUT_BATCH = DATA_DIR / "topup_batch_selection.csv"

RANDOM_SEED = 20260923  # fixed for reproducibility; distinct from both prior seeds

GROUP_BY_LANG = {
    "python": "python",
    "java": "java",
    "javascript": "javascript_typescript",
    "typescript": "javascript_typescript",
}

PER_GROUP_TARGET = {
    "python": 25,
    "java": 16,
    "javascript_typescript": 16,
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
    for csv_path in (PILOT_BATCH_CSV, FINAL_BATCH_CSV):
        with open(csv_path) as f:
            for row in csv.DictReader(f):
                already_tried.add(row["filename"])
    print(f"Excluding {len(already_tried)} filenames already tried (pilot + original final batch)")

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
            entry = namelist.get(fn)
            if entry is None:
                continue
            content = zf.read(entry).decode("utf-8", errors="replace")
            touched = [ln.split()[-1][2:] for ln in content.split("\n")
                       if ln.startswith("diff --git") and len(ln.split()) >= 4]
            recognized = [t for t in touched if pp.get_language_from_file(t)]
            if len(recognized) != 1:
                continue

            langs = lang_by_filename.get(fn, [])
            cwe_ids = [c for c in r["cwe_ids"].split(";") if c]
            primary_cwe = cwe_ids[0] if cwe_ids else "NO_CWE"
            groups_hit = set(GROUP_BY_LANG[lang] for lang in langs if lang in GROUP_BY_LANG)
            for group in groups_hit:
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
