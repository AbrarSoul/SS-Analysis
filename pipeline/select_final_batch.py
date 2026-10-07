"""
Selects a stratified working batch for the 300-case FINAL dataset (design doc
Section 29 Phase 4), oversampled to allow for attrition during Section 8
Steps 3-4, the same way select_pilot_batch.py did for the pilot.

Differences from the pilot batch selection, both deliberate:

  - Excludes every candidate already selected for the pilot batch (all 96,
    not just the 40 that ended up used) -- the final 300-case set must be
    built from cases the pilot never touched (Section 6.0.1), and excluding
    the full 96 rather than just the 40 used is the more conservative
    reading of that requirement: none of these candidates were exposed to
    us during pilot screening / prompt selection, full stop.

  - JavaScript and TypeScript are stratified as ONE combined group, not two
    separate ones -- Section 6.1 explicitly keeps JS/TS combined at 100
    cases for the final set (unlike the pilot's deliberate 10+10 split
    documented in Section 6.0.1). Python and Java remain their own groups.

  - Per-group target is 125, not 24. The pilot's own observed yield from
    "selected candidate" to "survives Steps 3-4 advisory verification" was
    77/96 = ~80%. Applying that same rate here: 125 selected per group x
    0.80 = ~100 expected survivors per group, matching Section 6.1's
    100/100/100 target directly (rather than the pilot's looser
    "oversample enough to comfortably reach 10" approach, since we now
    have a real observed yield rate to apply instead of a rough guess).

Selection criteria otherwise identical to the pilot's (single-file changes
only, highest-confidence CVE match [score == 1337], no near-duplicate-content
candidates, stratified across CWE categories within each group) -- see
select_pilot_batch.py's own docstring for why each of these was chosen;
unchanged here since the same Section 7/8 requirements apply to both sets.
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

OUT_BATCH = DATA_DIR / "final_batch_selection.csv"

PER_GROUP_TARGET = 125
RANDOM_SEED = 20260922  # fixed for reproducibility; distinct from the pilot's seed, documented not hidden

# Section 6.1: JS/TS combined as one group for the final set, unlike the
# pilot's separate 10+10 split (Section 6.0.1).
GROUP_BY_LANG = {
    "python": "python",
    "java": "java",
    "javascript": "javascript_typescript",
    "typescript": "javascript_typescript",
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

    pilot_filenames = set()
    with open(PILOT_BATCH_CSV) as f:
        for row in csv.DictReader(f):
            pilot_filenames.add(row["filename"])
    print(f"Excluding {len(pilot_filenames)} filenames already selected for the pilot batch")

    with open(CANDIDATES_CSV) as f:
        candidates = list(csv.DictReader(f))
    print(f"Total deduplicated candidates: {len(candidates)}")

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
            if fn in near_dup_filenames or fn in pilot_filenames:
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
            # A candidate can carry both a "javascript" and "typescript" tag
            # (e.g. a .tsx file) -- dedupe to its GROUP, not per raw language,
            # so it's only ever placed into javascript_typescript once.
            groups_hit = set(GROUP_BY_LANG[lang] for lang in langs if lang in GROUP_BY_LANG)
            for group in groups_hit:
                eligible_by_group_cwe[group][primary_cwe].append((r, [l for l in langs if GROUP_BY_LANG.get(l) == group]))

    selected = []  # list of (record, langs_to_write)
    for group in sorted(eligible_by_group_cwe.keys()):
        cwe_groups = eligible_by_group_cwe[group]
        cwe_list = sorted(cwe_groups.keys())
        total_eligible = sum(len(v) for v in cwe_groups.values())
        print(f"\n{group}: {total_eligible} eligible "
              f"(single-file, high-confidence, not near-duplicate, not in pilot batch) "
              f"across {len(cwe_list)} distinct primary CWEs")

        chosen = []
        cwe_pools = {c: list(v) for c, v in cwe_groups.items()}
        for pool in cwe_pools.values():
            random.shuffle(pool)
        cwe_cycle = list(cwe_pools.keys())
        i = 0
        while len(chosen) < PER_GROUP_TARGET and any(cwe_pools.values()):
            cwe = cwe_cycle[i % len(cwe_cycle)]
            if cwe_pools[cwe]:
                chosen.append(cwe_pools[cwe].pop())
            i += 1
            if i > 200000:
                break
        selected.extend(chosen)
        chosen_cwes = sorted(set(rec["cwe_ids"].split(";")[0] if rec["cwe_ids"] else "NONE" for rec, _ in chosen))
        print(f"  Selected {len(chosen)} candidates (target {PER_GROUP_TARGET}) covering CWEs: {chosen_cwes}")
        if len(chosen) < PER_GROUP_TARGET:
            print(f"  WARNING: only {len(chosen)}/{PER_GROUP_TARGET} available for {group} -- pool exhausted")

    with open(OUT_BATCH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["filename", "repo_url", "hash", "cve_ids", "cwe_ids", "max_score", "language"])
        for r, langs in selected:
            for lang in langs:
                writer.writerow([r["filename"], r["repo_url"], r["hash"], r["cve_ids"], r["cwe_ids"], r["max_score"], lang])

    print(f"\nTotal selected for final batch: {len(selected)}")
    print(f"Written to {OUT_BATCH}")


if __name__ == "__main__":
    main()
