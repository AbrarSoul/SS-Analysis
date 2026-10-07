"""
Selects a stratified working batch for the 30-case pilot dataset, oversampled
to allow for attrition during Section 8 Steps 3-4 (some repos will turn out
to be inaccessible, some advisories won't confirm the automated CVE match).

Selection criteria, all decisions explicit and documented:
  - Single-file changes only (recognized-language files), per Section 7.1's
    stated preference for one-file fixes in the primary benchmark -- and
    because Phase 1 confirmed Autogrep itself does NOT enforce this, so it
    must happen here, at curation time.
  - Highest-confidence CVE match only (score == 1337, i.e. a direct
    GHSA/NVD-linked commit, not a heuristic Prospector guess) -- since
    Section 5.2 already warns MoreFixes candidates aren't automatically
    ground truth, starting from the most trustworthy matches available
    gives Step 4's verification the best chance of actually confirming
    rather than rejecting.
  - Stratified across the 3 target languages AND across distinct CWE
    categories within each language (not just the single most common CWE
    repeated 24 times), to give the eventual 30-case pilot real coverage
    breadth rather than a narrow slice.
  - No candidate from Section 8.2's "near-duplicate-content, different
    commits" review list (274 groups) is selected, out of caution -- if a
    case is later needed from that pool it can be added deliberately with
    the near-duplicate relationship explicitly noted, not by accident.

Per-language target: 24 candidates (aiming for ~10 to survive Steps 3-4).
"""
import csv
import random
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4"
CANDIDATES_CSV = DATA_DIR / "candidates_deduplicated.csv"
TARGET_LANG_FILE = DATA_DIR / "target_language_candidates.txt"
DEDUP_LOG = DATA_DIR / "dedup_log.csv"

OUT_BATCH = DATA_DIR / "pilot_batch_selection.csv"

PER_LANGUAGE_TARGET = 24
RANDOM_SEED = 20260913  # fixed for reproducibility; documented, not hidden


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

    with open(CANDIDATES_CSV) as f:
        candidates = list(csv.DictReader(f))
    print(f"Total deduplicated candidates: {len(candidates)}")

    # Need single-file status; recompute from the zip once here rather than
    # re-deriving per language separately (kept simple, this script is a
    # one-off selection step, not part of the recurring pipeline).
    import zipfile
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "autogrep"))
    from patch_processor import PatchProcessor
    from config import Config
    pp = PatchProcessor(Config())

    eligible_by_lang_cwe = defaultdict(lambda: defaultdict(list))
    with zipfile.ZipFile(DATA_DIR / "patch-files2026-06-20.zip") as zf:
        namelist = {Path(n).name: n for n in zf.namelist() if n.endswith(".patch")}
        for r in candidates:
            fn = r["filename"]
            if fn in near_dup_filenames:
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
            for lang in langs:
                eligible_by_lang_cwe[lang][primary_cwe].append(r)

    selected = []
    for lang in sorted(eligible_by_lang_cwe.keys()):
        cwe_groups = eligible_by_lang_cwe[lang]
        cwe_list = sorted(cwe_groups.keys())
        print(f"\n{lang}: {sum(len(v) for v in cwe_groups.values())} eligible "
              f"(single-file, high-confidence, not flagged near-duplicate) "
              f"across {len(cwe_list)} distinct primary CWEs")

        # Round-robin across CWE categories until PER_LANGUAGE_TARGET reached,
        # so we don't end up with 24 copies of the single most common CWE.
        chosen = []
        cwe_pools = {c: list(v) for c, v in cwe_groups.items()}
        for pool in cwe_pools.values():
            random.shuffle(pool)
        cwe_cycle = list(cwe_pools.keys())
        i = 0
        while len(chosen) < PER_LANGUAGE_TARGET and any(cwe_pools.values()):
            cwe = cwe_cycle[i % len(cwe_cycle)]
            if cwe_pools[cwe]:
                chosen.append(cwe_pools[cwe].pop())
            i += 1
            if i > 10000:
                break
        selected.extend(chosen)
        chosen_cwes = sorted(set((c["cwe_ids"].split(";") or ["NONE"])[0] for c in chosen))
        print(f"  Selected {len(chosen)} candidates covering CWEs: {chosen_cwes}")

    with open(OUT_BATCH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["filename", "repo_url", "hash", "cve_ids", "cwe_ids", "max_score", "language"])
        for r in selected:
            fn = r["filename"]
            for lang in lang_by_filename.get(fn, []):
                writer.writerow([fn, r["repo_url"], r["hash"], r["cve_ids"], r["cwe_ids"], r["max_score"], lang])

    print(f"\nTotal selected for pilot batch: {len(selected)}")
    print(f"Written to {OUT_BATCH}")


if __name__ == "__main__":
    main()
