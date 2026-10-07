"""
Design doc Section 8 Step 2: deduplicate the target-language candidates
matched to CVE/CWE data (data/morefixes_v4/candidates_with_cve_cwe.csv)
using:
  - CVE and GHSA identifiers  -> same CVE appearing via multiple distinct
    patch files (different commit/repo); logged, not auto-resolved (see
    "multi-patch CVEs" below -- these are often legitimately complex
    multi-commit security releases, not duplicates).
  - Repository and commit hash -> verified unique by construction (each
    patch file's filename IS its repo+commit), checked here anyway.
  - Same-commit-different-representation -> discovered while investigating
    exact-content duplicates: some pairs are the literal same git commit
    object appearing twice under a short hash vs full hash, a repo-name
    casing difference, or a repo rename/transfer (GitHub preserves commit
    hashes across renames and most forks). These are true duplicates and
    are EXCLUDED here, not just flagged, per Section 7.2's "duplicated
    commits" criterion.
  - Near-duplicate changed code -> the remaining byte-identical-content
    groups where the commit hashes are genuinely different (not a
    prefix/casing/rename relationship). These are NOT auto-excluded --
    flagged for case-level review during Step 3/4, since a coincidentally
    small/simple patch can legitimately collide, and blanket-dropping here
    would remove real, independent cases without evidence they're the same
    underlying fix.
  - Multiple records referring to the same fix -> one commit mapped to more
    than one CVE row in `fixes` (see map_candidates_to_cve_cwe.py);
    consolidated into one row with all CVE ids, not dropped.

Every exclusion decision made here is written to the exclusion log with a
specific reason and the filename that was kept instead -- nothing is
silently dropped.
"""
import csv
import hashlib
import zipfile
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4"
ZIP_PATH = DATA_DIR / "patch-files2026-06-20.zip"
JOINED_CSV = DATA_DIR / "candidates_with_cve_cwe.csv"

OUT_DEDUP_LOG = DATA_DIR / "dedup_log.csv"
OUT_EXCLUSION_LOG = DATA_DIR / "dedup_exclusions.csv"
OUT_CLEAN_CANDIDATES = DATA_DIR / "candidates_deduplicated.csv"


def normalize_patch_content(raw: bytes) -> str:
    """Strip index lines (blob hashes change even for byte-identical diffs
    due to unrelated repo state) and surrounding whitespace, keep the
    actual +/- content, so truly identical changes hash identically
    regardless of incidental diff-header noise."""
    lines = []
    for line in raw.decode("utf-8", errors="replace").split("\n"):
        if line.startswith("index "):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def extract_commit_hash(filename: str) -> str:
    return filename.rsplit("_", 1)[-1].replace(".patch", "")


def is_same_commit_representation(filename_a: str, filename_b: str) -> bool:
    """True if these two filenames represent the literal same git commit
    object under a different guise: one hash is a prefix of the other
    (short vs full hash), or the hashes are identical but owner/name
    differ (repo rename, transfer, or case-only difference)."""
    hash_a = extract_commit_hash(filename_a).lower()
    hash_b = extract_commit_hash(filename_b).lower()
    if hash_a == hash_b:
        return True
    if hash_a.startswith(hash_b) or hash_b.startswith(hash_a):
        return True
    return False


def main():
    with open(JOINED_CSV) as f:
        rows = list(csv.DictReader(f))
    print(f"Loaded {len(rows)} (patch, CVE) rows across {len(set(r['filename'] for r in rows))} distinct patches")

    # --- 1. Repository+commit hash uniqueness (sanity check) ---
    repo_commit_pairs = defaultdict(list)
    for r in rows:
        repo_commit_pairs[(r["repo_url"], r["hash"])].append(r["filename"])
    collisions = {k: v for k, v in repo_commit_pairs.items() if len(set(v)) > 1}
    print(f"[1] Repo+commit pairs mapping to >1 distinct filename: {len(collisions)} (expect 0)")

    # --- 2. Multiple CVE records for the same patch (commit fixes >1 CVE) ---
    filename_to_cves = defaultdict(set)
    for r in rows:
        if r["cve_id"]:
            filename_to_cves[r["filename"]].add(r["cve_id"])
    multi_cve_patches = {f: cves for f, cves in filename_to_cves.items() if len(cves) > 1}
    print(f"[2] Patches mapping to >1 CVE id: {len(multi_cve_patches)}")

    # --- 3. Same CVE reachable via multiple distinct patches ---
    cve_to_filenames = defaultdict(set)
    for r in rows:
        if r["cve_id"]:
            cve_to_filenames[r["cve_id"]].add(r["filename"])
    multi_patch_cves = {c: fs for c, fs in cve_to_filenames.items() if len(fs) > 1}
    print(f"[3] CVEs reachable via >1 distinct patch file: {len(multi_patch_cves)}")

    # --- 4. Normalized patch-content hash collisions across different (repo, commit) ---
    distinct_filenames = sorted(set(r["filename"] for r in rows))
    content_hash_to_filenames = defaultdict(list)
    with zipfile.ZipFile(ZIP_PATH) as zf:
        namelist_by_basename = {Path(n).name: n for n in zf.namelist() if n.endswith(".patch")}
        for filename in distinct_filenames:
            zip_entry = namelist_by_basename.get(filename)
            if zip_entry is None:
                continue
            raw = zf.read(zip_entry)
            normalized = normalize_patch_content(raw)
            h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            content_hash_to_filenames[h].append(filename)

    exact_content_dupes = {h: fs for h, fs in content_hash_to_filenames.items() if len(fs) > 1}
    print(f"[4] Distinct (repo,commit) patches with byte-identical normalized content: {len(exact_content_dupes)} groups")

    # --- 4b. Split those groups: same-commit-different-representation
    # (excluded now) vs genuinely different commits with identical content
    # (flagged for later review, not excluded). ---
    excluded_filenames = {}  # filename -> (reason, kept_filename)
    near_duplicate_review = []  # groups of genuinely different commits, identical content

    for content_hash, filenames in exact_content_dupes.items():
        # Union-find-lite: group filenames within this content-duplicate set
        # that are also same-commit-representations of each other.
        remaining = list(filenames)
        same_commit_clusters = []
        while remaining:
            seed = remaining.pop(0)
            cluster = [seed]
            still_remaining = []
            for other in remaining:
                if any(is_same_commit_representation(other, c) for c in cluster):
                    cluster.append(other)
                else:
                    still_remaining.append(other)
            remaining = still_remaining
            same_commit_clusters.append(cluster)

        for cluster in same_commit_clusters:
            if len(cluster) > 1:
                # Keep the longest (fullest) hash; tie-break alphabetically.
                kept = max(cluster, key=lambda fn: (len(extract_commit_hash(fn)), fn))
                for fn in cluster:
                    if fn != kept:
                        excluded_filenames[fn] = ("same_commit_different_representation", kept)

        # Whatever clusters remain as size-1 but still shared the SAME
        # normalized content hash across DIFFERENT real commits -> flag for
        # review, do not exclude.
        surviving = [c[0] for c in same_commit_clusters if len(c) == 1]
        if len(surviving) > 1:
            near_duplicate_review.append(surviving)

    print(f"[4b] Same-commit-different-representation exclusions: {len(excluded_filenames)}")
    print(f"[4b] Genuinely-different-commit near-duplicate-content groups (flagged, not excluded): {len(near_duplicate_review)}")

    # --- Write dedup review log (informational, no exclusions implied) ---
    with open(OUT_DEDUP_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["dedup_reason", "group_key", "filenames"])
        for k, v in collisions.items():
            writer.writerow(["repo_commit_collision", str(k), ";".join(v)])
        for f_, cves in multi_cve_patches.items():
            writer.writerow(["multi_cve_per_patch", f_, ";".join(sorted(cves))])
        for c, fs in multi_patch_cves.items():
            writer.writerow(["cve_via_multiple_patches", c, ";".join(sorted(fs))])
        for group in near_duplicate_review:
            writer.writerow(["near_duplicate_content_different_commits", "", ";".join(sorted(group))])

    # --- Write exclusion log (actual decisions, with reasons) ---
    with open(OUT_EXCLUSION_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["excluded_filename", "reason", "kept_filename_instead"])
        for fn, (reason, kept) in sorted(excluded_filenames.items()):
            writer.writerow([fn, reason, kept])

    # --- Build the deduplicated candidate table ---
    filename_to_content_group = {}
    for h, fs in content_hash_to_filenames.items():
        if len(fs) > 1:
            for f_ in fs:
                filename_to_content_group[f_] = h[:12]

    per_filename = {}
    for r in rows:
        if r["filename"] in excluded_filenames:
            continue
        entry = per_filename.setdefault(r["filename"], {
            "filename": r["filename"], "repo_url": r["repo_url"], "hash": r["hash"],
            "cve_ids": set(), "cwe_ids": set(), "max_score": 0, "rel_types": set(),
        })
        if r["cve_id"]:
            entry["cve_ids"].add(r["cve_id"])
        if r["cwe_ids"]:
            entry["cwe_ids"].update(r["cwe_ids"].split(";"))
        entry["max_score"] = max(entry["max_score"], int(r["score"]) if r["score"] else 0)
        if r["rel_type"]:
            entry["rel_types"].add(r["rel_type"])

    with open(OUT_CLEAN_CANDIDATES, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["filename", "repo_url", "hash", "cve_ids", "cwe_ids",
                          "max_score", "rel_types", "near_duplicate_content_group"])
        for filename, e in sorted(per_filename.items()):
            writer.writerow([
                e["filename"], e["repo_url"], e["hash"],
                ";".join(sorted(e["cve_ids"])), ";".join(sorted(e["cwe_ids"])),
                e["max_score"], ";".join(sorted(e["rel_types"])),
                filename_to_content_group.get(filename) or "",
            ])

    print()
    print(f"Dedup review log (informational) -> {OUT_DEDUP_LOG}")
    print(f"Exclusion log (actual decisions)  -> {OUT_EXCLUSION_LOG}")
    print(f"Deduplicated candidate table ({len(per_filename)} unique patches, "
          f"{len(excluded_filenames)} excluded) -> {OUT_CLEAN_CANDIDATES}")


if __name__ == "__main__":
    main()
