"""
Design doc Section 8 Step 3 for the 300-case FINAL dataset (Phase 4) -- the
same procedure curate_step3_repo_states.py ran for the pilot, pointed at
topup23_batch_selection.csv's 375 candidates instead. See that script's
docstring for the full rationale (explicit commit hashes only, merge commits
flagged not guessed, real git diff extraction); unchanged here.

Adds one step the pilot version didn't need: extracting each candidate's
raw .patch file out of the MoreFixes zip into its own batch-specific patches
directory, since topup23_batch_selection.csv's candidates were never
previously extracted (only the pilot's 96 were).
"""
import csv
import json
import logging
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "autogrep"))
from config import Config  # noqa: E402
from patch_processor import PatchProcessor  # noqa: E402
from git_manager import GitManager  # noqa: E402
import git  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4"
BATCH_CSV = DATA_DIR / "topup23_batch_selection.csv"
PATCHES_ZIP = DATA_DIR / "patch-files2026-06-20.zip"
PATCHES_DIR = DATA_DIR / "topup23_batch_patches"
REPOS_CACHE_DIR = DATA_DIR / "topup23_repo_cache"

OUT_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "step3_repo_states_topup23"
OUT_LOG_CSV = DATA_DIR / "step3_results_topup23.csv"


def extract_patch_files(batch):
    PATCHES_DIR.mkdir(parents=True, exist_ok=True)
    wanted = {entry["filename"] for entry in batch}
    already = {p.name for p in PATCHES_DIR.glob("*.patch")}
    missing = wanted - already
    if not missing:
        logging.info(f"All {len(wanted)} patch files already extracted")
        return
    logging.info(f"Extracting {len(missing)} of {len(wanted)} patch files from {PATCHES_ZIP.name}")
    with zipfile.ZipFile(PATCHES_ZIP) as zf:
        namelist = {Path(n).name: n for n in zf.namelist() if n.endswith(".patch")}
        not_found = []
        for fn in missing:
            entry = namelist.get(fn)
            if entry is None:
                not_found.append(fn)
                continue
            (PATCHES_DIR / fn).write_bytes(zf.read(entry))
        if not_found:
            logging.warning(f"{len(not_found)} filenames from the batch were not found in the zip: {not_found[:5]}...")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    with open(BATCH_CSV) as f:
        batch = list(csv.DictReader(f))
    # Same filename can appear twice in the batch CSV (once per matched
    # language, e.g. a .tsx file tagged both javascript and typescript) --
    # dedupe by filename for the repo-state extraction itself, since the
    # underlying vulnerable/patched file content is identical either way.
    seen = set()
    unique_batch = []
    for entry in batch:
        if entry["filename"] not in seen:
            seen.add(entry["filename"])
            unique_batch.append(entry)
    logging.info(f"{len(batch)} batch rows -> {len(unique_batch)} unique candidates")

    extract_patch_files(unique_batch)

    config = Config(repos_cache_dir=REPOS_CACHE_DIR)
    pp = PatchProcessor(config)
    gm = GitManager(config)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPOS_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    already_done = set()
    fieldnames = ["filename", "cve_ids", "cwe_ids", "language", "status", "reason",
                  "vulnerable_commit", "fixed_commit", "changed_file", "is_merge_commit"]
    if OUT_LOG_CSV.exists():
        with open(OUT_LOG_CSV) as f:
            for row in csv.DictReader(f):
                already_done.add(row["filename"])
        print(f"Resuming: {len(already_done)} already processed in a prior run")

    log_file = open(OUT_LOG_CSV, "a", newline="")
    log_writer = csv.DictWriter(log_file, fieldnames=fieldnames)
    if OUT_LOG_CSV.stat().st_size == 0:
        log_writer.writeheader()
        log_file.flush()

    def emit(result):
        log_writer.writerow(result)
        log_file.flush()

    for i, entry in enumerate(unique_batch, 1):
        if entry["filename"] in already_done:
            continue
        filename = entry["filename"]
        logging.info(f"[{i}/{len(unique_batch)}] {filename}")
        result = {
            "filename": filename, "cve_ids": entry["cve_ids"], "cwe_ids": entry["cwe_ids"],
            "language": entry["language"], "status": None, "reason": None,
            "vulnerable_commit": None, "fixed_commit": entry["hash"],
            "changed_file": None, "is_merge_commit": False,
        }

        patch_file = PATCHES_DIR / filename
        if not patch_file.exists():
            result["status"] = "excluded"
            result["reason"] = "patch file missing from extracted batch"
            emit(result)
            continue

        patch_info = pp.process_patch(patch_file)
        if patch_info is None:
            result["status"] = "excluded"
            result["reason"] = "patch_processor could not parse this patch"
            emit(result)
            continue

        repo_path = gm.prepare_repo(patch_info)
        if repo_path is None:
            result["status"] = "excluded"
            result["reason"] = "repository inaccessible (clone failed or commit not found)"
            emit(result)
            continue

        try:
            repo = git.Repo(repo_path)
            fixed_commit_obj = repo.commit(patch_info.commit_id)
        except Exception as e:
            result["status"] = "excluded"
            result["reason"] = f"fixing commit not resolvable: {e}"
            emit(result)
            continue

        parents = fixed_commit_obj.parents
        if len(parents) == 0:
            result["status"] = "excluded"
            result["reason"] = "fixing commit has no parent (initial commit) -- no 'before' state exists"
            emit(result)
            continue
        if len(parents) > 1:
            result["is_merge_commit"] = True
            result["status"] = "flagged_for_review"
            result["reason"] = (
                f"fixing commit is a merge with {len(parents)} parents -- "
                f"which one represents the vulnerable pre-fix state is not "
                f"assumable via parents[0], needs manual resolution"
            )
            emit(result)
            continue

        parent_commit_obj = parents[0]
        result["vulnerable_commit"] = parent_commit_obj.hexsha

        file_change = patch_info.file_changes[0]
        result["changed_file"] = file_change.file_path

        case_dir = OUT_DIR / filename.replace(".patch", "")
        case_dir.mkdir(parents=True, exist_ok=True)

        try:
            repo.git.checkout(parent_commit_obj.hexsha, force=True)
            vuln_path = repo_path / file_change.file_path
            vulnerable_content = vuln_path.read_text(errors="replace") if vuln_path.exists() else None

            repo.git.checkout(fixed_commit_obj.hexsha, force=True)
            patched_path = repo_path / file_change.file_path
            patched_content = patched_path.read_text(errors="replace") if patched_path.exists() else None

            if vulnerable_content is None or patched_content is None:
                result["status"] = "excluded"
                result["reason"] = (
                    f"file missing at one revision (vuln={'ok' if vulnerable_content else 'MISSING'}, "
                    f"patched={'ok' if patched_content else 'MISSING'}) -- likely file was added/deleted, "
                    f"not modified"
                )
                emit(result)
                continue

            real_diff = repo.git.diff(parent_commit_obj.hexsha, fixed_commit_obj.hexsha,
                                       "--", file_change.file_path)

            (case_dir / "vulnerable_source").write_text(vulnerable_content)
            (case_dir / "patched_source").write_text(patched_content)
            (case_dir / "patch.diff").write_text(real_diff)
            (case_dir / "metadata.json").write_text(json.dumps({
                "case_id": filename.replace(".patch", ""),
                "cve_ids": entry["cve_ids"].split(";") if entry["cve_ids"] else [],
                "cwe_ids": entry["cwe_ids"].split(";") if entry["cwe_ids"] else [],
                "language": entry["language"],
                "repository": patch_info.repo_owner + "/" + patch_info.repo_name,
                "repository_url": entry["repo_url"],
                "vulnerable_commit": parent_commit_obj.hexsha,
                "fixed_commit": fixed_commit_obj.hexsha,
                "changed_file": file_change.file_path,
                "max_score": entry["max_score"],
            }, indent=2))

            result["status"] = "ok"
        except Exception as e:
            result["status"] = "excluded"
            result["reason"] = f"error during checkout/extraction: {e}"
        finally:
            try:
                gm.reset_repo(repo_path)
            except Exception:
                pass

        emit(result)

    log_file.close()

    with open(OUT_LOG_CSV) as f:
        all_results = list(csv.DictReader(f))

    status_counts = {}
    for r in all_results:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    print()
    print("=== Step 3 results (cumulative, including any resumed prior run) ===")
    for status, count in status_counts.items():
        print(f"  {status}: {count}")
    print(f"Log written to {OUT_LOG_CSV}")
    print(f"Extracted case states written to {OUT_DIR}")


if __name__ == "__main__":
    main()
