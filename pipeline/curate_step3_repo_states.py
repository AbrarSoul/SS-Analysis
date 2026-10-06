"""
Design doc Section 8 Step 3: Retrieve exact repository states.

For every candidate in the pilot batch:
  1. Fetch the repository (reusing Autogrep's GitManager -- this is also
     where the "accessible repository" check deferred from Step 1 finally
     happens, since it requires a live clone attempt).
  2. Check out the fixing commit.
  3. Resolve the correct vulnerable parent.
  4. Save immutable commit hashes.
  5. Extract relevant files from both revisions.
  6. Save the unified diff.

Design doc: "Do not depend on branch names because branches may move" --
every checkout here uses an explicit commit hash, never a branch name.

Unlike the earlier design_v1 prompt work (Section 10.4 of the Implementation
Log), this extracts COMPLETE file content at both revisions via git directly,
not diff-hunk deltas reconstructed from +/- lines -- a real fidelity upgrade
now that we're doing this per-case rather than needing a fast in-memory scan
across 52,723 patches.

Merge commits are NOT silently resolved via parents[0]: a merge commit has
more than one parent, and which one represents "the vulnerable state before
this fix" is not always parents[0] by default. These are flagged for
separate handling rather than guessed.
"""
import csv
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "autogrep"))
from config import Config  # noqa: E402
from patch_processor import PatchProcessor  # noqa: E402
from git_manager import GitManager  # noqa: E402
import git  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4"
BATCH_CSV = DATA_DIR / "pilot_batch_selection.csv"
PATCHES_DIR = DATA_DIR / "pilot_batch_patches"
REPOS_CACHE_DIR = DATA_DIR / "pilot_repo_cache"

OUT_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "step3_repo_states"
OUT_LOG_CSV = DATA_DIR / "step3_results.csv"


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    config = Config(repos_cache_dir=REPOS_CACHE_DIR)
    pp = PatchProcessor(config)
    gm = GitManager(config)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPOS_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    with open(BATCH_CSV) as f:
        batch = list(csv.DictReader(f))

    # Resume support: skip any filename already recorded in a prior run of
    # this script, so a partial run (timeout, interruption) never has to
    # restart from zero -- each result is also written incrementally below,
    # not just at the very end, for the same reason.
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

    results = []
    for i, entry in enumerate(batch, 1):
        if entry["filename"] in already_done:
            continue
        filename = entry["filename"]
        logging.info(f"[{i}/{len(batch)}] {filename}")
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

        # --- 1. Fetch the repository (also resolves "accessible repository") ---
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

        # --- 3. Resolve the correct vulnerable parent ---
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

        # --- 2. Check out the fixing commit; 5. Extract files from both revisions ---
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

            # --- 6. Save the unified diff -- real git diff, not the
            # delta-only reconstruction used during the bulk zip scan. ---
            real_diff = repo.git.diff(parent_commit_obj.hexsha, fixed_commit_obj.hexsha,
                                       "--", file_change.file_path)

            (case_dir / "vulnerable_source" ).write_text(vulnerable_content)
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

    # Read back the full log (this run's new rows + any resumed-from-prior-run
    # rows) for an accurate summary, rather than just this run's in-memory list.
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
