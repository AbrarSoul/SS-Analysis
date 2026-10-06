"""
Idempotently applies benchmark/hand_curations.json to the FROZEN dataset.

Some cases were captured by the automated pipeline from the wrong commit
(e.g. a test-only follow-up, or the commit that introduced the bug rather
than the one that fixed it). When the real fix is a small single-file
change, it is hand-curated: the real vulnerable/patched files are fetched
from GitHub and every derived artifact for the case is rebuilt with the
same code paths the pipeline uses.

Entries are keyed by the ORIGINAL pipeline case id (which is stable),
not by CASE-00XX (which shifts on any exclusion). Re-run this script after
every re-run of freeze_manifest_final.py, since that script regenerates
these cases from the original (wrong) pipeline captures.
"""
import difflib
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auto_locate_target import all_hunk_targets, HunkTarget  # noqa: E402
from extract_context_final import (  # noqa: E402
    LOCATOR_BY_LANG, _locate_with_confidence, get_imports_python, get_imports_brace_lang, CWE_DEFS,
)
from classify_difficulty_final import compute_diff_stats  # noqa: E402

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
EXT = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}


def gh_raw(repo, path, sha):
    return subprocess.run(
        ["gh", "api", "-H", "Accept: application/vnd.github.raw", f"repos/{repo}/contents/{path}?ref={sha}"],
        check=True, capture_output=True, text=True).stdout


def sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def make_diff(path, old, new):
    body = list(difflib.unified_diff(old.splitlines(), new.splitlines(), f"a/{path}", f"b/{path}", n=3, lineterm=""))
    header = [f"diff --git a/{path} b/{path}", "index 0000000..0000000 100644"]
    return "\n".join(header + body) + "\n"


def apply_one(entry, records):
    rec = next((r for r in records if r["original_source_case_id"] in
                (entry["old_original_source_case_id"], entry.get("new_original_source_case_id"))), None)
    if rec is None:
        print(f"  no frozen case found for {entry['old_original_source_case_id']} (excluded?) -- skipping")
        return
    case_id, lang = rec["case_id"], rec["language"]
    ext = EXT[lang]
    repo, path = entry["repository"], entry["changed_file"]
    case_dir = BENCH / "cases" / case_id

    old = gh_raw(repo, path, entry["vulnerable_commit"])
    new = gh_raw(repo, path, entry["fixed_commit"])
    diff = make_diff(path, old, new)
    (case_dir / f"vulnerable_source.{ext}").write_text(old)
    (case_dir / f"patched_source.{ext}").write_text(new)
    (case_dir / "patch.diff").write_text(diff)

    hunks = all_hunk_targets(diff)
    locator = LOCATOR_BY_LANG[lang]
    (vtext, cls), cv = _locate_with_confidence(locator, old, hunks, "old")
    (ptext, _), cp = _locate_with_confidence(locator, new, hunks, "new")
    conf = "auto_low_confidence" if "auto_low_confidence" in (cv, cp) else "auto"
    imports = get_imports_python(old) if lang == "python" else get_imports_brace_lang(old)

    ctx_path = BENCH / "model_context" / f"{case_id}.json"
    ctx = json.loads(ctx_path.read_text())
    ctx.update({
        "cwe": [{"id": c, "definition": CWE_DEFS.get(c, "(definition not found)")} for c in rec["cwe_ids"]],
        "containing_class_declaration": cls, "imports": imports,
        "vulnerable_function": vtext, "patched_function": ptext,
        "unified_diff": diff, "auto_locate_confidence": conf,
    })
    ctx_path.write_text(json.dumps(ctx, indent=2) + "\n")

    diff_path = BENCH / "difficulty" / f"{case_id}.json"
    d = json.loads(diff_path.read_text())
    st = compute_diff_stats(diff)
    d.update({"changed_files": st["changed_files"], "lines_added": st["lines_added"],
              "lines_removed": st["lines_removed"], "lines_changed_total": st["lines_changed_total"],
              "function_size_chars": len(vtext), "function_size_lines": vtext.count("\n") + 1,
              "auto_locate_confidence": conf})
    diff_path.write_text(json.dumps(d, indent=2) + "\n")

    probe = vtext[:200]
    start_line = old.count("\n", 0, old.index(probe)) + 1 if probe in old else None
    rec.update({
        "original_source_case_id": entry.get("new_original_source_case_id") or rec["original_source_case_id"],
        "vulnerable_commit": entry["vulnerable_commit"], "fixed_commit": entry["fixed_commit"],
        "changed_file": path, "changed_function": vtext.splitlines()[0].strip(),
        "vulnerable_lines": [start_line, start_line + vtext.count("\n")] if start_line else None,
        "patch_size_added": st["lines_added"], "patch_size_deleted": st["lines_removed"],
        "auto_locate_confidence": conf,
    })
    hashes = {}
    for f in [case_dir / f"vulnerable_source.{ext}", case_dir / f"patched_source.{ext}", case_dir / "patch.diff"]:
        hashes[str(f.relative_to(BENCH))] = sha256_file(f)
    rec.pop("artifact_hashes", None)
    rec.pop("case_level_hash", None)
    (case_dir / "metadata.json").write_text(json.dumps(rec, indent=2) + "\n")
    for f in [ctx_path, diff_path, case_dir / "metadata.json"]:
        hashes[str(f.relative_to(BENCH))] = sha256_file(f)
    rec["artifact_hashes"] = hashes
    rec["case_level_hash"] = hashlib.sha256("\n".join(f"{k}:{v}" for k, v in sorted(hashes.items())).encode()).hexdigest()
    # metadata.json's own hash covers the version WITHOUT the two hash fields, exactly as freeze_manifest_final.py does
    (case_dir / "metadata.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(f"  {case_id} ({repo}): {vtext.splitlines()[0].strip()[:70]!r} conf={conf} +{st['lines_added']}/-{st['lines_removed']}")


def apply_retarget(entry, records):
    """Keeps the frozen files as-is; only re-picks WHICH function is the target,
    by forcing the single hunk at entry['target_old_line'] instead of the
    locator's weight-based choice."""
    rec = next((r for r in records if r["original_source_case_id"] == entry["original_source_case_id"]), None)
    if rec is None:
        print(f"  no frozen case found for {entry['original_source_case_id']} (excluded?) -- skipping")
        return
    case_id, lang = rec["case_id"], rec["language"]
    ext = EXT[lang]
    case_dir = BENCH / "cases" / case_id
    old = (case_dir / f"vulnerable_source.{ext}").read_text()
    new = (case_dir / f"patched_source.{ext}").read_text()
    diff = (case_dir / "patch.diff").read_text()

    if "target_function_header" in entry:
        # Pin the enclosing function by its (unique) header line on BOTH sides, via a synthetic
        # hunk on the header line, for cases where the diff-driven locator lands on a fragment.
        hdr = entry["target_function_header"]
        assert old.count(hdr) == 1 and new.count(hdr) == 1, f"{case_id}: header must occur exactly once per side"
        old_ln = old.count("\n", 0, old.index(hdr)) + 1
        new_ln = new.count("\n", 0, new.index(hdr)) + 1
        hunks = [HunkTarget(old_line=old_ln, new_line=new_ln, changed_line_count=1,
                            has_deletion=True, has_insertion=True)]
    else:
        hunks = [h for h in all_hunk_targets(diff) if h.old_line == entry["target_old_line"]]
        assert len(hunks) == 1, f"{case_id}: expected exactly one hunk at old line {entry['target_old_line']}, got {len(hunks)}"
    locator = LOCATOR_BY_LANG[lang]
    (vtext, cls), _ = _locate_with_confidence(locator, old, hunks, "old")
    (ptext, _), _ = _locate_with_confidence(locator, new, hunks, "new")
    conf = "hand_retargeted"

    ctx_path = BENCH / "model_context" / f"{case_id}.json"
    ctx = json.loads(ctx_path.read_text())
    ctx.update({"containing_class_declaration": cls, "vulnerable_function": vtext,
                "patched_function": ptext, "auto_locate_confidence": conf})
    ctx_path.write_text(json.dumps(ctx, indent=2) + "\n")

    diff_path = BENCH / "difficulty" / f"{case_id}.json"
    d = json.loads(diff_path.read_text())
    d.update({"function_size_chars": len(vtext), "function_size_lines": vtext.count("\n") + 1,
              "auto_locate_confidence": conf})
    diff_path.write_text(json.dumps(d, indent=2) + "\n")

    probe = vtext[:200]
    start_line = old.count("\n", 0, old.index(probe)) + 1 if probe in old else None
    rec.update({"changed_function": vtext.splitlines()[0].strip(),
                "vulnerable_lines": [start_line, start_line + vtext.count("\n")] if start_line else None,
                "auto_locate_confidence": conf})
    hashes = {}
    for f in [case_dir / f"vulnerable_source.{ext}", case_dir / f"patched_source.{ext}", case_dir / "patch.diff"]:
        hashes[str(f.relative_to(BENCH))] = sha256_file(f)
    rec.pop("artifact_hashes", None)
    rec.pop("case_level_hash", None)
    (case_dir / "metadata.json").write_text(json.dumps(rec, indent=2) + "\n")
    for f in [ctx_path, diff_path, case_dir / "metadata.json"]:
        hashes[str(f.relative_to(BENCH))] = sha256_file(f)
    rec["artifact_hashes"] = hashes
    rec["case_level_hash"] = hashlib.sha256("\n".join(f"{k}:{v}" for k, v in sorted(hashes.items())).encode()).hexdigest()
    (case_dir / "metadata.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(f"  {case_id} ({entry['repository']}): retargeted -> {vtext.splitlines()[0].strip()[:70]!r}")


def main():
    entries = json.loads((BENCH / "hand_curations.json").read_text())
    mpath = BENCH / "manifest_frozen_final.jsonl"
    records = [json.loads(l) for l in mpath.read_text().splitlines() if l.strip()]
    for e in entries:
        (apply_retarget if e.get("kind") == "retarget" else apply_one)(e, records)
    mpath.write_text("".join(json.dumps(r) + "\n" for r in records))
    dh = hashlib.sha256("\n".join(f"{r['case_id']}:{r['case_level_hash']}" for r in sorted(records, key=lambda r: r["case_id"])).encode()).hexdigest()
    fr_path = BENCH / "freeze_record_final.json"
    fr = json.loads(fr_path.read_text())
    fr["dataset_hash_sha256"] = dh
    marker = " Post-freeze hand-curations"
    fr["note"] = fr["note"].split(marker)[0] + marker + (
        " (wrong-commit captures whose real fix is a small single-file change; see benchmark/hand_curations.json, "
        "applied idempotently by pipeline/apply_hand_curations.py, which MUST be re-run after any re-run of "
        "freeze_manifest_final.py): " + "; ".join(
            f"{e['repository']} ({e['fixed_commit'][:7]})" for e in entries if e.get("kind") != "retarget") +
        "; retargeted (function re-picked by hand, files unchanged): " + ", ".join(
            e["repository"] for e in entries if e.get("kind") == "retarget") +
        ". See Implementation_Log.md Section 12.16.")
    fr_path.write_text(json.dumps(fr, indent=2) + "\n")
    print(f"dataset hash: {dh}")


if __name__ == "__main__":
    main()
