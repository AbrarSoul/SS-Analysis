"""
Section 8 Step 7: freeze the manifest for the 40-case pilot partition.

- Stable case IDs: already assigned (CASE-0001..CASE-0040) during pilot
  compilation.
- Hash every artifact: SHA-256 of every file in each case directory,
  plus a case-level hash (SHA-256 of the sorted "path:hash" lines) and a
  single dataset-level hash over all case-level hashes, so any future
  change to any file in the frozen pilot is immediately detectable.
- Merges in the Section 10 schema fields this session can now populate
  from Steps 5-6's output: changed_function, vulnerable_lines,
  context_complexity (Step 6's structural_or_context_heavy, renamed to
  match Section 10's exact field name), patch_size_added/deleted.

Known gaps, deliberately left unpopulated rather than fabricated: ghsa_id,
advisory_date, repository_license, source_urls. Section 10's example
schema includes these, but nothing in Steps 1-6 of this session collected
them, and inventing plausible-looking values for a frozen research
artifact would be worse than leaving them explicitly absent. Flagged here
and in the session summary rather than silently omitted.
"""
import hashlib
import json
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
KNOWN_UNPOPULATED_SCHEMA_FIELDS = ["ghsa_id", "advisory_date", "repository_license", "source_urls"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def find_vulnerable_lines(vuln_source_path: Path, vuln_function_text: str) -> list[int] | None:
    source = vuln_source_path.read_text()
    try:
        start_char = source.index(vuln_function_text.split("... [TRUNCATED")[0][:200])
    except ValueError:
        return None
    start_line = source.count("\n", 0, start_char) + 1
    end_line = start_line + vuln_function_text.count("\n")
    return [start_line, end_line]


def main():
    manifest_lines = [json.loads(line) for line in (BENCH_DIR / "manifest.jsonl").read_text().splitlines() if line.strip()]
    manifest_by_id = {m["case_id"]: m for m in manifest_lines}

    frozen_records = []
    case_level_hashes = {}

    for case_id in sorted(manifest_by_id):
        case_dir = BENCH_DIR / "cases" / case_id
        base = dict(manifest_by_id[case_id])

        context = json.loads((BENCH_DIR / "model_context" / f"{case_id}.json").read_text())
        difficulty = json.loads((BENCH_DIR / "difficulty" / f"{case_id}.json").read_text())

        # changed_function: first line of the extracted vulnerable region,
        # trimmed to a readable label
        first_line = context["vulnerable_function"].splitlines()[0].strip()
        base["changed_function"] = first_line

        vuln_ext = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}[base["language"]]
        vuln_source_path = case_dir / f"vulnerable_source.{vuln_ext}"
        vulnerable_lines = find_vulnerable_lines(vuln_source_path, context["vulnerable_function"])
        base["vulnerable_lines"] = vulnerable_lines

        base["context_complexity"] = difficulty["structural_or_context_heavy"]
        base["pattern_or_taint"] = difficulty["pattern_or_taint"]
        base["patch_size_added"] = difficulty["lines_added"]
        base["patch_size_deleted"] = difficulty["lines_removed"]

        for field in KNOWN_UNPOPULATED_SCHEMA_FIELDS:
            base.setdefault(field, None)

        # hash every artifact in the case directory, excluding incidental
        # build byproducts (e.g. __pycache__/*.pyc from earlier py_compile
        # syntax checks) that are not part of the dataset itself
        artifact_hashes = {}
        for f in sorted(case_dir.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc":
                rel = str(f.relative_to(BENCH_DIR))
                artifact_hashes[rel] = sha256_file(f)
        # also hash this case's Step 5/6 output files
        for extra_path in [
            BENCH_DIR / "model_context" / f"{case_id}.json",
            BENCH_DIR / "difficulty" / f"{case_id}.json",
        ]:
            rel = str(extra_path.relative_to(BENCH_DIR))
            artifact_hashes[rel] = sha256_file(extra_path)

        base["artifact_hashes"] = artifact_hashes

        case_hash_input = "\n".join(f"{k}:{v}" for k, v in sorted(artifact_hashes.items()))
        case_level_hash = hashlib.sha256(case_hash_input.encode()).hexdigest()
        base["case_level_hash"] = case_level_hash
        case_level_hashes[case_id] = case_level_hash

        frozen_records.append(base)

    dataset_hash_input = "\n".join(f"{k}:{v}" for k, v in sorted(case_level_hashes.items()))
    dataset_hash = hashlib.sha256(dataset_hash_input.encode()).hexdigest()

    out_path = BENCH_DIR / "manifest_frozen.jsonl"
    with out_path.open("w") as f:
        for record in frozen_records:
            f.write(json.dumps(record) + "\n")

    freeze_record = {
        "partition": "pilot",
        "case_count": len(frozen_records),
        "frozen_at": "2026-09-20",
        "dataset_hash_sha256": dataset_hash,
        "manifest_file": "manifest_frozen.jsonl",
        "known_unpopulated_schema_fields": KNOWN_UNPOPULATED_SCHEMA_FIELDS,
        "note": (
            "Development (50-case) and final (300-case) partitions have not "
            "been curated yet and are not part of this freeze."
        ),
    }
    (BENCH_DIR / "freeze_record.json").write_text(json.dumps(freeze_record, indent=2) + "\n")

    print(f"Froze {len(frozen_records)} cases.")
    print(f"Dataset hash (pilot partition): {dataset_hash}")
    print(f"Wrote {out_path}")
    print(f"Wrote {BENCH_DIR / 'freeze_record.json'}")


if __name__ == "__main__":
    main()
