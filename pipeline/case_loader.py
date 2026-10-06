"""
Loads a curated benchmark/cases/CASE-XXXX case (design doc Section 10
manifest + Section 8 Step 5 model context, both built during Phase 2 pilot
curation) into a PatchInfo carrying real CVE/CWE/function data, instead of
the placeholder/diff-derived data the raw-.patch-file flow uses.

file_changes.changes is still populated from patch.diff via
PatchProcessor's own diff-parsing (reused, not reimplemented), so
_build_prompt_autogrep_default() and the unified-diff block in
_build_prompt_design_v1() keep working exactly as before; only the new
optional PatchInfo fields differ from the raw-.patch-file flow.
"""
import json
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "autogrep"))
from patch_processor import PatchInfo, PatchProcessor  # noqa: E402
from config import Config  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"

_EXT_BY_LANGUAGE = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}


def list_case_ids() -> List[str]:
    return sorted(p.name for p in (BENCH_DIR / "cases").iterdir() if p.is_dir() and p.name.startswith("CASE-"))


def load_case(case_id: str, config: Config) -> PatchInfo:
    case_dir = BENCH_DIR / "cases" / case_id
    metadata = json.loads((case_dir / "metadata.json").read_text())
    context = json.loads((BENCH_DIR / "model_context" / f"{case_id}.json").read_text())

    # Mirrors PatchProcessor.process_patch()'s own diff-to-FileChange
    # parsing exactly (only +/- content lines kept, joined with '\n'; no
    # filename-convention parsing needed since we already have repo/commit
    # from metadata.json), so file_changes.changes matches what the
    # raw-.patch-file flow would have produced for the same diff.
    from patch_processor import FileChange
    processor = PatchProcessor(config)
    diff_text = (case_dir / "patch.diff").read_text()

    file_changes: List[FileChange] = []
    current_file = None
    changes: List[str] = []
    for line in diff_text.split('\n'):
        if line.startswith('diff --git'):
            if current_file:
                language = processor.get_language_from_file(current_file)
                if language:
                    file_changes.append(FileChange(file_path=current_file, changes='\n'.join(changes), language=language))
            current_file = line.split()[-1][2:]  # strip "b/" prefix
            changes = []
        elif current_file and line.startswith(('+', '-')):
            changes.append(line)
    if current_file:
        language = processor.get_language_from_file(current_file)
        if language:
            file_changes.append(FileChange(file_path=current_file, changes='\n'.join(changes), language=language))

    assert file_changes, f"{case_id}: diff parsing produced no file changes"

    cwe_defs_table = json.loads((BENCH_DIR / "cwe_definitions.json").read_text())
    cwe_ids = metadata["cwe_ids"]
    cwe_definitions = [cwe_defs_table.get(c, "(definition not found)") for c in cwe_ids]

    repo_owner, repo_name = metadata["repository"].split("/", 1)

    return PatchInfo(
        repo_owner=repo_owner,
        repo_name=repo_name,
        commit_id=metadata["fixed_commit"],
        file_changes=file_changes,
        case_id=case_id,
        cve_id=metadata["cve_id"],
        cwe_ids=cwe_ids,
        cwe_definitions=cwe_definitions,
        vulnerable_function=context["vulnerable_function"],
        patched_function=context["patched_function"],
        containing_class_declaration=context.get("containing_class_declaration"),
        imports=context.get("imports"),
    )
