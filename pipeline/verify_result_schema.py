"""
Step 5 verification: builds real GenerationRecord and SampleExecutionRecord
rows from Steps 2-4's actual output (not synthetic placeholder data), by
re-executing the already-generated qwen2.5-coder rule against the real
checked-out vulnerable/patched commits (reusing RuleValidator._run_semgrep
rather than reinventing subprocess-semgrep calls), round-trips everything
through JSONL, and confirms the case-level aggregation helpers produce the
correct outcome.

This only covers the original_vulnerable/original_patched pair -- the
transformed-variant and benign-lookalike samples don't exist yet, since
those are produced during dataset curation (Phase 2/4), not Phase 1
infrastructure. That's expected; this is a schema/pipeline verification,
not a full case evaluation.
"""
import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_schema import (  # noqa: E402
    GenerationRecord, SampleExecutionRecord, append_jsonl, read_jsonl,
    case_confusion_counts, patch_discrimination_hit,
    vulnerability_generalization_recall, matthews_correlation_coefficient,
    make_run_id,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "autogrep"))
from config import Config  # noqa: E402
from rule_validator import RuleValidator  # noqa: E402
import git  # noqa: E402
import yaml  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CASE_ID = "github.com_aio-libs_aiohttp_1c335944d6a8b1298baf179b7c0b3069f10c514b"
COMMIT = "1c335944d6a8b1298baf179b7c0b3069f10c514b"
# From the patch hunk header itself: @@ -573,9 +573,14 @@ -- 9 lines starting
# at line 573 in the original (vulnerable) file.
CHANGED_LINES_VULNERABLE = range(573, 582)

QWEN_DIR = REPO_ROOT / "results" / "smoke_test" / "qwen2.5-coder_7b-instruct"
DEEPSEEK_DIR = REPO_ROOT / "results" / "smoke_test" / "deepseek-coder_6.7b"


def load_raw(run_dir: Path, case_id: str) -> dict:
    return json.loads((run_dir / "raw" / f"{case_id}.json").read_text())


def finding_lines(results) -> list:
    lines = []
    for r in results:
        start = r.get("start", {}).get("line")
        if start is not None:
            lines.append(start)
    return lines


def build_qwen_records(run_id: str):
    raw = load_raw(QWEN_DIR, CASE_ID)
    rule_path = QWEN_DIR / "generated_rules" / "python" / "vuln-aiohttp-1c335944.yml"
    rule = yaml.safe_load(rule_path.read_text())["rules"][0]

    gen_record = GenerationRecord(
        run_id=run_id, case_id=CASE_ID, model_tag="qwen2.5-coder:7b-instruct",
        host="GPU-farmi-001", condition="raw", attempt_index=1,
        temperature=raw["temperature"], max_retries=3,
        yaml_valid=True, semgrep_valid=True,
        rule_id=rule["id"], rule_path=str(rule_path),
        timestamp=raw["timestamp"],
    )

    config = Config()
    validator = RuleValidator(config)
    repo_path = QWEN_DIR / "cache" / "repos" / "aio-libs_aiohttp"
    repo = git.Repo(repo_path)
    target_rel = "aiohttp/web_urldispatcher.py"

    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
        yaml.dump({"rules": [rule]}, tf)
        rule_file = tf.name

    try:
        repo.git.checkout(repo.commit(COMMIT).parents[0])  # vulnerable version
        vuln_results, _ = validator._run_semgrep(rule_file, str(repo_path / target_rel))

        repo.git.checkout(COMMIT)  # patched version
        patched_results, _ = validator._run_semgrep(rule_file, str(repo_path / target_rel))
    finally:
        repo.git.checkout(COMMIT)
        Path(rule_file).unlink(missing_ok=True)

    vuln_lines = finding_lines(vuln_results)
    vuln_location_ok = any(l in CHANGED_LINES_VULNERABLE for l in vuln_lines) if vuln_lines else None

    sample_vuln = SampleExecutionRecord(
        run_id=run_id, case_id=CASE_ID, model_tag="qwen2.5-coder:7b-instruct",
        condition="raw", sample_type="original_vulnerable", label="positive",
        detected=bool(vuln_results), finding_location_correct=vuln_location_ok,
        finding_lines=vuln_lines or None,
    )
    sample_patched = SampleExecutionRecord(
        run_id=run_id, case_id=CASE_ID, model_tag="qwen2.5-coder:7b-instruct",
        condition="raw", sample_type="original_patched", label="negative",
        detected=bool(patched_results),
        finding_lines=finding_lines(patched_results) or None,
    )
    return gen_record, [sample_vuln, sample_patched]


def build_deepseek_record(run_id: str):
    raw = load_raw(DEEPSEEK_DIR, CASE_ID)
    return GenerationRecord(
        run_id=run_id, case_id=CASE_ID, model_tag="deepseek-coder:6.7b",
        host="GPU-farmi-004", condition="raw", attempt_index=1,
        temperature=raw["temperature"], max_retries=3,
        yaml_valid=False, semgrep_valid=False,
        validation_error="Malformed YAML in raw response (unparseable after cleanup)",
        timestamp=raw["timestamp"],
    )


def main():
    run_id = make_run_id("phase1-step5-verification")
    gen_log = REPO_ROOT / "results" / "run_log_verification.jsonl"
    sample_log = REPO_ROOT / "results" / "sample_execution_log_verification.jsonl"
    for p in (gen_log, sample_log):
        if p.exists():
            p.unlink()

    qwen_gen, qwen_samples = build_qwen_records(run_id)
    deepseek_gen = build_deepseek_record(run_id)

    append_jsonl([qwen_gen, deepseek_gen], gen_log)
    append_jsonl(qwen_samples, sample_log)

    print("=== Round-tripped GenerationRecords ===")
    for r in read_jsonl(gen_log, GenerationRecord):
        print(r)

    print("\n=== Round-tripped SampleExecutionRecords ===")
    loaded_samples = read_jsonl(sample_log, SampleExecutionRecord)
    for r in loaded_samples:
        print(r)

    print("\n=== Case-level aggregation (qwen2.5-coder:7b-instruct, this one case) ===")
    counts = case_confusion_counts(loaded_samples)
    print(f"Confusion counts: {counts}")
    print(f"Patch discrimination hit: {patch_discrimination_hit(loaded_samples)}")
    print(f"VGR (no variants generated yet, expected None): {vulnerability_generalization_recall(loaded_samples)}")
    print(f"MCC: {matthews_correlation_coefficient(counts)}")


if __name__ == "__main__":
    main()
