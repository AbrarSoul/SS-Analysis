"""
Builds the test set for the Syntax Review role (design Section 17.2, Section 19), mined from the
EXISTING pilot screening run -- no new curation (design Section 19: "pilot or development data").

Syntax Review Agent responsibilities (Section 17.2): diagnose YAML and Semgrep DSL problems, apply
or recommend the smallest correction, avoid changing rule meaning without an explicit warning.
Selection measurement (Section 19): error-diagnosis rate and compilation-recovery rate.

Three ground-truth categories, derived directly from the pilot run's own real generation records
(no new labels invented):

  YAML_ERROR         : yaml_valid == False -- the raw LLM output never parsed into a valid rule at all.
  SEMGREP_DSL_ERROR   : yaml_valid == True, semgrep_valid == False, and the validation_error is a real
                        Semgrep-level parse/pattern rejection (is_semgrep_parse_error()).
  NOT_A_SYNTAX_ERROR  : yaml_valid == True, semgrep_valid == False, but the error is a plain
                        discrimination miss ("failed to detect.../incorrectly detected...") -- the
                        rule is syntactically fine, just semantically wrong. This category exists to
                        test whether a reviewer correctly recognizes when there ISN'T a syntax
                        problem, matching Section 17.2's "avoid changing rule meaning without an
                        explicit warning."

Sources (pilot screening, autogrep_default prompt, "raw" condition attempt 1):
  results/runs_pilot_screening/<model>__autogrep_default/      -- 6 of 8 pilot models
  results/runs_pilot_rerun_fixed/<model>__autogrep_default/    -- deepseek-coder/magicoder specifically,
      whose results/runs_pilot_screening copies are STALE (pre-dates the extract_response() fence-
      stripping fix -- both show 0/40 yaml_valid in the stale directory, a known, already-documented
      bug, not a new finding here).

Writes benchmark/role_screening/syntax_review_testset.json: up to SAMPLES_PER_CATEGORY items per
category, fixed random seed for reproducibility, each item carrying the broken rule text, the real
error message, the ground-truth category, and enough case/patch info to re-validate a proposed fix.
"""
import json
import os
import random
import sys
from pathlib import Path

os.environ.setdefault("GPTLAB_API_KEY", "not-used-for-mining")  # no network calls happen in this script
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import is_semgrep_parse_error  # noqa: E402
from case_loader import load_case  # noqa: E402
from gptlab_config import build_config  # noqa: E402

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient  # noqa: E402

RESULTS_ROOT = Path(__file__).resolve().parent.parent / "results"
OUT_PATH = Path(__file__).resolve().parent.parent / "benchmark" / "role_screening" / "syntax_review_testset.json"
SAMPLES_PER_CATEGORY = 15
SEED = 20261002

# deepseek-coder/magicoder's results/runs_pilot_screening copies are stale (pre-fix); pull from the
# rerun directory instead for exactly these two.
STALE_IN_MAIN_RUN = {"deepseek-coder:6.7b", "magicoder:7b"}


def _find_raw_capture(model_run_dir: Path, case_id: str):
    """Case ids are scattered across several timestamped run_id subdirectories under raw/ (the pilot
    run spanned several separate invocations) -- search all of them for the one holding this case."""
    for f in (model_run_dir / "raw").glob("*/" + case_id + ".json"):
        return json.loads(f.read_text())
    return None


def _model_run_dirs():
    out = {}
    for d in (RESULTS_ROOT / "runs_pilot_screening").glob("*__autogrep_default"):
        gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
        model = gen[0]["model_tag"] if gen else None
        if model and model not in STALE_IN_MAIN_RUN:
            out[model] = d
    for d in (RESULTS_ROOT / "runs_pilot_rerun_fixed").glob("*__autogrep_default"):
        gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
        model = gen[0]["model_tag"] if gen else None
        if model in STALE_IN_MAIN_RUN:
            out[model] = d
    return out


def _classify(record: dict) -> str:
    if not record["yaml_valid"]:
        return "YAML_ERROR"
    if not record["semgrep_valid"]:
        if is_semgrep_parse_error(record.get("validation_error")):
            return "SEMGREP_DSL_ERROR"
        return "NOT_A_SYNTAX_ERROR"
    return "OK"  # not broken, not useful as a syntax-review test input


def main():
    config = build_config("qwen2.5-coder:7b-instruct")  # only used for its prompt-building/parsing helpers below
    llm_client = LLMClient(config)

    by_category = {"YAML_ERROR": [], "SEMGREP_DSL_ERROR": [], "NOT_A_SYNTAX_ERROR": []}

    for model, d in _model_run_dirs().items():
        gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
        for record in gen:
            if record["condition"] != "raw" or record["attempt_index"] != 1:
                continue
            category = _classify(record)
            if category == "OK":
                continue
            case_id = record["case_id"]
            raw = _find_raw_capture(d, case_id)
            if raw is None:
                continue

            patch_info = load_case(case_id, config)
            if category == "YAML_ERROR":
                # Parsing failed -- there's no sanitized rule dict to show, only the raw extracted text.
                broken_rule_text = llm_client.extract_response(raw["raw_content"])
                error_message = llm_client.last_error or "failed to parse into a valid rule"
            else:
                rule = llm_client.parse_and_sanitize_response(raw["raw_content"], patch_info)
                if rule is None:
                    continue  # shouldn't happen (yaml_valid was True), skip defensively
                import yaml as _yaml
                broken_rule_text = _yaml.dump({"rules": [rule]}, sort_keys=False, default_flow_style=False)
                # For NOT_A_SYNTAX_ERROR specifically, validation_error is genuinely None by construction
                # (sample_evaluation.py's evaluate_case_bundle() only sets it from a real Semgrep execution
                # error -- never just because the TP/FN/FP/TN pattern came out wrong), not a data gap. State
                # that plainly instead of an uninformative placeholder, since the reviewer needs an accurate
                # description of what's actually known to correctly diagnose "no syntax problem here."
                error_message = record.get("validation_error") or (
                    "Semgrep executed this rule without any parse or pattern error. However, it did not "
                    "correctly distinguish the vulnerable version from the patched version of the code "
                    "(no syntax-level error was reported)."
                )

            by_category[category].append({
                "case_id": case_id,
                "source_model": model,
                "category": category,
                "broken_rule_text": broken_rule_text,
                "error_message": error_message,
            })

    random.seed(SEED)
    sampled = []
    for category, items in by_category.items():
        random.shuffle(items)
        sampled.extend(items[:SAMPLES_PER_CATEGORY])
    random.shuffle(sampled)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({
        "purpose": "Syntax Review role-capability screening test set (design Sections 17.2/19)",
        "samples_per_category_requested": SAMPLES_PER_CATEGORY,
        "random_seed": SEED,
        "category_counts_available": {k: len(v) for k, v in by_category.items()},
        "category_counts_sampled": {k: sum(1 for s in sampled if s["category"] == k) for k in by_category},
        "items": sampled,
    }, indent=2))
    print(f"Available before sampling: { {k: len(v) for k, v in by_category.items()} }")
    print(f"Sampled {len(sampled)} items -> {OUT_PATH}")


if __name__ == "__main__":
    main()
