"""
Runs a candidate model against the Rule Repair role-capability test set (design Sections 17.2/19).

Rule Repair Agent responsibilities (Section 17.2): revise the rule using deterministic diagnostics
and review output, preserve correct rule components, stop after three repair rounds. Expected output:
a revised executable rule. Selection measurement (Section 19): repair success and regression rate.

Reuses the SAME 45-item test set `build_syntax_review_testset.py` mined (broken rule + real error,
3 ground-truth categories) rather than mining a second, separate data set -- all three categories
represent "a rule that failed and needs repair" from this role's perspective (per Section 17.1's
workflow, Rule Repair is invoked after Semantic Review diagnoses ANY failure type, not just syntax
ones). The prompt here is framed differently from the syntax-review one: it asks directly for a
revised rule and explicitly instructs preserving correct components, rather than asking for a
diagnosis first -- testing whether a repair-specific framing does better than a diagnosis-then-fix
framing, not just reusing syntax review's own proposed-fix numbers.

Measurement, both newly operationalized here (the design doc does not give exact formulas for either,
only the names -- documented as methodology choices):

  - repair success rate: the revised rule, re-validated for real (RuleValidator.validate_rule(), same
    clone-free machinery as everywhere else), now passes on the case's actual original
    vulnerable/patched pair.
  - regression rate: among repair-SUCCESS cases only, does the revised rule, when run against the
    FULL six-sample bundle (evaluate_case_bundle()), produce a false positive on either negative
    bundle sample (variant_safe, benign_lookalike)? There is no "before" bundle execution to diff
    against for a rule that was broken from the start, so "regression" is operationalized here as
    "the fix that made it pass the narrow pair check is overly broad enough to misfire elsewhere in
    the same case's bundle" -- the most grounded regression-like signal available without inventing
    synthetic multi-round repair state.

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_rule_repair.py --models qwen2.5-coder:32b,DeepHat/DeepHat-V1-7B,qwen3-coder-next:latest
"""
import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS  # noqa: E402
from case_loader import load_case  # noqa: E402
from sample_evaluation import evaluate_case_bundle  # noqa: E402

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient  # noqa: E402
from rule_validator import RuleValidator  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
TESTSET_PATH = BENCH_DIR / "role_screening" / "syntax_review_testset.json"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results" / "role_screening_rule_repair"


def _load_frozen_manifest_index() -> dict:
    index = {}
    for name in ("manifest_frozen.jsonl", "manifest_frozen_final.jsonl"):
        path = BENCH_DIR / name
        if path.exists():
            for line in path.read_text().splitlines():
                if line.strip():
                    record = json.loads(line)
                    index[record["case_id"]] = record
    return index


def build_prompt(item: dict) -> str:
    return f"""You are repairing a Semgrep rule that failed. Revise it so it correctly detects the
vulnerable code and does NOT match the patched code. Preserve every part of the rule that is already
correct -- change only what is actually broken. Do not change what vulnerability the rule is trying
to detect.

RULE:
{item['broken_rule_text']}

OBSERVED ERROR / EXECUTION RESULT:
{item['error_message']}

Respond with ONLY the complete revised Semgrep YAML rule. No explanation, no markdown fence commentary,
just the YAML."""


def run_model(model_tag: str, items: list, frozen_manifest: dict, partial_jsonl_path: Path):
    config = build_config(model_tag, temperature=0.0, prompt_variant="autogrep_default")
    llm_client = LLMClient(config)
    validator = RuleValidator(config)

    # Resume-safety: a prior invocation may have been cut off partway (e.g. a background-task time
    # limit, as happened live on the DeepHat run 2026-10-02) -- skip items already recorded. An
    # errored attempt (e.g. a request timeout) does NOT count as done. Keyed by (case_id, category,
    # source_model), NOT case_id alone -- the SAME case_id can appear more than once in this test set
    # under different categories/source models (confirmed: 45 items, only 31 unique case_ids alone,
    # but all 45 unique once category+source_model are included); case_id alone would silently
    # collapse genuinely distinct test items. Found and fixed after an identical bug caused a real,
    # silent item loss on a semantic-review run (run_semantic_review.py, same pattern).
    def _full_key(r):
        return (r["case_id"], r["category"], r["source_model"])

    by_key = {}
    if partial_jsonl_path.exists():
        for line in partial_jsonl_path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                by_key[_full_key(r)] = r
    results = [r for r in by_key.values() if not r.get("error")]
    already_done = {k for k, r in by_key.items() if not r.get("error")}
    if by_key:
        logging.info(f"[{model_tag}] resuming: {len(already_done)}/{len(items)} item(s) already done "
                     f"({len(by_key) - len(already_done)} prior error(s) will be retried)")

    for item in items:
        if _full_key(item) in already_done:
            continue
        prompt = build_prompt(item)
        try:
            response = llm_client.client.chat.completions.create(
                model=model_tag,
                messages=[
                    {"role": "system", "content": "You are a precise Semgrep rule repair specialist."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=2048,
            )
            content = response.choices[0].message.content
        except Exception as e:
            logging.error(f"[{model_tag}/{item['case_id']}] generation error: {e}")
            record = {**item, "repair_success": False, "regression": None,
                      "raw_response": None, "error": str(e)}
            results.append(record)
            with open(partial_jsonl_path, "a") as f:
                f.write(json.dumps(record) + "\n")
            continue

        patch_info = load_case(item["case_id"], config)
        rule = llm_client.parse_and_sanitize_response(content, patch_info)
        repair_success = False
        regression = None

        if rule is not None:
            repo_path_marker = Path(f"<curated-case:{item['case_id']}>")
            is_valid, _ = validator.validate_rule(rule, patch_info, repo_path_marker)
            repair_success = is_valid

            if repair_success:
                case_dir = BENCH_DIR / "cases" / item["case_id"]
                language = patch_info.file_changes[0].language
                frozen = frozen_manifest.get(item["case_id"], {})
                sample_records, _ = evaluate_case_bundle(
                    rule, case_dir, language, validator,
                    "role-screening", item["case_id"], model_tag, "rule_repair",
                    vulnerable_lines=frozen.get("vulnerable_lines"),
                )
                regression = any(
                    s.sample_type in ("variant_safe", "benign_lookalike") and s.outcome == "FP"
                    for s in sample_records
                )

        record = {
            **item,
            "repair_success": repair_success,
            "regression": regression,
            "raw_response": content,
        }
        results.append(record)
        with open(partial_jsonl_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        logging.info(f"[{model_tag}/{item['case_id']}] truth={item['category']} "
                     f"repair_success={repair_success} regression={regression}")

    return results


def score(results: list) -> dict:
    n = len(results)
    successes = [r for r in results if r["repair_success"]]
    regressions = [r for r in successes if r.get("regression")]

    per_category = {}
    for cat in ("YAML_ERROR", "SEMGREP_DSL_ERROR", "NOT_A_SYNTAX_ERROR"):
        cat_results = [r for r in results if r["category"] == cat]
        cat_success = [r for r in cat_results if r["repair_success"]]
        per_category[cat] = {
            "n": len(cat_results),
            "repair_success_rate": len(cat_success) / len(cat_results) if cat_results else None,
        }

    return {
        "n_items": n,
        "overall_repair_success_rate": len(successes) / n if n else None,
        "n_successes": len(successes),
        "regression_rate": len(regressions) / len(successes) if successes else None,
        "per_category": per_category,
    }


def main():
    parser = argparse.ArgumentParser(description="Rule Repair role-capability screening runner.")
    parser.add_argument("--models", required=True, help="Comma-separated model tags.")
    parser.add_argument("--limit", type=int, default=None, help="Only run the first N test items (for verification).")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="%(asctime)s - %(levelname)s - %(message)s")

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    for m in models:
        if m not in MODEL_HOSTS:
            parser.error(f"Unknown model tag: {m}")

    testset = json.loads(TESTSET_PATH.read_text())
    items = testset["items"]
    if args.limit is not None:
        items = items[:args.limit]
    logging.info(f"Loaded {len(items)} test items ({testset['category_counts_sampled']})")
    frozen_manifest = _load_frozen_manifest_index()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for model_tag in models:
        safe_name = model_tag.replace("/", "_").replace(":", "_")
        partial_jsonl_path = RESULTS_DIR / f"{safe_name}.partial.jsonl"
        results = run_model(model_tag, items, frozen_manifest, partial_jsonl_path)
        out_path = RESULTS_DIR / f"{safe_name}.json"
        scores = score(results)
        out_path.write_text(json.dumps({"model_tag": model_tag, "scores": scores, "results": results}, indent=2))
        logging.info(f"[{model_tag}] overall_repair_success_rate={scores['overall_repair_success_rate']:.3f} "
                     f"regression_rate={scores['regression_rate']} -> {out_path}")


if __name__ == "__main__":
    main()
