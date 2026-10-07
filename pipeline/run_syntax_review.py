"""
Runs a candidate model against the Syntax Review role-capability test set (design Sections 17.2/19).

Prompt format and response schema are a new methodology choice (the design doc specifies only the
abstract "expected output": diagnosis or corrected rule -- not a literal template), documented here
rather than left implicit: the model is asked to classify the problem into exactly one of the three
ground-truth categories build_syntax_review_testset.py uses, explain briefly, and either propose a
corrected rule or state NONE if it judges there is no syntax problem (directly operationalizing
Section 17.2's "avoid changing rule meaning without an explicit warning" -- a reviewer that always
proposes a "fix" regardless of category would score 0 on NOT_A_SYNTAX_ERROR items specifically, since
there's nothing to measure a bogus "fix" against but the diagnosis label itself).

Measurement (Section 19's "error-diagnosis and compilation-recovery rate"):
  - error-diagnosis accuracy: predicted category == ground-truth category, over all items.
  - compilation-recovery rate: for YAML_ERROR/SEMGREP_DSL_ERROR items only (the two categories where a
    real fix is possible), does the model's proposed corrected rule now pass real Semgrep validation
    against the case's actual original vulnerable/patched pair (RuleValidator.validate_rule(), the
    same clone-free machinery every other phase uses)? Computed only when the model actually proposed
    a rule -- a model that never proposes a fix cannot be credited with "recovering" anything, and
    that's reflected as a 0, not excluded from the denominator.

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_syntax_review.py --models qwen2.5-coder:7b-instruct,magicoder:7b
"""
import argparse
import json
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS  # noqa: E402
from case_loader import load_case  # noqa: E402

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient  # noqa: E402
from rule_validator import RuleValidator  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
TESTSET_PATH = BENCH_DIR / "role_screening" / "syntax_review_testset.json"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results" / "role_screening_syntax_review"
CATEGORIES = ("YAML_ERROR", "SEMGREP_DSL_ERROR", "NOT_A_SYNTAX_ERROR")


def build_prompt(item: dict) -> str:
    return f"""You are reviewing a Semgrep rule that a code-generation model produced. Your job is
syntax review only: diagnose whether the problem is a YAML-level error, a Semgrep-pattern-DSL-level
error, or not a syntax problem at all (the rule may simply be semantically wrong, which is a
different reviewer's job, not yours). Apply or recommend only the SMALLEST correction needed -- never
change what the rule is trying to detect.

RULE:
{item['broken_rule_text']}

OBSERVED ERROR / EXECUTION RESULT:
{item['error_message']}

Respond in EXACTLY this format, nothing else:
DIAGNOSIS: <one of: YAML_ERROR, SEMGREP_DSL_ERROR, NOT_A_SYNTAX_ERROR>
EXPLANATION: <one or two sentences>
CORRECTED_RULE:
<a complete corrected Semgrep YAML rule if DIAGNOSIS is YAML_ERROR or SEMGREP_DSL_ERROR, or the exact
word NONE if DIAGNOSIS is NOT_A_SYNTAX_ERROR>"""


def parse_response(content: str):
    diag_match = re.search(r"DIAGNOSIS:\s*(\w+)", content)
    diagnosis = diag_match.group(1).strip().upper() if diag_match else None
    if diagnosis not in CATEGORIES:
        diagnosis = None

    corrected_match = re.search(r"CORRECTED_RULE:\s*(.*)", content, flags=re.DOTALL)
    corrected_text = corrected_match.group(1).strip() if corrected_match else ""
    proposed_none = bool(re.match(r"^NONE\b", corrected_text, flags=re.IGNORECASE))
    return diagnosis, (None if proposed_none or not corrected_text else corrected_text)


def run_model(model_tag: str, items: list):
    config = build_config(model_tag, temperature=0.0, prompt_variant="autogrep_default")
    llm_client = LLMClient(config)
    validator = RuleValidator(config)

    results = []
    for item in items:
        prompt = build_prompt(item)
        try:
            response = llm_client.client.chat.completions.create(
                model=model_tag,
                messages=[
                    {"role": "system", "content": "You are a precise Semgrep rule syntax reviewer."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=2048,
            )
            content = response.choices[0].message.content
        except Exception as e:
            logging.error(f"[{model_tag}/{item['case_id']}] generation error: {e}")
            results.append({**item, "predicted_category": None, "proposed_fix_compiled": None,
                             "raw_response": None, "error": str(e)})
            continue

        predicted_category, corrected_text = parse_response(content)

        fix_compiled = None
        if corrected_text is not None:
            patch_info = load_case(item["case_id"], config)
            rule = llm_client.parse_and_sanitize_response(corrected_text, patch_info)
            if rule is None:
                fix_compiled = False
            else:
                repo_path_marker = Path(f"<curated-case:{item['case_id']}>")
                is_valid, _ = validator.validate_rule(rule, patch_info, repo_path_marker)
                fix_compiled = is_valid

        results.append({
            **item,
            "predicted_category": predicted_category,
            "diagnosis_correct": predicted_category == item["category"],
            "proposed_fix": corrected_text,
            "proposed_fix_compiled": fix_compiled,
            "raw_response": content,
        })
        logging.info(f"[{model_tag}/{item['case_id']}] truth={item['category']} "
                     f"predicted={predicted_category} fix_compiled={fix_compiled}")

    return results


def score(results: list) -> dict:
    n = len(results)
    diagnosis_correct = sum(1 for r in results if r.get("diagnosis_correct"))
    recoverable = [r for r in results if r["category"] in ("YAML_ERROR", "SEMGREP_DSL_ERROR")]
    recovered = sum(1 for r in recoverable if r.get("proposed_fix_compiled"))

    per_category = {}
    for cat in CATEGORIES:
        cat_results = [r for r in results if r["category"] == cat]
        per_category[cat] = {
            "n": len(cat_results),
            "diagnosis_accuracy": sum(1 for r in cat_results if r.get("diagnosis_correct")) / len(cat_results)
            if cat_results else None,
        }

    return {
        "n_items": n,
        "overall_diagnosis_accuracy": diagnosis_correct / n if n else None,
        "compilation_recovery_rate": recovered / len(recoverable) if recoverable else None,
        "n_recoverable_items": len(recoverable),
        "per_category": per_category,
    }


def main():
    parser = argparse.ArgumentParser(description="Syntax Review role-capability screening runner.")
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

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for model_tag in models:
        results = run_model(model_tag, items)
        safe_name = model_tag.replace("/", "_").replace(":", "_")
        out_path = RESULTS_DIR / f"{safe_name}.json"
        scores = score(results)
        out_path.write_text(json.dumps({"model_tag": model_tag, "scores": scores, "results": results}, indent=2))
        logging.info(f"[{model_tag}] overall_diagnosis_accuracy={scores['overall_diagnosis_accuracy']:.3f} "
                     f"compilation_recovery_rate={scores['compilation_recovery_rate']} -> {out_path}")


if __name__ == "__main__":
    main()
