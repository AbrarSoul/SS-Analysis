"""
Runs a candidate model against the Semantic Review role-capability test set (design Sections
17.2/19/17.3).

The prompt shows ONLY what Section 17.3 permits a real agent to see: the rule, the original patch
evidence (vulnerable/patched function), and the original pair's visible execution outcome. It never
shows the hidden variant/lookalike samples used to construct the ground-truth label for
OVER_GENERALIZATION/UNDER_GENERALIZATION/NONE items -- the model must reason about pattern quality
from the patch evidence alone for those three, since the visible signal is identical across all three
(confirmed empirically in build_semantic_review_testset.py: all three categories show a fully correct
original pair). MISS and PATCHED_CODE_FINDING are directly readable from the visible execution outcome
itself -- correctly reporting them is a real but low bar (does the model accurately read what it was
shown), while the other three test actual judgment.

Measurement (Section 19's "correct failure diagnosis"): predicted category == ground-truth category,
overall and per category -- the per-category breakdown matters more than the overall number here,
since MISS/PATCHED_CODE_FINDING and the three judgment-call categories are not comparably difficult.

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_semantic_review.py --models deepseek-r1:14b,GPT-Lab/QwQ-32B-GGUF:Q6_K,DeepHat/DeepHat-V1-7B
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

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
TESTSET_PATH = BENCH_DIR / "role_screening" / "semantic_review_testset.json"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results" / "role_screening_semantic_review"
CATEGORIES = ("MISS", "PATCHED_CODE_FINDING", "OVER_GENERALIZATION", "UNDER_GENERALIZATION", "NONE")


def build_prompt(item: dict, patch_info) -> str:
    vo = item["visible_outcome"]
    return f"""You are reviewing a Semgrep rule's semantic correctness -- not syntax, which is handled
elsewhere. You can see only the original vulnerable code, the original patched code, the rule, and
whether the rule fired correctly on each. You CANNOT see any other test code; classify using only the
following and your understanding of the vulnerability.

VULNERABLE FUNCTION (before fix):
{patch_info.vulnerable_function or "(not available)"}

PATCHED FUNCTION (after fix):
{patch_info.patched_function or "(not available)"}

RULE:
{item['rule_text']}

VISIBLE EXECUTION RESULT:
- Against the original vulnerable code: {"DETECTED" if vo["original_vulnerable_detected"] else "NOT detected"}
- Against the original patched code: {"DETECTED (incorrectly)" if vo["original_patched_detected"] else "NOT detected (correct)"}

Classify this rule into EXACTLY ONE of:
- MISS: it fails to detect the vulnerable code.
- PATCHED_CODE_FINDING: it incorrectly fires on the patched code.
- OVER_GENERALIZATION: it correctly handles the pair shown, but its pattern looks broad enough that it
  would likely also match unrelated safe code that merely resembles the vulnerable shape.
- UNDER_GENERALIZATION: it correctly handles the pair shown, but its pattern looks narrowly tied to
  this exact code and would likely miss other forms of the same underlying vulnerability.
- NONE: it correctly handles the pair shown and its pattern looks well-targeted -- neither too broad
  nor too narrow.

Respond in EXACTLY this format:
DIAGNOSIS: <one of: MISS, PATCHED_CODE_FINDING, OVER_GENERALIZATION, UNDER_GENERALIZATION, NONE>
EXPLANATION: <one or two sentences>"""


def parse_response(content: str):
    # Found live building run_c3.py: a model can wrap field labels in markdown bold
    # ("**DIAGNOSIS:**") despite being asked for plain "DIAGNOSIS: ...", silently producing an
    # unparseable response. Confirmed this affected 2/67 of deepseek-r1:14b's already-reported
    # results here (one of which was actually correct once parsed properly) -- corrected via
    # Implementation_Log, not just fixed silently going forward.
    content = content.replace("**", "")
    match = re.search(r"DIAGNOSIS:\s*(\w+)", content)
    diagnosis = match.group(1).strip().upper() if match else None
    return diagnosis if diagnosis in CATEGORIES else None


def run_model(model_tag: str, items: list, partial_jsonl_path: Path):
    config = build_config(model_tag, temperature=0.0, prompt_variant="autogrep_default")
    # Reasoning models (deepseek-r1, QwQ) emit <think> blocks and need more room -- confirmed live
    # during Phase 3 candidate verification (Implementation_Log 12.39).
    is_reasoning_model = any(k in model_tag.lower() for k in ("deepseek-r1", "qwq"))
    max_tokens = 4096 if is_reasoning_model else 1024
    if is_reasoning_model:
        # The default 120s (autogrep/config.py) is NOT enough for QwQ-32B specifically -- confirmed
        # live: a trivial one-word test prompt alone took 166s to respond. Every one of 56/67 items
        # in a real run failed with "Request timed out" at 120s, repeatedly, across many retries --
        # this was never host instability resolving itself, it was a timeout set too short for this
        # model's real response time. A first fix to 300s ALSO proved insufficient for the real
        # (longer, full-context) prompts -- raised again to 600s. deepseek-r1:14b (smaller, faster)
        # never needed this, but raising it for both reasoning candidates is harmless -- it only
        # affects how long a genuinely slow
        # response is allowed to take, not anything about a fast one.
        config.request_timeout_seconds = 600.0
    llm_client = LLMClient(config)

    # Keyed by (case_id, category, source_model) -- NOT (case_id, category) alone, which collides:
    # the SAME case_id can independently produce the SAME ground-truth category from MULTIPLE
    # different source models' rules (confirmed live -- 25 of this test set's 67 items share a
    # (case_id, category) pair with at least one other item, but every item IS unique once
    # source_model is included). An earlier version of this key caused a real, silent bug: a QwQ-32B
    # resume treated one of two same-keyed-but-distinct items as already handled and permanently
    # skipped it (explains a 66-not-67 result on a separate deepseek-r1 run, traced down after the
    # fact). A later retry's record overwrites an earlier one for the SAME full key, so a case isn't
    # "done" if its only recorded attempt errored (e.g. a request timeout) -- found necessary after
    # a QwQ-32B run had 56/67 items fail with "Request timed out" under host load.
    def _full_key(r):
        return (r["case_id"], r["category"], r["source_model"])

    by_key = {}
    if partial_jsonl_path.exists():
        for line in partial_jsonl_path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                by_key[_full_key(r)] = r
    # Only the good ones go into the running results list -- an errored entry is dropped here and
    # will be freshly appended by the retry loop below, rather than kept as a stale duplicate.
    results = [r for r in by_key.values() if not r.get("error")]
    already_done = {k for k, r in by_key.items() if not r.get("error")}
    if by_key:
        logging.info(f"[{model_tag}] resuming: {len(already_done)}/{len(items)} item(s) already done "
                     f"({len(by_key) - len(already_done)} prior error(s) will be retried)")

    for item in items:
        key = _full_key(item)
        if key in already_done:
            continue
        patch_info = load_case(item["case_id"], config)
        prompt = build_prompt(item, patch_info)
        try:
            response = llm_client.client.chat.completions.create(
                model=model_tag,
                messages=[
                    {"role": "system", "content": "You are a precise Semgrep rule semantic reviewer."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=max_tokens,
            )
            content = response.choices[0].message.content
        except Exception as e:
            logging.error(f"[{model_tag}/{item['case_id']}] generation error: {e}")
            record = {**item, "predicted_category": None, "diagnosis_correct": False,
                      "raw_response": None, "error": str(e)}
            results.append(record)
            with open(partial_jsonl_path, "a") as f:
                f.write(json.dumps(record) + "\n")
            continue

        # Reasoning models wrap output in <think>...</think> before the real answer -- strip it the
        # same way llm_client.extract_response() already does for rule generation.
        visible_content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)
        predicted = parse_response(visible_content)

        record = {
            **item,
            "predicted_category": predicted,
            "diagnosis_correct": predicted == item["category"],
            "raw_response": content,
        }
        results.append(record)
        with open(partial_jsonl_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        logging.info(f"[{model_tag}/{item['case_id']}] truth={item['category']} predicted={predicted}")

    return results


def score(results: list) -> dict:
    n = len(results)
    correct = sum(1 for r in results if r.get("diagnosis_correct"))
    per_category = {}
    for cat in CATEGORIES:
        cat_results = [r for r in results if r["category"] == cat]
        per_category[cat] = {
            "n": len(cat_results),
            "diagnosis_accuracy": sum(1 for r in cat_results if r.get("diagnosis_correct")) / len(cat_results)
            if cat_results else None,
        }
    return {"n_items": n, "overall_diagnosis_accuracy": correct / n if n else None, "per_category": per_category}


def main():
    parser = argparse.ArgumentParser(description="Semantic Review role-capability screening runner.")
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
        safe_name = model_tag.replace("/", "_").replace(":", "_")
        partial_jsonl_path = RESULTS_DIR / f"{safe_name}.partial.jsonl"
        results = run_model(model_tag, items, partial_jsonl_path)
        out_path = RESULTS_DIR / f"{safe_name}.json"
        scores = score(results)
        out_path.write_text(json.dumps({"model_tag": model_tag, "scores": scores, "results": results}, indent=2))
        logging.info(f"[{model_tag}] overall_diagnosis_accuracy={scores['overall_diagnosis_accuracy']:.3f} -> {out_path}")


if __name__ == "__main__":
    main()
