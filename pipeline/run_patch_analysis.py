"""
Runs a candidate model against the Patch Analysis role-capability test set (design Sections
17.2/19), scored by a fixed judge model.

Patch Analysis Agent responsibilities (Section 17.2): explain the vulnerability mechanism, identify
sources, sinks, sanitizers, and missing checks, distinguish essential APIs from project-specific
names, recommend pattern or taint mode, return a structured vulnerability specification. Selection
measurement (Section 19): mechanism, source, sink, and fix accuracy.

**This role's ground truth is deliberately evidence-limited** (benchmark/role_screening/
patch_analysis_testset.json, converged after 5 review rounds -- see Implementation_Log 12.45-12.48):
several fields are honestly marked NOT SHOWN or conditional, because the real evidence available to
a patch-analysis agent (the original patch and the vulnerable/patched code -- Section 17.3) doesn't
establish everything a complete exploit narrative would need. The candidate prompt below mirrors
that same evidence scope (diff + vulnerable/patched source, nothing more) and explicitly tells the
model that saying "not shown" is a valid, correct answer -- not a gap to paper over. Scoring must
honor this: per the reviewing party's explicit closing instruction, a model that correctly abstains
where the ground truth itself is evidence-limited should score as CORRECT, not be penalized for
failing to invent specifics.

Because mechanism/source/sink/fix are free-text (unlike the categorical labels the other three
roles used), automated string matching can't score this fairly. Scoring uses a FIXED JUDGE MODEL
(qwen2.5-coder:32b, gptlab_config.JUDGE_MODEL) -- never one of this role's own candidates -- per a
per-field rubric: CORRECT / PARTIALLY_CORRECT / INCORRECT / APPROPRIATE_ABSTENTION (candidate
correctly said "not shown", matching the ground truth's own evidence status) / OVERREACHED
(candidate asserted unsupported specifics where the ground truth says not-shown/conditional).
APPROPRIATE_ABSTENTION counts as a correct outcome; OVERREACHED counts as incorrect, for RQ8-style
scoring purposes.

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_patch_analysis.py --models deepseek-r1:14b,qwen3-coder-next:latest
"""
import argparse
import json
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS, JUDGE_MODEL  # noqa: E402
from case_loader import load_case  # noqa: E402

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
TESTSET_PATH = BENCH_DIR / "role_screening" / "patch_analysis_testset.json"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results" / "role_screening_patch_analysis"
FIELDS = ("mechanism", "source", "sink", "fix")
VERDICTS = ("CORRECT", "PARTIALLY_CORRECT", "INCORRECT", "APPROPRIATE_ABSTENTION", "OVERREACHED")


def build_candidate_prompt(item: dict, patch_info) -> str:
    return f"""You are analyzing a security vulnerability from its patch. You are given exactly the
same evidence a real patch-analysis reviewer would have: the original patch and the vulnerable and
patched code. You do NOT have access to the original advisory, commit message, or any other external
context -- only what is shown below.

VULNERABLE CODE (before fix):
{patch_info.vulnerable_function or "(not available)"}

PATCHED CODE (after fix):
{patch_info.patched_function or "(not available)"}

PATCH DIFF:
{item['diff_text']}

Produce a structured vulnerability specification with exactly these four fields. If the evidence
above does not establish something, say so explicitly (e.g. "not shown in the provided evidence") --
that is a correct and expected answer when the evidence genuinely doesn't cover it. Do not invent
specifics you cannot support from what's shown.

Respond in EXACTLY this format:
MECHANISM: <explain the vulnerability mechanism>
SOURCE: <identify the source(s) -- where the dangerous data/condition originates>
SINK: <identify the sink(s) -- where the dangerous operation occurs>
FIX: <what the patch does to remediate it>"""


def parse_candidate_response(content: str) -> dict:
    # Found live in run_c3.py (Implementation_Log) with qwen2.5-coder:7b-instruct: a model can wrap
    # field labels in markdown bold with a leading bullet ("- **MECHANISM**: ...") despite being
    # asked for plain "MECHANISM: ...", silently producing an all-null parse. Neither
    # deepseek-r1:14b nor qwen3-coder-next:latest exhibited this in the completed screening runs
    # (confirmed: 0/15 fully-null results for both), so no retroactive correction was needed there,
    # but hardening this parser is still worthwhile for future reruns with other models.
    cleaned = content.replace("**", "")
    out = {}
    for field in FIELDS:
        pattern = rf"(?:^|\n)[\s\-*]*{field.upper()}:\s*(.*?)(?=\n[\s\-*]*(?:MECHANISM|SOURCE|SINK|FIX):|\Z)"
        match = re.search(pattern, cleaned, flags=re.DOTALL | re.IGNORECASE)
        out[field] = match.group(1).strip() if match else None
    return out


def build_judge_prompt(item: dict, candidate_fields: dict) -> str:
    gt_block = "\n".join(f"{f.upper()} (ground truth): {item[f]}" for f in FIELDS)
    cand_block = "\n".join(f"{f.upper()} (candidate): {candidate_fields.get(f) or '(no answer given)'}" for f in FIELDS)
    return f"""You are judging a candidate model's patch-analysis answer against a hand-verified
ground truth. The ground truth itself is sometimes evidence-limited -- its own verification note
below explains exactly which parts are fully established, which are supported only by context
beyond the bare diff, and which are honestly marked "not shown" or conditional. A candidate that
correctly recognizes evidence is missing (saying so explicitly, not inventing a specific) should be
judged APPROPRIATE_ABSTENTION, which counts as a GOOD outcome -- not a failure to find more detail.
A candidate that confidently asserts unsupported specifics where the ground truth itself says
"not shown" or "conditional" should be judged OVERREACHED, which counts as a BAD outcome, even if
the invented specifics sound plausible.

GROUND TRUTH VERIFICATION NOTE (explains the evidence status of each field below):
{item['verification_note']}

{gt_block}

{cand_block}

For EACH of the four fields (mechanism, source, sink, fix), give a verdict and a one-sentence reason.
Respond in EXACTLY this format, one block per field:
MECHANISM_VERDICT: <one of: CORRECT, PARTIALLY_CORRECT, INCORRECT, APPROPRIATE_ABSTENTION, OVERREACHED>
MECHANISM_REASON: <one sentence>
SOURCE_VERDICT: <same five options>
SOURCE_REASON: <one sentence>
SINK_VERDICT: <same five options>
SINK_REASON: <one sentence>
FIX_VERDICT: <same five options>
FIX_REASON: <one sentence>"""


def parse_judge_response(content: str) -> dict:
    out = {}
    for field in FIELDS:
        vmatch = re.search(rf"{field.upper()}_VERDICT:\s*(\w+)", content, flags=re.IGNORECASE)
        rmatch = re.search(rf"{field.upper()}_REASON:\s*(.*)", content, flags=re.IGNORECASE)
        verdict = vmatch.group(1).strip().upper() if vmatch else None
        out[field] = {
            "verdict": verdict if verdict in VERDICTS else None,
            "reason": rmatch.group(1).strip().splitlines()[0] if rmatch else None,
        }
    return out


def call_model(llm_client: LLMClient, model_tag: str, prompt: str, system: str, max_tokens: int):
    response = llm_client.client.chat.completions.create(
        model=model_tag,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content


def run_model(model_tag: str, items: list, partial_jsonl_path: Path):
    config = build_config(model_tag, temperature=0.0, prompt_variant="autogrep_default")
    llm_client = LLMClient(config)
    judge_config = build_config(JUDGE_MODEL, temperature=0.0, prompt_variant="autogrep_default")
    judge_client = LLMClient(judge_config)

    is_reasoning_model = any(k in model_tag.lower() for k in ("deepseek-r1", "qwq"))
    max_tokens = 4096 if is_reasoning_model else 1536
    if is_reasoning_model:
        config.request_timeout_seconds = 600.0  # lesson from semantic review, Implementation_Log 12.44

    by_case = {}
    if partial_jsonl_path.exists():
        for line in partial_jsonl_path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                by_case[r["case_id"]] = r
    results = [r for r in by_case.values() if not r.get("error")]
    already_done = {cid for cid, r in by_case.items() if not r.get("error")}
    if by_case:
        logging.info(f"[{model_tag}] resuming: {len(already_done)}/{len(items)} item(s) already done "
                     f"({len(by_case) - len(already_done)} prior error(s) will be retried)")

    for item in items:
        cid = item["case_id"]
        if cid in already_done:
            continue
        config_patch_info = load_case(cid, config)
        prompt = build_candidate_prompt(item, config_patch_info)
        try:
            content = call_model(llm_client, model_tag, prompt,
                                  "You are a precise security patch analyst.", max_tokens)
        except Exception as e:
            logging.error(f"[{model_tag}/{cid}] generation error: {e}")
            record = {"case_id": cid, "candidate_fields": None, "judge_result": None,
                      "raw_response": None, "error": str(e)}
            results.append(record)
            with open(partial_jsonl_path, "a") as f:
                f.write(json.dumps(record) + "\n")
            continue

        visible_content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)
        candidate_fields = parse_candidate_response(visible_content)

        judge_prompt = build_judge_prompt(item, candidate_fields)
        try:
            judge_content = call_model(judge_client, JUDGE_MODEL, judge_prompt,
                                        "You are a precise, fair grader.", 1024)
            judge_result = parse_judge_response(judge_content)
        except Exception as e:
            logging.error(f"[{model_tag}/{cid}] judge error: {e}")
            judge_result = None

        record = {
            "case_id": cid,
            "candidate_fields": candidate_fields,
            "judge_result": judge_result,
            "raw_response": content,
        }
        results.append(record)
        with open(partial_jsonl_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        verdicts = {f: (judge_result or {}).get(f, {}).get("verdict") for f in FIELDS}
        logging.info(f"[{model_tag}/{cid}] {verdicts}")

    return results


def score(results: list) -> dict:
    n = len(results)
    scored = [r for r in results if r.get("judge_result")]
    per_field = {}
    for field in FIELDS:
        verdicts = [r["judge_result"][field]["verdict"] for r in scored if r["judge_result"].get(field, {}).get("verdict")]
        good = sum(1 for v in verdicts if v in ("CORRECT", "APPROPRIATE_ABSTENTION"))
        per_field[field] = {
            "n_judged": len(verdicts),
            "good_rate": good / len(verdicts) if verdicts else None,
            "verdict_counts": {v: verdicts.count(v) for v in VERDICTS if verdicts.count(v) > 0},
        }
    overall_good = sum(per_field[f]["verdict_counts"].get("CORRECT", 0)
                        + per_field[f]["verdict_counts"].get("APPROPRIATE_ABSTENTION", 0) for f in FIELDS)
    overall_judged = sum(per_field[f]["n_judged"] for f in FIELDS)
    return {
        "n_items": n,
        "n_scored": len(scored),
        "overall_good_rate": overall_good / overall_judged if overall_judged else None,
        "per_field": per_field,
    }


def main():
    parser = argparse.ArgumentParser(description="Patch Analysis role-capability screening runner.")
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
    for item in items:
        item["diff_text"] = (BENCH_DIR / "cases" / item["case_id"] / "patch.diff").read_text()
    if args.limit is not None:
        items = items[:args.limit]
    logging.info(f"Loaded {len(items)} test items")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for model_tag in models:
        safe_name = model_tag.replace("/", "_").replace(":", "_")
        partial_jsonl_path = RESULTS_DIR / f"{safe_name}.partial.jsonl"
        results = run_model(model_tag, items, partial_jsonl_path)
        out_path = RESULTS_DIR / f"{safe_name}.json"
        scores = score(results)
        out_path.write_text(json.dumps({"model_tag": model_tag, "scores": scores, "results": results}, indent=2))
        logging.info(f"[{model_tag}] overall_good_rate={scores['overall_good_rate']} -> {out_path}")


if __name__ == "__main__":
    main()
