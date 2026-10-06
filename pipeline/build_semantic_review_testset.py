"""
Builds the test set for the Semantic Review role (design Sections 17.2/19), mined from the existing
pilot screening run -- no new curation (Section 19: "pilot or development data").

Semantic Review Agent responsibilities (Section 17.2): compare the rule with patch evidence and
execution results, diagnose misses, patched-code findings, over-generalization, and
under-generalization, produce structured repair instructions. Expected output: failure
classification. Selection measurement (Section 19): correct failure diagnosis.

**Hidden-evaluation protection (Section 17.3) drives this test set's design directly**: transformed
vulnerable variants, transformed safe variants, and benign look-alikes are NEVER visible to agents --
only the original patch/vulnerable/patched code and "Semgrep compiler and visible execution results."
This means the real Semantic Review Agent can directly OBSERVE a miss (fails on original_vulnerable)
or a patched-code finding (fires on original_patched), but can only ever REASON ABOUT -- never directly
observe -- over-generalization or under-generalization, since the samples that would reveal those
(benign_lookalike/variant_safe, variant_vulnerable_1/2) are hidden from it by design. The test items
below reflect this split, and the PROMPT built by run_semantic_review.py shows the model ONLY the
rule, the original patch evidence, and the original pair's visible execution outcome -- never the
hidden samples used to construct the ground-truth label. The harness is allowed to use the hidden
data for SCORING (the same role the real Hidden Evaluator plays at the end of the C1-C4 workflow),
just never for the prompt itself.

Five ground-truth categories, each required to be the ONE issue present (clean, unambiguous labels):

  MISS                 : original_vulnerable == FN (rule fails to detect the vulnerable code at all).
                         Source: pilot "raw" condition (single-shot, can fail the original pair).
  PATCHED_CODE_FINDING : original_patched == FP (rule incorrectly fires on already-fixed code).
                         Source: pilot "raw" condition.
  OVER_GENERALIZATION  : original pair correct (TP/TN), but variant_safe or benign_lookalike == FP.
                         Source: pilot "autogrep" condition's ACCEPTED rules (by definition pass the
                         original pair -- Autogrep's own retry loop only accepts a rule that does).
  UNDER_GENERALIZATION : original pair correct, but variant_vulnerable_1 or _2 == FN.
                         Source: pilot "autogrep" condition's accepted rules.
  NONE                 : every one of the 6 bundle samples is correctly classified -- a genuinely
                         good rule, included as a negative/control case to test whether the reviewer
                         correctly recognizes "nothing wrong here" rather than always finding a flaw.
                         Source: pilot "autogrep" condition's accepted rules.

For the two autogrep-sourced categories, the accepted rule's full text is reconstructed from the raw
captures (same technique run_generation.py's reconstruct_attempt_trail() uses): attempt_trail says
which attempt_index actually succeeded, and that attempt's raw content lives in raw/<case_id>.json
(attempt 1) or raw_retries/<case_id>_attempt{N}.json (later attempts).
"""
import json
import os
import random
import sys
from collections import defaultdict
from pathlib import Path

os.environ.setdefault("GPTLAB_API_KEY", "not-used-for-mining")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from case_loader import load_case  # noqa: E402
from gptlab_config import build_config  # noqa: E402

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient  # noqa: E402

RESULTS_ROOT = Path(__file__).resolve().parent.parent / "results"
OUT_PATH = Path(__file__).resolve().parent.parent / "benchmark" / "role_screening" / "semantic_review_testset.json"
SAMPLES_PER_CATEGORY = 15
SEED = 20261002
STALE_IN_MAIN_RUN = {"deepseek-coder:6.7b", "magicoder:7b"}


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


def _find_raw_capture(model_run_dir: Path, case_id: str, attempt_index: int):
    subdir = "raw" if attempt_index == 1 else "raw_retries"
    name = f"{case_id}.json" if attempt_index == 1 else f"{case_id}_attempt{attempt_index}.json"
    for f in (model_run_dir / subdir).glob("*/" + name):
        return json.loads(f.read_text())
    return None


def _visible_outcome(samples_by_type: dict) -> dict:
    """What the real agent is allowed to see (Section 17.3): the original pair's outcome only."""
    vuln = samples_by_type.get("original_vulnerable")
    patched = samples_by_type.get("original_patched")
    return {
        "original_vulnerable_detected": vuln["detected"] if vuln else None,
        "original_vulnerable_outcome": vuln["outcome"] if vuln else None,
        "original_patched_detected": patched["detected"] if patched else None,
        "original_patched_outcome": patched["outcome"] if patched else None,
    }


def main():
    config = build_config("qwen2.5-coder:7b-instruct")
    llm_client = LLMClient(config)

    by_category = defaultdict(list)

    for model, d in _model_run_dirs().items():
        gen = [json.loads(l) for l in (d / "generation_log.jsonl").read_text().splitlines()]
        smp = [json.loads(l) for l in (d / "sample_execution_log.jsonl").read_text().splitlines()]

        # --- MISS / PATCHED_CODE_FINDING: pilot "raw" condition ---
        raw_by_case = defaultdict(dict)
        for s in smp:
            if s["condition"] == "raw":
                raw_by_case[s["case_id"]][s["sample_type"]] = s
        for record in gen:
            if record["condition"] != "raw" or record["attempt_index"] != 1 or not record["yaml_valid"]:
                continue
            case_id = record["case_id"]
            samples = raw_by_case.get(case_id, {})
            if not samples:
                continue
            vuln = samples.get("original_vulnerable")
            patched = samples.get("original_patched")
            if vuln is None or patched is None:
                continue

            category = None
            if vuln["outcome"] == "FN" and patched["outcome"] != "FP":
                category = "MISS"
            elif patched["outcome"] == "FP" and vuln["outcome"] != "FN":
                category = "PATCHED_CODE_FINDING"
            if category is None:
                continue

            raw_capture = _find_raw_capture(d, case_id, 1)
            if raw_capture is None:
                continue
            patch_info = load_case(case_id, config)
            rule = llm_client.parse_and_sanitize_response(raw_capture["raw_content"], patch_info)
            if rule is None:
                continue
            import yaml as _yaml
            rule_text = _yaml.dump({"rules": [rule]}, sort_keys=False, default_flow_style=False)

            by_category[category].append({
                "case_id": case_id, "source_model": model, "category": category,
                "rule_text": rule_text, "visible_outcome": _visible_outcome(samples),
            })

        # --- OVER/UNDER_GENERALIZATION / NONE: pilot "autogrep" condition's accepted rules ---
        autogrep_by_case = defaultdict(dict)
        for s in smp:
            if s["condition"] == "autogrep":
                autogrep_by_case[s["case_id"]][s["sample_type"]] = s
        for record in gen:
            if record["condition"] != "autogrep" or not record["semgrep_valid"]:
                continue
            case_id = record["case_id"]
            samples = autogrep_by_case.get(case_id, {})
            if len(samples) < 6:
                continue  # need the full bundle to classify cleanly

            over = any(samples.get(t, {}).get("outcome") == "FP" for t in ("variant_safe", "benign_lookalike"))
            under = any(samples.get(t, {}).get("outcome") == "FN" for t in ("variant_vulnerable_1", "variant_vulnerable_2"))
            if over and under:
                continue  # not clean -- both issues present, ambiguous for a single ground-truth label
            category = "OVER_GENERALIZATION" if over else ("UNDER_GENERALIZATION" if under else "NONE")

            # Find the attempt_index that actually succeeded, per its own attempt_trail.
            succeeding = next((a for a in (record.get("attempt_trail") or []) if a.get("semgrep_valid")), None)
            attempt_index = succeeding["attempt_index"] if succeeding else 1
            raw_capture = _find_raw_capture(d, case_id, attempt_index)
            if raw_capture is None:
                continue
            patch_info = load_case(case_id, config)
            rule = llm_client.parse_and_sanitize_response(raw_capture["raw_content"], patch_info)
            if rule is None:
                continue
            import yaml as _yaml
            rule_text = _yaml.dump({"rules": [rule]}, sort_keys=False, default_flow_style=False)

            by_category[category].append({
                "case_id": case_id, "source_model": model, "category": category,
                "rule_text": rule_text, "visible_outcome": _visible_outcome(samples),
            })

    random.seed(SEED)
    sampled = []
    for category, items in by_category.items():
        random.shuffle(items)
        sampled.extend(items[:SAMPLES_PER_CATEGORY])
    random.shuffle(sampled)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({
        "purpose": "Semantic Review role-capability screening test set (design Sections 17.2/19/17.3)",
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
