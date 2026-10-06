"""
C3 (homogeneous multi-agent) -- design Section 18.3: "The same underlying model performs all LLM
roles with separate role prompts and contexts." Scoped in Research_Log/C3_Scope.md; see that doc for
two resolved design decisions this implementation depends on:

1. Model choice (by parameter scale, not raw MCC rank): C3-S = qwen2.5-coder:32b,
   C3-E = qwen2.5-coder:7b-instruct. Both variants use ONE model for every role below -- NOT the
   per-role assignments Phase 3's role-capability screening produced (those are for C4-A, a
   separate, later configuration: "best pilot model assigned to each role").
2. Budget: the literal 5-agent workflow does not fit Section 20's max_llm_calls:6 if a full
   Semantic Review LLM call re-runs after every repair round (worked out in C3_Scope.md: a single
   pass alone already costs 4 calls, leaving only 2). Resolved to exactly ONE repair round, whose
   post-repair accept/reject check uses the deterministic Semgrep Executor's own result directly
   instead of a second Semantic Review call -- using exactly 6 calls in the worst case, with zero
   slack, rather than silently exceeding the stated budget.

Exact call sequence (Section 17.1's workflow, with the above resolution):
  (1) Patch Analysis Agent -> structured vulnerability specification
  (2) Rule Generation Agent -> converts the specification into one Semgrep YAML rule
  (3) Syntax Review Agent [round 0] -> diagnosis + optional corrected rule
      [Semgrep Executor: real Semgrep execution against the original pair -- deterministic, not an
       LLM call]
  (4) Semantic Review Agent [round 0] -> ACCEPTED/NOT_ACCEPTED judgment + structured repair
      instructions if not accepted
      -> if ACCEPTED: done, proceed to the Hidden Evaluator
      -> if NOT ACCEPTED:
  (5) Rule Repair Agent -> revises the rule using the real Semgrep error AND the Semantic Review
      Agent's structured instructions
  (6) Syntax Review Agent [round 1] -> diagnosis + optional corrected rule for the repaired rule
      [Semgrep Executor: real Semgrep execution against the original pair again -- THIS is the
       final accept/reject decision for round 1; no second Semantic Review call]

If accepted (at round 0 or round 1): the accepted rule is evaluated against the FULL six-sample
bundle via evaluate_case_bundle() -- the Hidden Evaluator, deterministic, reused unmodified from
every other phase of this study. If never accepted: episode ends with no accepted rule, same
failure-handling convention as C2 and Autogrep's own retry loop.

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_c3.py --variant C3-E --cases CASE-0041,CASE-0042
    python pipeline/run_c3.py --variant C3-S --cases supported --results-dir results/runs_c3
"""
import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS  # noqa: E402
from case_loader import load_case  # noqa: E402
from sample_evaluation import evaluate_case_bundle  # noqa: E402

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient, _make_suggested_id  # noqa: E402
from rule_validator import RuleValidator, _curated_file_paths  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
RESULTS_ROOT = Path(__file__).resolve().parent.parent / "results"

# C3_Scope.md decision 1 -- by parameter scale, not raw MCC rank.
VARIANT_MODELS = {
    "C3-S": "qwen2.5-coder:32b",
    "C3-E": "qwen2.5-coder:7b-instruct",
}

MAX_LLM_CALLS = 6  # Section 20, same constant C2 uses -- see C3_Scope.md decision 2 for how it's spent.


# ---------------------------------------------------------------------------
# Agent 1: Patch Analysis -- reuses the prompt shape from run_patch_analysis.py,
# adapted to take patch_info/diff_text directly rather than a screening test-item dict.
# ---------------------------------------------------------------------------

def build_patch_analysis_prompt(patch_info, diff_text: str) -> str:
    return f"""You are analyzing a security vulnerability from its patch. You are given the
original patch and the vulnerable and patched code.

VULNERABLE CODE (before fix):
{patch_info.vulnerable_function or "(not available)"}

PATCHED CODE (after fix):
{patch_info.patched_function or "(not available)"}

PATCH DIFF:
{diff_text}

Produce a structured vulnerability specification with exactly these four fields. If the evidence
does not establish something, say so explicitly rather than invent detail.

Respond in EXACTLY this format:
MECHANISM: <explain the vulnerability mechanism>
SOURCE: <identify the source(s)>
SINK: <identify the sink(s)>
FIX: <what the patch does to remediate it>"""


def parse_patch_analysis_response(content: str) -> dict:
    # qwen2.5-coder:7b-instruct wraps field labels in markdown bold with a leading bullet
    # ("- **MECHANISM**: ...") despite being asked for plain "MECHANISM: ..." -- found live on
    # CASE-0042, where this silently produced an all-null spec and cascaded into a useless
    # Rule Generation prompt. Strip ** globally and tolerate a leading bullet/dash before the
    # field name, rather than require the exact literal format requested.
    cleaned = content.replace("**", "")
    out = {}
    for field in ("mechanism", "source", "sink", "fix"):
        pattern = rf"(?:^|\n)[\s\-*]*{field.upper()}:\s*(.*?)(?=\n[\s\-*]*(?:MECHANISM|SOURCE|SINK|FIX):|\Z)"
        match = re.search(pattern, cleaned, flags=re.DOTALL | re.IGNORECASE)
        out[field] = match.group(1).strip() if match else None
    return out


# ---------------------------------------------------------------------------
# Agent 2: Rule Generation -- NEW prompt, consumes the structured spec (not the raw diff),
# per Section 17.2: "Convert the specification into one Semgrep YAML rule."
# ---------------------------------------------------------------------------

def build_rule_generation_prompt(spec: dict, language: str, suggested_id: str) -> str:
    return f"""Convert the following vulnerability specification into exactly one Semgrep YAML
rule that detects the vulnerable pattern and does not match the patched pattern. Generalize the
security mechanism; avoid depending on repository-specific names where the specification marks them
as non-essential.

VULNERABILITY SPECIFICATION:
Mechanism: {spec.get('mechanism') or '(not established)'}
Source: {spec.get('source') or '(not established)'}
Sink: {spec.get('sink') or '(not established)'}
Fix: {spec.get('fix') or '(not established)'}

Language: {language}

Return exactly one Semgrep YAML rule. Do not include Markdown fences or prose. Include id, pattern,
languages, message, severity, and metadata fields. Use "{suggested_id}" as the id.
severity must be one of: ERROR, WARNING, INFO."""


# ---------------------------------------------------------------------------
# Agent 3: Syntax Review -- reused prompt shape from run_syntax_review.py.
# ---------------------------------------------------------------------------

def build_syntax_review_prompt(rule_text: str, error_message: str) -> str:
    return f"""You are reviewing a Semgrep rule for syntax problems only -- not semantic
correctness, which is handled elsewhere. Diagnose whether the problem is a YAML-level error, a
Semgrep-pattern-DSL-level error, or not a syntax problem at all. Apply or recommend only the
SMALLEST correction needed -- never change what the rule is trying to detect.

RULE:
{rule_text}

OBSERVED ERROR / EXECUTION RESULT:
{error_message}

Respond in EXACTLY this format, nothing else:
DIAGNOSIS: <one of: YAML_ERROR, SEMGREP_DSL_ERROR, NOT_A_SYNTAX_ERROR>
EXPLANATION: <one or two sentences>
CORRECTED_RULE:
<a complete corrected Semgrep YAML rule if DIAGNOSIS is YAML_ERROR or SEMGREP_DSL_ERROR, or the exact
word NONE if DIAGNOSIS is NOT_A_SYNTAX_ERROR>"""


def parse_syntax_review_response(content: str):
    # Same markdown-bold-label hardening as parse_patch_analysis_response -- see its comment.
    content = content.replace("**", "")
    diag_match = re.search(r"DIAGNOSIS:\s*(\w+)", content)
    diagnosis = diag_match.group(1).strip().upper() if diag_match else None
    corrected_match = re.search(r"CORRECTED_RULE:\s*(.*)", content, flags=re.DOTALL)
    corrected_text = corrected_match.group(1).strip() if corrected_match else ""
    proposed_none = bool(re.match(r"^NONE\b", corrected_text, flags=re.IGNORECASE))
    return diagnosis, (None if proposed_none or not corrected_text else corrected_text)


# ---------------------------------------------------------------------------
# Agent 4: Semantic Review -- adapted from run_semantic_review.py: adds a structured
# repair-instructions field alongside the diagnosis, per Section 17.2's "produce structured
# repair instructions," and an explicit ACCEPT/NOT_ACCEPT verdict the orchestrator checks directly.
# ---------------------------------------------------------------------------

def build_semantic_review_prompt(rule_text: str, patch_info, vuln_detected: bool, patched_detected: bool) -> str:
    return f"""You are reviewing a Semgrep rule's semantic correctness. You can see the original
vulnerable code, the original patched code, the rule, and whether it fired correctly on each.

VULNERABLE FUNCTION (before fix):
{patch_info.vulnerable_function or "(not available)"}

PATCHED FUNCTION (after fix):
{patch_info.patched_function or "(not available)"}

RULE:
{rule_text}

VISIBLE EXECUTION RESULT:
- Against the original vulnerable code: {"DETECTED" if vuln_detected else "NOT detected"}
- Against the original patched code: {"DETECTED (incorrectly)" if patched_detected else "NOT detected (correct)"}

Decide whether this rule should be ACCEPTED. Accept only if it correctly detects the vulnerable
code, does not fire on the patched code, and its pattern looks well-targeted (neither clearly too
broad nor clearly too narrow, based on what's visible here). If not accepted, classify the failure
and give concrete, actionable repair instructions.

Respond in EXACTLY this format:
VERDICT: <ACCEPTED or NOT_ACCEPTED>
DIAGNOSIS: <one of: MISS, PATCHED_CODE_FINDING, OVER_GENERALIZATION, UNDER_GENERALIZATION, NONE>
REPAIR_INSTRUCTIONS: <concrete guidance for fixing the rule, or NONE if accepted>"""


def parse_semantic_review_response(content: str) -> dict:
    # Same markdown-bold-label hardening as parse_patch_analysis_response -- see its comment.
    content = content.replace("**", "")
    vmatch = re.search(r"VERDICT:\s*(\w+)", content)
    dmatch = re.search(r"DIAGNOSIS:\s*(\w+)", content)
    rmatch = re.search(r"REPAIR_INSTRUCTIONS:\s*(.*)", content, flags=re.DOTALL)
    return {
        "verdict": vmatch.group(1).strip().upper() if vmatch else None,
        "diagnosis": dmatch.group(1).strip().upper() if dmatch else None,
        "repair_instructions": rmatch.group(1).strip() if rmatch else None,
    }


# ---------------------------------------------------------------------------
# Agent 5: Rule Repair -- adapted from run_rule_repair.py: incorporates BOTH the deterministic
# Semgrep error AND the Semantic Review Agent's structured repair instructions, per Section 17.2
# ("Revise the rule using deterministic diagnostics and review output").
# ---------------------------------------------------------------------------

def build_rule_repair_prompt(rule_text: str, semgrep_error: Optional[str], repair_instructions: Optional[str]) -> str:
    return f"""You are repairing a Semgrep rule that failed review. Revise it so it correctly
detects the vulnerable code and does NOT match the patched code. Preserve every part of the rule
that is already correct -- change only what is actually broken.

RULE:
{rule_text}

DETERMINISTIC SEMGREP RESULT:
{semgrep_error or "(the rule compiled and ran; see review diagnosis below)"}

SEMANTIC REVIEW DIAGNOSIS AND REPAIR INSTRUCTIONS:
{repair_instructions or "(none given)"}

Respond with ONLY the complete revised Semgrep YAML rule. No explanation, no markdown fence
commentary, just the YAML."""


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class C3EpisodeRecord:
    run_id: str
    case_id: str
    model_tag: str
    variant: str
    condition: str  # "c3"
    accepted: bool
    rule_id: Optional[str]
    calls_used: int
    accepted_at_round: Optional[int]  # 0 or 1, or None if never accepted
    stop_reason: str  # "accepted_round0" | "accepted_round1" | "rejected_round0_no_repair_needed_but_failed" | "max_llm_calls"
    patch_analysis: Optional[dict]
    syntax_review_round0: Optional[dict]
    semantic_review_round0: Optional[dict]
    rule_repair: Optional[dict]
    syntax_review_round1: Optional[dict]
    validation_error: Optional[str]
    timestamp: float


def _call(llm_client: LLMClient, model_tag: str, prompt: str, system: str, max_tokens: int) -> str:
    response = llm_client.client.chat.completions.create(
        model=model_tag,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content


def run_c3_episode(case_id: str, model_tag: str, variant: str, config, llm_client: LLMClient,
                    validator: RuleValidator, run_id: str, frozen_manifest: dict, max_tokens: int):
    import time
    patch_info = load_case(case_id, config)
    case_dir = BENCH_DIR / "cases" / case_id
    language = patch_info.file_changes[0].language
    diff_text = (case_dir / "patch.diff").read_text()
    repo_path_marker = Path(f"<curated-case:{case_id}>")
    calls_used = 0

    # --- Call 1: Patch Analysis ---
    content = _call(llm_client, model_tag, build_patch_analysis_prompt(patch_info, diff_text),
                     "You are a precise security patch analyst.", max_tokens)
    calls_used += 1
    spec = parse_patch_analysis_response(content)

    # --- Call 2: Rule Generation ---
    suggested_id = _make_suggested_id(patch_info)
    content = _call(llm_client, model_tag, build_rule_generation_prompt(spec, language, suggested_id),
                     "You generate Semgrep rules in YAML format. Return only raw YAML.", max_tokens)
    calls_used += 1
    rule = llm_client.parse_and_sanitize_response(content, patch_info)

    syntax_round0 = semantic_round0 = rule_repair_result = syntax_round1 = None
    accepted_rule = None
    accepted_at_round = None
    stop_reason = "rejected_round1"
    last_error = None

    for round_num in (0, 1):
        if calls_used >= MAX_LLM_CALLS:
            stop_reason = "max_llm_calls"
            break

        # --- Syntax Review (call 3 at round 0, call 6 at round 1) ---
        if rule is not None:
            rule_text_for_review = _dump_rule(rule)
            is_valid, semgrep_error = validator.validate_rule(rule, patch_info, repo_path_marker)
        else:
            rule_text_for_review = content  # raw, unparsed text
            is_valid, semgrep_error = False, llm_client.last_error or "failed to parse/sanitize into a rule"

        syntax_content = _call(llm_client, model_tag,
                                build_syntax_review_prompt(rule_text_for_review, semgrep_error or "(no error -- rule compiled and ran)"),
                                "You are a precise Semgrep rule syntax reviewer.", max_tokens)
        calls_used += 1
        diagnosis, corrected_text = parse_syntax_review_response(syntax_content)
        syntax_result = {"round": round_num, "diagnosis": diagnosis, "proposed_fix": corrected_text}
        if round_num == 0:
            syntax_round0 = syntax_result
        else:
            syntax_round1 = syntax_result

        if corrected_text is not None:
            candidate_rule = llm_client.parse_and_sanitize_response(corrected_text, patch_info)
            if candidate_rule is not None:
                rule = candidate_rule
                is_valid, semgrep_error = validator.validate_rule(rule, patch_info, repo_path_marker)

        if round_num == 1:
            # Decision 2: no second Semantic Review call -- the deterministic Semgrep result IS
            # the final accept/reject check for round 1.
            if is_valid:
                accepted_rule = rule
                accepted_at_round = 1
                stop_reason = "accepted_round1"
            else:
                last_error = semgrep_error
                stop_reason = "rejected_round1"
            break

        # --- Semantic Review (call 4, round 0 only) ---
        if calls_used >= MAX_LLM_CALLS:
            stop_reason = "max_llm_calls"
            break
        vuln_detected, patched_detected = _check_original_pair(validator, rule, patch_info) if rule else (False, False)
        semantic_content = _call(llm_client, model_tag,
                                  build_semantic_review_prompt(rule_text_for_review, patch_info, vuln_detected, patched_detected),
                                  "You are a precise Semgrep rule semantic reviewer.", max_tokens)
        calls_used += 1
        semantic_round0 = parse_semantic_review_response(semantic_content)

        if semantic_round0["verdict"] == "ACCEPTED" and is_valid:
            accepted_rule = rule
            accepted_at_round = 0
            stop_reason = "accepted_round0"
            break

        # --- Rule Repair (call 5) ---
        if calls_used >= MAX_LLM_CALLS:
            stop_reason = "max_llm_calls"
            break
        repair_content = _call(llm_client, model_tag,
                                build_rule_repair_prompt(rule_text_for_review, semgrep_error, semantic_round0.get("repair_instructions")),
                                "You are a precise Semgrep rule repair specialist.", max_tokens)
        calls_used += 1
        rule = llm_client.parse_and_sanitize_response(repair_content, patch_info)
        rule_repair_result = {"proposed_rule_parsed": rule is not None}
        last_error = semgrep_error
        # loop continues to round 1 (syntax review re-check)

    wall_clock_done = time.time()

    sample_records = []
    if accepted_rule is not None:
        frozen = frozen_manifest.get(case_id, {})
        sample_records, bundle_error = evaluate_case_bundle(
            accepted_rule, case_dir, language, validator,
            run_id, case_id, model_tag, "c3",
            vulnerable_lines=frozen.get("vulnerable_lines"),
        )
        if bundle_error:
            last_error = bundle_error

    episode = C3EpisodeRecord(
        run_id=run_id, case_id=case_id, model_tag=model_tag, variant=variant, condition="c3",
        accepted=accepted_rule is not None,
        rule_id=accepted_rule["id"] if accepted_rule else None,
        calls_used=calls_used, accepted_at_round=accepted_at_round, stop_reason=stop_reason,
        patch_analysis=spec, syntax_review_round0=syntax_round0, semantic_review_round0=semantic_round0,
        rule_repair=rule_repair_result, syntax_review_round1=syntax_round1,
        validation_error=last_error if accepted_rule is None else None,
        timestamp=wall_clock_done,
    )
    return episode, sample_records


def _dump_rule(rule: dict) -> str:
    import yaml
    return yaml.dump({"rules": [rule]}, sort_keys=False, default_flow_style=False)


def _check_original_pair(validator: RuleValidator, rule: dict, patch_info):
    """Real Semgrep execution against the original pair specifically, for the Semantic Review
    Agent's own "visible execution result" input -- reuses RuleValidator's internal _run_semgrep
    the same way sample_evaluation.py does, via the curated case's standalone files."""
    import tempfile
    import yaml as _yaml
    vuln_path, patched_path = _curated_file_paths(patch_info)
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
        _yaml.dump({"rules": [rule]}, tf)
        rule_file = tf.name
    try:
        vuln_results, _ = validator._run_semgrep(rule_file, str(vuln_path))
        patched_results, _ = validator._run_semgrep(rule_file, str(patched_path))
        return bool(vuln_results), bool(patched_results)
    finally:
        Path(rule_file).unlink(missing_ok=True)


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


def run_variant_on_cases(variant: str, case_ids: list, results_root: Path):
    model_tag = VARIANT_MODELS[variant]
    config = build_config(model_tag, temperature=0.0, prompt_variant="autogrep_default")
    llm_client = LLMClient(config)
    validator = RuleValidator(config)
    max_tokens = 2048

    results_root = Path(results_root).resolve()
    run_dir = results_root / f"{variant}"
    run_dir.mkdir(parents=True, exist_ok=True)
    episode_log = run_dir / "c3_episode_log.jsonl"
    sample_log = run_dir / "sample_execution_log.jsonl"

    frozen_manifest = _load_frozen_manifest_index()
    from result_schema import make_run_id, append_jsonl
    run_id = make_run_id(model_tag)

    already_done = set()
    if episode_log.exists():
        for line in episode_log.read_text().splitlines():
            if line.strip():
                already_done.add(json.loads(line)["case_id"])
    pending = [c for c in case_ids if c not in already_done]
    if already_done:
        logging.info(f"[{variant}] resuming: {len(already_done)}/{len(case_ids)} already done")
    logging.info(f"[{variant}] processing {len(pending)} case(s) under C3, model={model_tag}")

    for case_id in pending:
        try:
            episode, sample_records = run_c3_episode(
                case_id, model_tag, variant, config, llm_client, validator, run_id, frozen_manifest, max_tokens
            )
        except Exception as e:
            logging.error(f"[{case_id}] unexpected error: {e}", exc_info=True)
            continue
        with open(episode_log, "a") as f:
            f.write(json.dumps(asdict(episode)) + "\n")
        append_jsonl(sample_records, sample_log)
        logging.info(f"[{case_id}] accepted={episode.accepted} calls={episode.calls_used} "
                     f"accepted_at_round={episode.accepted_at_round} stop_reason={episode.stop_reason}")

    logging.info(f"[{variant}] done -> {episode_log}")


def preflight_auth(hosts) -> None:
    import requests
    from gptlab_config import host_base_url, get_api_key
    key = get_api_key()
    for host in sorted(set(hosts)):
        try:
            r = requests.get(f"{host_base_url(host)}/models", headers={"Authorization": f"Bearer {key}"}, timeout=30)
        except requests.RequestException as e:
            sys.exit(f"Preflight FAILED: cannot reach {host}: {e}")
        if r.status_code != 200:
            sys.exit(f"Preflight FAILED on {host}: HTTP {r.status_code}. Nothing was run.")
        logging.info(f"Preflight OK on {host}")


def main():
    parser = argparse.ArgumentParser(description="C3 (homogeneous multi-agent) runner -- see module docstring.")
    parser.add_argument("--variant", required=True, choices=list(VARIANT_MODELS.keys()))
    parser.add_argument("--cases", required=True,
                         help="'supported' for all supported-representability final cases, or a comma-separated list of case IDs.")
    parser.add_argument("--results-dir", type=Path, default=Path("results") / "runs_c3")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format='%(asctime)s - %(levelname)s - %(message)s')

    model_tag = VARIANT_MODELS[args.variant]
    preflight_auth([MODEL_HOSTS[model_tag]])

    if args.cases == "supported":
        manifest = [json.loads(l) for l in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines() if l.strip()]
        case_ids = [r["case_id"] for r in manifest if r.get("semgrep_representability") == "supported"]
    else:
        case_ids = [c.strip() for c in args.cases.split(",") if c.strip()]

    run_variant_on_cases(args.variant, case_ids, args.results_dir)


if __name__ == "__main__":
    main()
