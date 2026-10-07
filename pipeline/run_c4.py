"""
C4 (heterogeneous multi-agent) -- design Sections 18.4-18.6. Scoped in Research_Log/C4_Scope.md.

Unlike C2/C3, most of C4's design decisions are already resolved by earlier work:
  - C4-A ("best pilot-performing model per role", Section 18.4) IS Phase 3's role-capability
    screening output directly (Implementation_Log 12.40-12.49) -- no new decision needed.
  - C4-B ("strong model for analysis/generation/repair, smaller model for syntax/semantic review",
    Section 18.5) reuses the exact strong/efficient pair C3-S/C3-E already established
    (qwen2.5-coder:32b / qwen2.5-coder:7b-instruct), per C4_Scope.md.
  - The workflow (Section 17.1) and budget resolution (Section 20, one repair round, no second
    Semantic Review call -- Implementation_Log 12.50) are UNCHANGED from C3. The only thing that
    differs between C3 and C4 is WHICH model answers each of the 5 role-specific calls.

This module deliberately does NOT modify run_c3.py's own orchestration code, to avoid any risk to
C3's already-reported, trusted results -- it imports run_c3.py's prompt-building and
response-parsing functions directly (pure functions, no model-specific behavior) and implements its
own episode loop with per-role (model_tag, LLMClient) routing instead of one shared model/client for
the whole episode.

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_c4.py --variant C4-A --cases CASE-0041,CASE-0042
    python pipeline/run_c4.py --variant C4-B --cases supported --results-dir results/runs_c4
"""
import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS  # noqa: E402
from case_loader import load_case  # noqa: E402
from sample_evaluation import evaluate_case_bundle  # noqa: E402
from result_schema import make_run_id, append_jsonl  # noqa: E402
from run_c3 import (  # noqa: E402
    build_patch_analysis_prompt, parse_patch_analysis_response,
    build_rule_generation_prompt, build_syntax_review_prompt, parse_syntax_review_response,
    build_semantic_review_prompt, parse_semantic_review_response, build_rule_repair_prompt,
    _call, _dump_rule, _check_original_pair, _load_frozen_manifest_index,
    MAX_LLM_CALLS, BENCH_DIR,
)

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient, _make_suggested_id  # noqa: E402
from rule_validator import RuleValidator  # noqa: E402

ROLES = ("patch_analysis", "rule_generation", "syntax_review", "semantic_review", "rule_repair")

# C4_Scope.md: C4-A is Phase 3's own measured per-role assignments; C4-B reuses C3-S/C3-E's pair.
C4_CONFIGS = {
    "C4-A": {
        "patch_analysis": "qwen3-coder-next:latest",
        "rule_generation": "qwen2.5-coder:7b-instruct",
        "syntax_review": "qwen2.5-coder:7b-instruct",
        "semantic_review": "deepseek-r1:14b",
        "rule_repair": "qwen2.5-coder:32b",
    },
    "C4-B": {
        "patch_analysis": "qwen2.5-coder:32b",
        "rule_generation": "qwen2.5-coder:32b",
        "rule_repair": "qwen2.5-coder:32b",
        "syntax_review": "qwen2.5-coder:7b-instruct",
        "semantic_review": "qwen2.5-coder:7b-instruct",
    },
}


@dataclass
class C4EpisodeRecord:
    run_id: str
    case_id: str
    variant: str
    condition: str  # "c4"
    role_models: dict
    accepted: bool
    rule_id: Optional[str]
    calls_used: int
    accepted_at_round: Optional[int]
    stop_reason: str
    patch_analysis: Optional[dict]
    syntax_review_round0: Optional[dict]
    semantic_review_round0: Optional[dict]
    rule_repair: Optional[dict]
    syntax_review_round1: Optional[dict]
    validation_error: Optional[str]
    timestamp: float


def run_c4_episode(case_id: str, variant: str, role_models: dict, clients: dict, parser_client: LLMClient,
                    validator: RuleValidator, run_id: str, frozen_manifest: dict, max_tokens: int):
    """Same workflow and budget resolution as run_c3.run_c3_episode(), generalized to route each of
    the 5 calls to its own role's assigned model/client instead of one shared model for everything."""
    patch_info = load_case(case_id, clients["patch_analysis"].config)
    case_dir = BENCH_DIR / "cases" / case_id
    language = patch_info.file_changes[0].language
    diff_text = (case_dir / "patch.diff").read_text()
    repo_path_marker = Path(f"<curated-case:{case_id}>")
    calls_used = 0

    # --- Call 1: Patch Analysis ---
    content = _call(clients["patch_analysis"], role_models["patch_analysis"],
                     build_patch_analysis_prompt(patch_info, diff_text),
                     "You are a precise security patch analyst.", max_tokens)
    calls_used += 1
    spec = parse_patch_analysis_response(content)

    # --- Call 2: Rule Generation ---
    suggested_id = _make_suggested_id(patch_info)
    content = _call(clients["rule_generation"], role_models["rule_generation"],
                     build_rule_generation_prompt(spec, language, suggested_id),
                     "You generate Semgrep rules in YAML format. Return only raw YAML.", max_tokens)
    calls_used += 1
    rule = parser_client.parse_and_sanitize_response(content, patch_info)

    syntax_round0 = semantic_round0 = rule_repair_result = syntax_round1 = None
    accepted_rule = None
    accepted_at_round = None
    stop_reason = "rejected_round1"
    last_error = None

    for round_num in (0, 1):
        if calls_used >= MAX_LLM_CALLS:
            stop_reason = "max_llm_calls"
            break

        # --- Syntax Review ---
        if rule is not None:
            rule_text_for_review = _dump_rule(rule)
            is_valid, semgrep_error = validator.validate_rule(rule, patch_info, repo_path_marker)
        else:
            rule_text_for_review = content
            is_valid, semgrep_error = False, parser_client.last_error or "failed to parse/sanitize into a rule"

        syntax_content = _call(clients["syntax_review"], role_models["syntax_review"],
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
            candidate_rule = parser_client.parse_and_sanitize_response(corrected_text, patch_info)
            if candidate_rule is not None:
                rule = candidate_rule
                is_valid, semgrep_error = validator.validate_rule(rule, patch_info, repo_path_marker)

        if round_num == 1:
            if is_valid:
                accepted_rule = rule
                accepted_at_round = 1
                stop_reason = "accepted_round1"
            else:
                last_error = semgrep_error
                stop_reason = "rejected_round1"
            break

        # --- Semantic Review (round 0 only) ---
        if calls_used >= MAX_LLM_CALLS:
            stop_reason = "max_llm_calls"
            break
        vuln_detected, patched_detected = _check_original_pair(validator, rule, patch_info) if rule else (False, False)
        semantic_content = _call(clients["semantic_review"], role_models["semantic_review"],
                                  build_semantic_review_prompt(rule_text_for_review, patch_info, vuln_detected, patched_detected),
                                  "You are a precise Semgrep rule semantic reviewer.", max_tokens)
        calls_used += 1
        semantic_round0 = parse_semantic_review_response(semantic_content)

        if semantic_round0["verdict"] == "ACCEPTED" and is_valid:
            accepted_rule = rule
            accepted_at_round = 0
            stop_reason = "accepted_round0"
            break

        # --- Rule Repair ---
        if calls_used >= MAX_LLM_CALLS:
            stop_reason = "max_llm_calls"
            break
        repair_content = _call(clients["rule_repair"], role_models["rule_repair"],
                                build_rule_repair_prompt(rule_text_for_review, semgrep_error, semantic_round0.get("repair_instructions")),
                                "You are a precise Semgrep rule repair specialist.", max_tokens)
        calls_used += 1
        rule = parser_client.parse_and_sanitize_response(repair_content, patch_info)
        rule_repair_result = {"proposed_rule_parsed": rule is not None}
        last_error = semgrep_error

    sample_records = []
    if accepted_rule is not None:
        frozen = frozen_manifest.get(case_id, {})
        sample_records, bundle_error = evaluate_case_bundle(
            accepted_rule, case_dir, language, validator,
            run_id, case_id, "c4", "c4",
            vulnerable_lines=frozen.get("vulnerable_lines"),
        )
        if bundle_error:
            last_error = bundle_error

    episode = C4EpisodeRecord(
        run_id=run_id, case_id=case_id, variant=variant, condition="c4", role_models=role_models,
        accepted=accepted_rule is not None,
        rule_id=accepted_rule["id"] if accepted_rule else None,
        calls_used=calls_used, accepted_at_round=accepted_at_round, stop_reason=stop_reason,
        patch_analysis=spec, syntax_review_round0=syntax_round0, semantic_review_round0=semantic_round0,
        rule_repair=rule_repair_result, syntax_review_round1=syntax_round1,
        validation_error=last_error if accepted_rule is None else None,
        timestamp=time.time(),
    )
    return episode, sample_records


def run_variant_on_cases(variant: str, case_ids: list, results_root: Path):
    role_models = C4_CONFIGS[variant]
    unique_models = sorted(set(role_models.values()))
    logging.info(f"[{variant}] role assignments: {role_models}")

    configs = {m: build_config(m, temperature=0.0, prompt_variant="autogrep_default") for m in unique_models}
    for m, cfg in configs.items():
        # Reasoning models (deepseek-r1, QwQ) need far more than the 120s default -- confirmed live
        # during Phase 3 screening (Implementation_Log 12.44) and again here: the first full C4-A
        # attempt hit 4 timeouts in the first 23 cases before this fix (deepseek-r1:14b plays
        # semantic review in C4-A), each one silently dropping that case from the run entirely.
        if any(k in m.lower() for k in ("deepseek-r1", "qwq")):
            cfg.request_timeout_seconds = 600.0
    clients_by_model = {m: LLMClient(configs[m]) for m in unique_models}
    clients = {role: clients_by_model[model_tag] for role, model_tag in role_models.items()}
    parser_client = clients["rule_generation"]  # parse_and_sanitize_response is model-agnostic; any client works
    validator = RuleValidator(configs[unique_models[0]])  # RuleValidator is also model-agnostic (real Semgrep only)
    max_tokens = 2048

    results_root = Path(results_root).resolve()
    run_dir = results_root / variant
    run_dir.mkdir(parents=True, exist_ok=True)
    episode_log = run_dir / "c4_episode_log.jsonl"
    sample_log = run_dir / "sample_execution_log.jsonl"

    frozen_manifest = _load_frozen_manifest_index()
    run_id = make_run_id(variant)

    already_done = set()
    if episode_log.exists():
        for line in episode_log.read_text().splitlines():
            if line.strip():
                already_done.add(json.loads(line)["case_id"])
    pending = [c for c in case_ids if c not in already_done]
    if already_done:
        logging.info(f"[{variant}] resuming: {len(already_done)}/{len(case_ids)} already done")
    logging.info(f"[{variant}] processing {len(pending)} case(s) under C4")

    for case_id in pending:
        try:
            episode, sample_records = run_c4_episode(
                case_id, variant, role_models, clients, parser_client, validator, run_id, frozen_manifest, max_tokens
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
    parser = argparse.ArgumentParser(description="C4 (heterogeneous multi-agent) runner -- see module docstring.")
    parser.add_argument("--variant", required=True, choices=list(C4_CONFIGS.keys()))
    parser.add_argument("--cases", required=True,
                         help="'supported' for all supported-representability final cases, or a comma-separated list of case IDs.")
    parser.add_argument("--results-dir", type=Path, default=Path("results") / "runs_c4")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format='%(asctime)s - %(levelname)s - %(message)s')

    role_models = C4_CONFIGS[args.variant]
    preflight_auth([MODEL_HOSTS[m] for m in set(role_models.values())])

    if args.cases == "supported":
        manifest = [json.loads(l) for l in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines() if l.strip()]
        case_ids = [r["case_id"] for r in manifest if r.get("semgrep_representability") == "supported"]
    else:
        case_ids = [c.strip() for c in args.cases.split(",") if c.strip()]

    run_variant_on_cases(args.variant, case_ids, args.results_dir)


if __name__ == "__main__":
    main()
