"""
C2 ("iterative single agent") -- design doc Section 18.2: "The same model generates, interprets
Semgrep feedback, and repairs its rule. Give it the same call and token budget as C3." Scoped in
Research_Log/C2_Scope.md; see that doc for why C2 does NOT depend on Phase 3/C3's role screening
(Section 20 already fixes a concrete budget directly) and why this is a standalone runner rather
than a further modification of Autogrep's own retry loop (used by Phase 5's "autogrep" condition,
whose results are already locked and must not be put at risk of a behavioral change).

Budget (design Section 20, adopted as-is):
    max_llm_calls: 6
    max_combined_input_tokens: 30000
    max_combined_output_tokens: 6000
    max_repair_rounds: 3
    max_wall_clock_minutes: 10

Call-accounting decision (Section 20's own numbers resolve an ambiguity the spec's prose leaves
open -- see C2_Scope.md): interpreting Semgrep's feedback and repairing the rule are ONE combined
call per round, not two. Two calls/round x 3 rounds = 6, plus the initial generation call = 7,
which overshoots max_llm_calls:6 on its own; one call/round fits (1 initial + 3 rounds = 4 calls,
2 calls of slack). Each round's single call is exactly `LLMClient.generate_rule(patch_info,
error_feedback)` with error_feedback set to the previous round's real Semgrep validation error --
the same per-call shape Autogrep's own retry loop already uses, just budget-capped differently
(cumulative tokens + wall clock, not just a bare attempt count) and run outside that loop entirely.

The actual OpenAI call is reimplemented here (not calling LLMClient.generate_rule() directly)
solely to capture response.usage (token counts) and wall-clock duration per call -- generate_rule()
discards both. Everything else (prompt construction, response parsing/sanitization, rule
validation against the curated case's clone-free standalone files) reuses Autogrep's real code
unmodified: LLMClient._build_prompt()/parse_and_sanitize_response(), RuleValidator.validate_rule().

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_c2.py --models qwen2.5-coder:7b-instruct --cases CASE-0041,CASE-0042
    python pipeline/run_c2.py --models qwen2.5-coder:7b-instruct --cases supported --results-dir results/runs_c2
"""
import argparse
import json
import logging
import platform
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS, PRIMARY_MODEL_HOSTS  # noqa: E402
from case_loader import load_case  # noqa: E402
from result_schema import append_jsonl, make_run_id  # noqa: E402
from sample_evaluation import evaluate_case_bundle  # noqa: E402

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))
from llm_client import LLMClient  # noqa: E402
from rule_validator import RuleValidator  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"

# Design Section 20, adopted as-is -- see this module's docstring for the call-accounting resolution.
MAX_LLM_CALLS = 6
MAX_COMBINED_INPUT_TOKENS = 30000
MAX_COMBINED_OUTPUT_TOKENS = 6000
MAX_REPAIR_ROUNDS = 3
MAX_WALL_CLOCK_SECONDS = 10 * 60

# Same system prompt LLMClient.generate_rule() sends -- duplicated here (not imported) only
# because this module makes its own chat.completions.create() call to capture usage/timing,
# which generate_rule() does not expose.
_SYSTEM_PROMPT = """You generate Semgrep rules in YAML format.
    Return only the raw YAML content without any markdown formatting or additional text.
    Always include these required fields: id, pattern, message, severity, languages"""


@dataclass
class C2EpisodeRecord:
    """Episode-level record (one row per case+model), distinct in shape from GenerationRecord's
    per-attempt schema -- C2's unit of accounting is the whole budget-capped episode, not a single
    attempt. Kept in this module rather than added to result_schema.py to avoid touching the shared
    schema file Phase 5's already-locked results depend on."""
    run_id: str
    case_id: str
    model_tag: str
    host: str
    condition: str  # always "c2"
    temperature: float
    accepted: bool
    rule_id: Optional[str]
    calls_used: int
    repair_rounds_used: int
    input_tokens_used: int
    output_tokens_used: int
    wall_clock_seconds: float
    stop_reason: str  # "accepted" | "max_llm_calls" | "max_repair_rounds" | "max_wall_clock" | "max_input_tokens" | "max_output_tokens"
    validation_error: Optional[str]
    timestamp: float

    def to_json(self) -> str:
        return json.dumps(asdict(self))


def _call_model(llm_client: LLMClient, patch_info, error_feedback: Optional[str]):
    """One budget-tracked call: builds the prompt (reusing LLMClient's real prompt-building,
    including the error_feedback-appending behavior already used by Autogrep's own retry loop),
    calls the API directly to capture usage/timing, and parses the response via Autogrep's real
    parse_and_sanitize_response(). Returns (rule_or_None, input_tokens, output_tokens, seconds)."""
    prompt = llm_client._build_prompt(patch_info, error_feedback)
    kwargs = {}
    if llm_client.config.max_output_tokens is not None:
        kwargs["max_tokens"] = llm_client.config.max_output_tokens
    t0 = time.monotonic()
    try:
        response = llm_client.client.chat.completions.create(
            model=llm_client.config.model_name,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=llm_client.config.generation_temperature,
            **kwargs,
        )
    except Exception as e:
        llm_client.last_error = f"Error generating rule: {e}"
        logging.error(llm_client.last_error)
        return None, 0, 0, time.monotonic() - t0
    elapsed = time.monotonic() - t0

    usage = getattr(response, "usage", None)
    in_tok = getattr(usage, "prompt_tokens", 0) or 0
    out_tok = getattr(usage, "completion_tokens", 0) or 0

    if not response.choices:
        llm_client.last_error = "No response generated from LLM"
        return None, in_tok, out_tok, elapsed

    content = response.choices[0].message.content
    rule = llm_client.parse_and_sanitize_response(content, patch_info)
    return rule, in_tok, out_tok, elapsed


def run_c2_episode(case_id: str, model_tag: str, host: str, config,
                    llm_client: LLMClient, validator: RuleValidator, run_id: str,
                    frozen_manifest: dict):
    """Runs one case through the full C2 budget-capped episode. Returns (episode_record, sample_records)."""
    patch_info = load_case(case_id, config)
    case_dir = BENCH_DIR / "cases" / case_id
    language = patch_info.file_changes[0].language
    # Never read -- validate_rule() branches on patch_info.case_id being set and reads the
    # curated case's standalone files directly (Section 12.24's clone-free refactor). Same
    # synthetic-marker convention git_manager.py's prepare_repo() uses.
    repo_path_marker = Path(f"<curated-case:{case_id}>")

    episode_start = time.monotonic()
    calls_used = 0
    repair_rounds_used = 0
    input_tokens_used = 0
    output_tokens_used = 0
    error_feedback = None
    accepted_rule = None
    stop_reason = "max_repair_rounds"  # default if the loop exits via the round cap below
    last_error = None

    while True:
        elapsed = time.monotonic() - episode_start
        if calls_used >= MAX_LLM_CALLS:
            stop_reason = "max_llm_calls"
            break
        if elapsed >= MAX_WALL_CLOCK_SECONDS:
            stop_reason = "max_wall_clock"
            break
        if input_tokens_used >= MAX_COMBINED_INPUT_TOKENS:
            stop_reason = "max_input_tokens"
            break
        if output_tokens_used >= MAX_COMBINED_OUTPUT_TOKENS:
            stop_reason = "max_output_tokens"
            break
        if calls_used > 0 and repair_rounds_used >= MAX_REPAIR_ROUNDS:
            stop_reason = "max_repair_rounds"
            break

        rule, in_tok, out_tok, _ = _call_model(llm_client, patch_info, error_feedback)
        calls_used += 1
        input_tokens_used += in_tok
        output_tokens_used += out_tok
        if calls_used > 1:
            repair_rounds_used += 1

        if rule is None:
            last_error = llm_client.last_error or "failed to parse/sanitize into a rule"
            error_feedback = last_error
            continue

        is_valid, error = validator.validate_rule(rule, patch_info, repo_path_marker)
        if is_valid:
            accepted_rule = rule
            stop_reason = "accepted"
            break
        last_error = error
        error_feedback = error

    wall_clock_seconds = time.monotonic() - episode_start

    sample_records = []
    if accepted_rule is not None:
        frozen = frozen_manifest.get(case_id, {})
        sample_records, bundle_error = evaluate_case_bundle(
            accepted_rule, case_dir, language, validator,
            run_id, case_id, model_tag, "c2",
            vulnerable_lines=frozen.get("vulnerable_lines"),
        )
        if bundle_error:
            last_error = bundle_error

    episode = C2EpisodeRecord(
        run_id=run_id, case_id=case_id, model_tag=model_tag, host=host, condition="c2",
        temperature=config.generation_temperature, accepted=accepted_rule is not None,
        rule_id=accepted_rule["id"] if accepted_rule else None,
        calls_used=calls_used, repair_rounds_used=repair_rounds_used,
        input_tokens_used=input_tokens_used, output_tokens_used=output_tokens_used,
        wall_clock_seconds=wall_clock_seconds, stop_reason=stop_reason,
        validation_error=last_error if accepted_rule is None else None,
        timestamp=time.time(),
    )
    return episode, sample_records


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


def _completed_case_ids(episode_log: Path) -> set:
    if not episode_log.exists():
        return set()
    done = set()
    for line in episode_log.read_text().splitlines():
        if not line.strip():
            continue
        try:
            done.add(json.loads(line)["case_id"])
        except (json.JSONDecodeError, KeyError):
            continue
    return done


def record_environment(run_dir: Path, model_tag: str, config) -> None:
    env = {
        "model_tag": model_tag,
        "condition": "c2",
        "base_url": config.openrouter_base_url,
        "temperature": config.generation_temperature,
        "budget": {
            "max_llm_calls": MAX_LLM_CALLS,
            "max_combined_input_tokens": MAX_COMBINED_INPUT_TOKENS,
            "max_combined_output_tokens": MAX_COMBINED_OUTPUT_TOKENS,
            "max_repair_rounds": MAX_REPAIR_ROUNDS,
            "max_wall_clock_seconds": MAX_WALL_CLOCK_SECONDS,
        },
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "recorded_at": time.time(),
    }
    try:
        env["semgrep_version"] = subprocess.run(
            ["semgrep", "--version"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except Exception:
        env["semgrep_version"] = None
    try:
        pinned = (AUTOGREP_DIR / "PINNED_COMMIT").read_text().split()[0]
        env["autogrep_commit"] = pinned
    except Exception:
        env["autogrep_commit"] = None
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "environment.json").write_text(json.dumps(env, indent=2))


def run_model_on_cases(model_tag: str, case_ids: list, results_root: Path, temperature: float) -> None:
    host = MODEL_HOSTS[model_tag]
    safe_name = model_tag.replace("/", "_").replace(":", "_")
    run_id = make_run_id(model_tag)
    results_root = Path(results_root).resolve()
    run_dir = results_root / f"{safe_name}__c2"

    frozen_manifest = _load_frozen_manifest_index()
    config = build_config(model_tag, temperature=temperature, prompt_variant="autogrep_default")
    record_environment(run_dir, model_tag, config)

    llm_client = LLMClient(config)
    validator = RuleValidator(config)

    episode_log = run_dir / "c2_episode_log.jsonl"
    sample_log = run_dir / "sample_execution_log.jsonl"

    already_done = _completed_case_ids(episode_log)
    pending = [c for c in case_ids if c not in already_done]
    if already_done:
        logging.info(f"[{model_tag}] resuming: {len(already_done)}/{len(case_ids)} case(s) "
                      f"already complete in {episode_log}, {len(pending)} remaining")
    logging.info(f"[{model_tag}] processing {len(pending)} case(s) under C2, run_id={run_id}")

    for case_id in pending:
        try:
            episode, sample_records = run_c2_episode(
                case_id, model_tag, host, config, llm_client, validator, run_id, frozen_manifest
            )
        except Exception as e:
            logging.error(f"[{case_id}] unexpected error: {e}", exc_info=True)
            continue
        append_jsonl([episode], episode_log)
        append_jsonl(sample_records, sample_log)
        logging.info(f"[{case_id}] accepted={episode.accepted} calls={episode.calls_used} "
                     f"repair_rounds={episode.repair_rounds_used} stop_reason={episode.stop_reason}")

    logging.info(f"[{model_tag}] done -> {episode_log}")


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
            sys.exit(f"Preflight FAILED on {host}: HTTP {r.status_code} - {r.text[:120]}. Nothing was run.")
        logging.info(f"Preflight OK on {host} ({len(r.json().get('data', []))} models visible)")


def main():
    parser = argparse.ArgumentParser(description="C2 (iterative single agent) runner -- see module docstring.")
    parser.add_argument("--models", required=True,
                         help="Comma-separated model tags, or 'primary' for all 8 verified primary models.")
    parser.add_argument("--cases", required=True,
                         help="'supported' for all supported-representability final cases, "
                              "or a comma-separated list of case IDs (e.g. CASE-0041,CASE-0042).")
    parser.add_argument("--results-dir", type=Path, default=Path("results") / "runs_c2")
    # Section 20 names no temperature for C2; Section 13.3's primary deterministic configuration
    # (temp 0) is adopted as the default here, matching the Phase 5 primary benchmark's own
    # condition, since C2 is meant to compare against single-model performance under matched
    # settings. Override with --temperature if a different comparison is wanted.
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                         format='%(asctime)s - %(levelname)s - %(message)s')

    if args.models == "primary":
        models = list(PRIMARY_MODEL_HOSTS.keys())
    else:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
        for m in models:
            if m not in MODEL_HOSTS:
                parser.error(f"Unknown model tag: {m}. Known tags: {list(MODEL_HOSTS)}")

    preflight_auth(MODEL_HOSTS[m] for m in models)

    if args.cases == "supported":
        # FINAL set only, not _load_frozen_manifest_index()'s pilot+final combined index -- the pilot's
        # 40 cases are all labeled "supported" too (used for model/prompt SELECTION, design Section 6,
        # never for benchmark evaluation), so that combined index would silently pull in 40 cases that
        # don't belong here. Found live: the first launch attempt reported "193 case(s)" instead of the
        # expected 153, caught before any real cost beyond 2 HTTP calls -- stopped and fixed immediately.
        final_manifest = [json.loads(l) for l in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines() if l.strip()]
        case_ids = [r["case_id"] for r in final_manifest if r.get("semgrep_representability") == "supported"]
    else:
        case_ids = [c.strip() for c in args.cases.split(",") if c.strip()]

    for model_tag in models:
        run_model_on_cases(model_tag, case_ids, args.results_dir, args.temperature)


if __name__ == "__main__":
    main()
