"""
Run v2 episode: one model on one case (Research_Log/Run_v2_Specification.md, supervisor Issue 5).

Why one shared attempt chain. In v1, Autogrep's retry loop (autogrep/main.py) and the iterative loop
(pipeline/run_c2.py) made the same call each round -- the prompt plus the previous round's error as feedback --
and differed only in budget: Autogrep up to 3 attempts; the iterative loop up to 4 attempts (1 + 3 repairs)
within 30,000 input tokens, 6,000 output tokens and 10 minutes. They were run separately, days apart, so their
difference mixed one extra attempt with run-to-run variation and timing (Issue 5). Run v2 makes ONE chain of
attempts per model and case and reads all three workflows from it:
  single_shot = attempt 1
  autogrep    = attempts 1-3
  iterative   = attempts 1-4, as far as the iterative budget allows (checked before each call, as v1 did)
So the workflows differ only in their budgets, by construction, and every attempt is shared.

Acceptance (the check that ends the chain) is the run v2 visible gate: both visible files scanned cleanly, the
vulnerable file detected at the annotated location (primary location method), the patched file not detected.
The v1-style check (no location) is recorded too, as a secondary measure.

Everything is recorded per attempt: the exact prompt and system message, the raw response, token usage, timing,
the failure stage, the gate result, and the budget used before the call. After the chain, every rule it produced
is scored on all six samples, so the analysis can score any workflow without running Semgrep again.

Infrastructure failures (the API raising) are retried with backoff; if they persist the episode raises
InfraError and is NOT recorded, so the runner can resume it later from scratch (specification, stop rule 2).
They never count as a model failure.
"""
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

import sample_evaluation as SE

# Budgets (v1 values, unchanged: Autogrep max_retries=3; run_c2.py's constants).
AUTOGREP_MAX_ATTEMPTS = 3
ITERATIVE_MAX_LLM_CALLS = 6
ITERATIVE_MAX_REPAIR_ROUNDS = 3
ITERATIVE_MAX_INPUT_TOKENS = 30000
ITERATIVE_MAX_OUTPUT_TOKENS = 6000
ITERATIVE_MAX_WALL_CLOCK_SECONDS = 10 * 60
MAX_ATTEMPTS = 1 + ITERATIVE_MAX_REPAIR_ROUNDS          # the longest chain any workflow can use
WORKFLOWS = ("single_shot", "autogrep", "iterative")

API_RETRIES = 3
API_BACKOFF_SECONDS = (10, 60, 300)

# Feedback for a rejected rule. The first two are v1's own messages (autogrep/rule_validator.py); the others
# cover cases v1 could not tell apart. None gives line numbers or any other hidden information.
FB_NOT_DETECTED = "Rule failed to detect vulnerability in original version"
FB_PATCHED_DETECTED = "Rule incorrectly detected vulnerability in fixed version"
FB_WRONG_LOCATION = "Rule matched the original version, but not at the code changed by the patch"
FB_NOT_SCANNED = "Semgrep did not scan the target file: the rule's languages do not match the file's language ({language})"
FB_TARGET_PARSE = "Semgrep could not fully parse the target file with this rule's language"
# Part II probe feedback: v1's message (pipeline/diagnostic_v2.py run_model_case_cd); the probe is built only from the
# visible functions, so the message reveals nothing hidden.
FB_PROBE = ("Rule correctly handled the original vulnerable/patched pair, but failed an additional development-time "
            "test case ({reason}). Your rule must also correctly handle this additional test case.")


class InfraError(RuntimeError):
    """The model API kept failing; the episode must be resumed later, not recorded."""


@dataclass
class Attempt:
    index: int                                  # 1-based
    feedback_in: Optional[str]                  # feedback this attempt received (None for attempt 1)
    system_message: str
    prompt: str
    raw_response: Optional[str]
    input_tokens: int
    output_tokens: int
    seconds: float
    api_retries: int
    failure_stage: Optional[str]                # LLMClient.last_failure_stage, None if a rule was parsed
    error: Optional[str]                        # parse error or gate failure, i.e. the next attempt's feedback
    rule: Optional[dict]
    accepted: bool                              # passed the run v2 visible gate
    accepted_visible_only: Optional[bool]       # v1-style gate (no location); None if no rule
    gate_scan_status: Optional[Dict[str, str]]  # visible sample -> scan status
    budget_before: Dict[str, float]             # calls, input_tokens, output_tokens, seconds used before this call
    within_iterative_budget: bool
    probe: Optional[dict] = None                # Part II C/D: probe scan result, when the visible gate passed


@dataclass
class Episode:
    run_id: str
    case_id: str
    model_tag: str
    attempts: List[Attempt] = field(default_factory=list)
    stop_reason: str = ""
    workflows: Dict[str, dict] = field(default_factory=dict)
    samples: Dict[int, List[dict]] = field(default_factory=dict)   # attempt index -> six sample records
    probe_eligible: Optional[bool] = None       # Part II C/D only

    def to_dict(self):
        return asdict(self)


def visible_gate(records, language: str):
    """(accepted, accepted_visible_only, feedback) from the two visible sample records."""
    by = {r.sample_type: r for r in records}
    vuln, patched = by["original_vulnerable"], by["original_patched"]
    for r in (vuln, patched):
        if r.scan_status == "rule_error":
            return False, False, r.scan_message or "Semgrep rejected the rule"
        if r.scan_status == "not_scanned":
            return False, False, FB_NOT_SCANNED.format(language=language)
        if r.scan_status == "target_parse_error":
            return False, False, FB_TARGET_PARSE
        if r.scan_status != "ok":
            return False, False, r.scan_message or "Semgrep failed"
    visible_only = vuln.detected and not patched.detected
    if not vuln.detected:
        return False, visible_only, FB_NOT_DETECTED
    if patched.detected:
        return False, visible_only, FB_PATCHED_DETECTED
    if vuln.finding_location_correct is False:
        return False, visible_only, FB_WRONG_LOCATION
    return True, visible_only, None


def _iterative_allows(budget: Dict[str, float], attempt_index: int) -> bool:
    """v1's run_c2 check, made before each call."""
    return (budget["calls"] < ITERATIVE_MAX_LLM_CALLS
            and budget["seconds"] < ITERATIVE_MAX_WALL_CLOCK_SECONDS
            and budget["input_tokens"] < ITERATIVE_MAX_INPUT_TOKENS
            and budget["output_tokens"] < ITERATIVE_MAX_OUTPUT_TOKENS
            and attempt_index - 1 <= ITERATIVE_MAX_REPAIR_ROUNDS)


def _typed(llm_client) -> bool:
    return getattr(llm_client.config, "construction_mode", "original_prompt") == "typed_json"


def parse_reply(llm_client, raw, patch_info):
    """Free-form YAML or typed JSON, by the client's construction mode (Part II cells B/D use typed JSON)."""
    if _typed(llm_client):
        return llm_client._parse_typed_json_response(raw, patch_info)
    return llm_client.parse_and_sanitize_response(raw, patch_info)


def call_model(llm_client, patch_info, feedback, sleep=time.sleep, clock=time.monotonic):
    """One model call with transport retries. Returns (system, prompt, raw, in_tokens, out_tokens, seconds, retries).
    Raises InfraError if the API keeps failing."""
    if _typed(llm_client):
        system = llm_client._system_message_typed_json()
        prompt = llm_client._build_prompt_typed_json_v2(patch_info, feedback)
    else:
        system = llm_client._system_message()
        prompt = llm_client._build_prompt(patch_info, feedback)
    kwargs = {}
    if llm_client.config.max_output_tokens is not None:
        kwargs["max_tokens"] = llm_client.config.max_output_tokens
    last = None
    for retry in range(API_RETRIES + 1):
        t0 = clock()
        try:
            resp = llm_client.client.chat.completions.create(
                model=llm_client.config.model_name,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                temperature=llm_client.config.generation_temperature, **kwargs)
        except Exception as e:                                    # transport / server error
            last = e
            if retry < API_RETRIES:
                sleep(API_BACKOFF_SECONDS[min(retry, len(API_BACKOFF_SECONDS) - 1)])
            continue
        seconds = clock() - t0
        usage = getattr(resp, "usage", None)
        raw = resp.choices[0].message.content if getattr(resp, "choices", None) else None
        return (system, prompt, raw, getattr(usage, "prompt_tokens", 0) or 0,
                getattr(usage, "completion_tokens", 0) or 0, seconds, retry)
    raise InfraError(f"model API failed {API_RETRIES + 1} times: {last}")


def probe_check(rule, probe_files, scanner=None):
    """Part II C/D (v1's combined_gate semantics): pass iff the vulnerable probe is detected and the patched probe is
    not. A scan that is not "ok" counts as a failed check, never as "no probe"."""
    import semgrep_runner
    scanner = scanner or semgrep_runner.scan
    vuln, patched = (str(p) for p in probe_files)
    out = scanner(rule, [vuln, patched])
    status = {"vulnerable_probe": out[vuln].status, "patched_probe": out[patched].status}
    if any(st != "ok" for st in status.values()):
        return {"passed": False, "reason": "probe scan error", "scan_status": status}
    vd, pd = bool(out[vuln].results), bool(out[patched].results)
    failed = ([] if vd else ["vulnerable_probe_correct"]) + (["patched_probe_correct"] if pd else [])
    return {"passed": not failed, "reason": f"probe check(s) failed: {failed}" if failed else None,
            "scan_status": status, "vulnerable_detected": vd, "patched_detected": pd}


def run_episode(llm_client, patch_info, case_dir: Path, language: str, location_ranges: dict,
                run_id: str, case_id: str, model_tag: str,
                scanner=None, sleep=time.sleep, clock=time.monotonic,
                max_attempts: int = MAX_ATTEMPTS, use_iterative_budget: bool = True,
                probe_files=None, workflows=WORKFLOWS) -> Episode:
    """Part I: the defaults. Part II: max_attempts=3, use_iterative_budget=False, workflows=("single_shot",
    "autogrep") -- v1's Part II loop was 3 attempts with no token or time limit, i.e. the same budget as Autogrep --
    and, for cells C/D with an eligible probe, probe_files=(vulnerable_probe_path, patched_probe_path)."""
    ep = Episode(run_id=run_id, case_id=case_id, model_tag=model_tag)
    budget = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "seconds": 0.0}
    start = clock()
    feedback = None
    iterative_open = True

    for k in range(1, max_attempts + 1):
        budget["seconds"] = clock() - start
        allows = iterative_open and (not use_iterative_budget or _iterative_allows(budget, k))
        iterative_open = allows
        if use_iterative_budget and k > AUTOGREP_MAX_ATTEMPTS and not allows:
            ep.stop_reason = "iterative_budget"
            break

        snapshot = dict(budget)
        system, prompt, raw, tin, tout, secs, retries = call_model(llm_client, patch_info, feedback, sleep, clock)
        budget["calls"] += 1
        budget["input_tokens"] += tin
        budget["output_tokens"] += tout

        rule = parse_reply(llm_client, raw, patch_info)
        probe = None
        stage = None if rule is not None else (llm_client.last_failure_stage or "no_rule_text")
        accepted, visible_only, error, scan_status = False, None, None, None
        if rule is None:
            error = llm_client.last_error or "failed to parse/sanitize into a rule"
        else:
            recs, _ = SE.evaluate_case_bundle_v2(rule, case_dir, language, run_id, case_id, model_tag,
                                                 f"gate_attempt{k}", location_ranges, scanner=scanner,
                                                 only_samples={"original_vulnerable", "original_patched"})
            accepted, visible_only, error = visible_gate(recs, language)
            scan_status = {r.sample_type: r.scan_status for r in recs}
            if accepted and probe_files is not None:
                probe = probe_check(rule, probe_files, scanner)
                if not probe["passed"]:
                    accepted, error = False, FB_PROBE.format(reason=probe["reason"])

        ep.attempts.append(Attempt(
            index=k, feedback_in=feedback, system_message=system, prompt=prompt, raw_response=raw,
            input_tokens=tin, output_tokens=tout, seconds=secs, api_retries=retries,
            failure_stage=stage, error=error, rule=rule, accepted=accepted,
            accepted_visible_only=visible_only, gate_scan_status=scan_status,
            budget_before=snapshot, within_iterative_budget=allows, probe=probe))
        if accepted:
            ep.stop_reason = "accepted"
            break
        feedback = error
    else:
        ep.stop_reason = "max_attempts"

    # Score every rule the chain produced on all six samples.
    for a in ep.attempts:
        if a.rule is not None:
            recs, _ = SE.evaluate_case_bundle_v2(a.rule, case_dir, language, run_id, case_id, model_tag,
                                                 f"attempt{a.index}", location_ranges, scanner=scanner)
            ep.samples[a.index] = [asdict(r) for r in recs]

    ep.workflows = derive_workflows(ep.attempts, workflows)
    ep.probe_eligible = None if probe_files is None else True
    return ep


def derive_workflows(attempts: List[Attempt], workflows=WORKFLOWS) -> Dict[str, dict]:
    """Each workflow's result from the shared chain: the attempts it may use, and the first accepted one."""
    limits = {
        "single_shot": lambda a: a.index == 1,
        "autogrep": lambda a: a.index <= AUTOGREP_MAX_ATTEMPTS,
        "iterative": lambda a: a.within_iterative_budget,
    }
    out = {}
    for wf in workflows:
        used = []
        for a in attempts:
            if not limits[wf](a):
                break
            used.append(a)
            if a.accepted:
                break
        acc = next((a for a in used if a.accepted), None)
        out[wf] = {
            "attempts_used": [a.index for a in used],
            "accepted_attempt": acc.index if acc else None,
            "calls": len(used),
            "input_tokens": sum(a.input_tokens for a in used),
            "output_tokens": sum(a.output_tokens for a in used),
            "accepted_visible_only_attempt": next((a.index for a in used if a.accepted_visible_only), None),
        }
    return out
