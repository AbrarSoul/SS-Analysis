"""
Phase 1 Step 6: the orchestration entry point.

Runs a set of GPT-Lab models against a directory of .patch-format cases,
producing:
  - a "raw" GenerationRecord and an "autogrep" GenerationRecord per case,
    per the design doc's Section 15 distinction (attempt 1's untouched
    output, independently re-evaluated, versus whatever Autogrep's real
    retry loop ultimately settled on)
  - SampleExecutionRecords for the original vulnerable/patched pair, for
    both conditions
  - an environment.json per model run, recording hardware/software/config
    alongside the results (Section 13.5), not just the metrics themselves

Transformed-variant and benign-lookalike samples are not evaluated here --
those require a labeled test bundle that does not exist until dataset
curation (Phase 2/4) builds one. This script evaluates whatever samples a
given case actually has; once Phase 2 adds variant files to a case, this
same script will pick them up without modification, since evaluate_case()
enumerates patch_info.file_changes / repo_path directly rather than
assuming exactly two files exist.

Usage:
    export GPTLAB_API_KEY=...
    python pipeline/run_generation.py --models primary --patches-dir <dir>
    python pipeline/run_generation.py --models qwen2.5-coder:7b-instruct,deepseek-coder:6.7b --patches-dir <dir>
"""
import argparse
import hashlib
import json
import logging
import platform
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS, PRIMARY_MODEL_HOSTS  # noqa: E402
from raw_capture import RawCaptureRecorder, wrap_llm_client  # noqa: E402
from result_schema import GenerationRecord, append_jsonl, make_run_id  # noqa: E402
from sample_evaluation import evaluate_original_pair, evaluate_case_bundle, parse_vulnerable_changed_lines  # noqa: E402
from case_loader import load_case  # noqa: E402

from main import AutoGrep  # noqa: E402


def record_environment(run_dir: Path, model_tag: str, config) -> None:
    """Section 13.5: record hardware/software/config alongside results."""
    env = {
        "model_tag": model_tag,
        "base_url": config.openrouter_base_url,
        "temperature": config.generation_temperature,
        "max_retries": config.max_retries,
        "max_files_changed_configured": config.max_files_changed,
        "max_files_changed_note": "NOT enforced by Autogrep itself -- see PINNED_CONFIG.md",
        "prompt_variant": config.prompt_variant,
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
    # Read from PINNED_COMMIT, not `git -C autogrep rev-parse HEAD`: autogrep/ stopped being its own git
    # repository once the project's own local git repo was set up (its .git was moved aside to
    # autogrep_upstream.git.bak/ so the vendored edits could be tracked as ordinary files). `git -C` in that
    # state silently falls back to the PARENT repo and printed the literal string "HEAD" to stdout instead of
    # failing loudly -- found auditing environment.json while building the Section 30 preregistration checklist.
    try:
        autogrep_dir = Path(__file__).resolve().parent.parent / "autogrep"
        pinned = (autogrep_dir / "PINNED_COMMIT").read_text().split()[0]
        env["autogrep_commit"] = pinned
    except Exception:
        env["autogrep_commit"] = None

    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "environment.json").write_text(json.dumps(env, indent=2))


def reconstruct_attempt_trail(autogen, recorder: RawCaptureRecorder, case_id: str,
                               patch_info, repo_path: Path, max_retries: int) -> list:
    """Independently re-evaluates every captured attempt (not just the
    first) through parse+validate, since Autogrep's own process_patch()
    discards all but the final outcome when every attempt fails -- so a
    total-failure case would otherwise carry zero diagnostic detail about
    *why* each retry failed.

    For a curated case (patch_info.case_id set), repo_path is a synthetic
    marker path that never exists on disk BY DESIGN (git_manager.prepare_repo()
    skips cloning entirely -- Section 12.24) -- rule_validator.validate_rule()
    already knows to read the standalone case files directly in that
    situation, without needing repo_path to exist. The `repo_path.exists()`
    guard below is only meaningful for the raw-.patch-file flow, where a
    missing clone really does mean "can't validate." Applying it
    unconditionally made every curated-case re-validation here report
    "repo not available for validation" instead of the real per-attempt
    outcome -- found auditing the Phase 5 primary results before Phase 7
    analysis (Implementation Log Section 12.30). This bug never affected the
    actual reported semgrep_valid pass/fail counts (autogrep_gen.semgrep_valid
    is set independently from Autogrep's own real process_patch() result,
    not from this function) -- only the diagnostic attempt_trail detail and,
    for total-failure cases, the human-readable validation_error message."""
    trail = []
    for attempt_index in range(1, max_retries + 1):
        f = (recorder.raw_dir / f"{case_id}.json" if attempt_index == 1
             else recorder.retries_dir / f"{case_id}_attempt{attempt_index}.json")
        if not f.exists():
            break  # no further attempts were made this run

        raw_payload = json.loads(f.read_text())
        rule = autogen.llm_client.parse_and_sanitize_response(raw_payload["raw_content"], patch_info)
        if rule is None:
            trail.append({"attempt_index": attempt_index, "yaml_valid": False,
                          "semgrep_valid": False, "error": "failed to parse/sanitize into a rule"})
            continue
        if patch_info.case_id is None and not repo_path.exists():
            trail.append({"attempt_index": attempt_index, "yaml_valid": True,
                          "semgrep_valid": None, "error": "repo not available for validation"})
            continue

        is_valid, error = autogen.rule_validator.validate_rule(rule, patch_info, repo_path)
        trail.append({"attempt_index": attempt_index, "yaml_valid": True,
                      "semgrep_valid": is_valid, "error": error})
    return trail


def evaluate_case(autogen, patch_file: Path, recorder: RawCaptureRecorder,
                   run_id: str, model_tag: str, host: str, config):
    """Runs one case through both conditions. Returns (generation_records, sample_records)."""
    case_id = patch_file.stem
    recorder.begin_case(case_id)

    # Autogrep condition: whatever the real retry loop settles on.
    result = autogen.process_patch(patch_file)
    autogrep_rule, patch_info = (result if result else (None, None))

    # process_patch() doesn't return patch_info on total failure; re-parse
    # it directly (cheap -- no network/LLM calls) so we can still locate the
    # repo for raw-condition re-evaluation below.
    if patch_info is None:
        patch_info = autogen.patch_processor.process_patch(patch_file)
        if patch_info is None:
            logging.error(f"[{case_id}] could not parse the patch at all; skipping")
            return [], []

    repo_path = config.repos_cache_dir / f"{patch_info.repo_owner}_{patch_info.repo_name}"
    changed_lines_by_file = parse_vulnerable_changed_lines(patch_file.read_text())

    gen_records = []
    sample_records = []

    # --- Raw condition: independently re-evaluate attempt 1's captured content ---
    raw_file = recorder.raw_dir / f"{case_id}.json"
    if raw_file.exists():
        raw_payload = json.loads(raw_file.read_text())
        raw_rule = autogen.llm_client.parse_and_sanitize_response(raw_payload["raw_content"], patch_info)

        prompt_text = raw_payload.get("prompt_text")
        prompt_hash = hashlib.sha256(prompt_text.encode()).hexdigest() if prompt_text else None

        raw_gen = GenerationRecord(
            run_id=run_id, case_id=case_id, model_tag=model_tag, host=host,
            condition="raw", attempt_index=1, temperature=raw_payload["temperature"],
            max_retries=config.max_retries, yaml_valid=raw_rule is not None,
            rule_id=raw_rule["id"] if raw_rule else None,
            prompt_hash=prompt_hash,
            timestamp=raw_payload["timestamp"],
        )

        if raw_rule is not None and repo_path.exists():
            raw_samples, raw_rule_error = evaluate_original_pair(
                raw_rule, patch_info, repo_path, autogen.rule_validator,
                run_id, case_id, model_tag, "raw",
                changed_lines_by_file=changed_lines_by_file,
            )
            raw_gen.semgrep_valid = (
                any(s.sample_type == "original_vulnerable" and s.outcome == "TP" for s in raw_samples)
                and any(s.sample_type == "original_patched" and s.outcome == "TN" for s in raw_samples)
            )
            raw_gen.validation_error = raw_rule_error
            sample_records.extend(raw_samples)

        gen_records.append(raw_gen)
    else:
        logging.warning(f"[{case_id}] no raw capture file found -- raw condition skipped")

    # --- Autogrep condition: whatever the retry loop actually returned ---
    attempt_trail = reconstruct_attempt_trail(
        autogen, recorder, case_id, patch_info, repo_path, config.max_retries
    )
    autogrep_gen = GenerationRecord(
        run_id=run_id, case_id=case_id, model_tag=model_tag, host=host,
        condition="autogrep", attempt_index=-1, temperature=config.generation_temperature,
        max_retries=config.max_retries, yaml_valid=autogrep_rule is not None,
        semgrep_valid=autogrep_rule is not None,  # process_patch() already validated this
        rule_id=autogrep_rule["id"] if autogrep_rule else None,
        timestamp=time.time(),
        attempt_trail=attempt_trail,
    )
    if autogrep_rule is None and attempt_trail:
        autogrep_gen.validation_error = attempt_trail[-1].get("error")
    elif autogrep_rule is None:
        # no attempt reached the model (API/auth/network failure): keep the cause instead of a silent blank record
        autogrep_gen.validation_error = getattr(autogen.llm_client, "last_error", None) or "no model response captured"
    if autogrep_rule is not None and repo_path.exists():
        autogrep_samples, autogrep_rule_error = evaluate_original_pair(
            autogrep_rule, patch_info, repo_path, autogen.rule_validator,
            run_id, case_id, model_tag, "autogrep",
            changed_lines_by_file=changed_lines_by_file,
        )
        autogrep_gen.validation_error = autogrep_rule_error
        sample_records.extend(autogrep_samples)
    gen_records.append(autogrep_gen)

    return gen_records, sample_records


def evaluate_case_from_curated(autogen, case_id: str, recorder: RawCaptureRecorder,
                                run_id: str, model_tag: str, host: str, config,
                                frozen_manifest: dict):
    """Curated-case counterpart to evaluate_case() above: loads real case
    data (pipeline/case_loader.py) instead of parsing a raw .patch file,
    feeds it into Autogrep's own generation+retry loop via
    process_patch()'s patch_info_override, and evaluates the resulting
    rule against the full Section 9 six-sample bundle (evaluate_case_bundle())
    instead of just the original vulnerable/patched pair. Returns
    (generation_records, sample_records).

    frozen_manifest is passed in explicitly (not read from a module global)
    so this function has no shared mutable state -- required for
    run_model_on_cases() to be safely called concurrently from multiple
    threads (one per GPU host) without one thread's manifest load racing
    another's."""
    recorder.begin_case(case_id)
    patch_info = load_case(case_id, config)
    case_dir = config.benchmark_cases_dir / case_id
    # a stable, case-derived filename for cache_manager bookkeeping only --
    # its content is never read, since patch_info_override is provided.
    synthetic_patch_file = config.patches_dir / f"{case_id}.patch"

    result = autogen.process_patch(synthetic_patch_file, patch_info_override=patch_info)
    autogrep_rule, _ = (result if result else (None, patch_info))

    repo_path = config.repos_cache_dir / f"{patch_info.repo_owner}_{patch_info.repo_name}"
    language = patch_info.file_changes[0].language

    frozen = frozen_manifest.get(case_id, {})
    vulnerable_lines = frozen.get("vulnerable_lines")

    gen_records = []
    sample_records = []

    # --- Raw condition ---
    raw_file = recorder.raw_dir / f"{case_id}.json"
    if raw_file.exists():
        raw_payload = json.loads(raw_file.read_text())
        raw_rule = autogen.llm_client.parse_and_sanitize_response(raw_payload["raw_content"], patch_info)

        prompt_text = raw_payload.get("prompt_text")
        prompt_hash = hashlib.sha256(prompt_text.encode()).hexdigest() if prompt_text else None

        raw_gen = GenerationRecord(
            run_id=run_id, case_id=case_id, model_tag=model_tag, host=host,
            condition="raw", attempt_index=1, temperature=raw_payload["temperature"],
            max_retries=config.max_retries, yaml_valid=raw_rule is not None,
            rule_id=raw_rule["id"] if raw_rule else None,
            prompt_hash=prompt_hash,
            timestamp=raw_payload["timestamp"],
        )

        if raw_rule is not None:
            raw_samples, raw_rule_error = evaluate_case_bundle(
                raw_rule, case_dir, language, autogen.rule_validator,
                run_id, case_id, model_tag, "raw", vulnerable_lines=vulnerable_lines,
            )
            by_type = {r.sample_type: r for r in raw_samples}
            raw_gen.semgrep_valid = (
                by_type.get("original_vulnerable") is not None and by_type["original_vulnerable"].outcome == "TP"
                and by_type.get("original_patched") is not None and by_type["original_patched"].outcome == "TN"
            )
            raw_gen.validation_error = raw_rule_error
            sample_records.extend(raw_samples)

        gen_records.append(raw_gen)
    else:
        logging.warning(f"[{case_id}] no raw capture file found -- raw condition skipped")

    # --- Autogrep condition ---
    attempt_trail = reconstruct_attempt_trail(
        autogen, recorder, case_id, patch_info, repo_path, config.max_retries
    )
    autogrep_gen = GenerationRecord(
        run_id=run_id, case_id=case_id, model_tag=model_tag, host=host,
        condition="autogrep", attempt_index=-1, temperature=config.generation_temperature,
        max_retries=config.max_retries, yaml_valid=autogrep_rule is not None,
        semgrep_valid=autogrep_rule is not None,
        rule_id=autogrep_rule["id"] if autogrep_rule else None,
        timestamp=time.time(),
        attempt_trail=attempt_trail,
    )
    if autogrep_rule is None and attempt_trail:
        autogrep_gen.validation_error = attempt_trail[-1].get("error")
    elif autogrep_rule is None:
        # no attempt reached the model (API/auth/network failure): keep the cause instead of a silent blank record
        autogrep_gen.validation_error = getattr(autogen.llm_client, "last_error", None) or "no model response captured"
    if autogrep_rule is not None:
        autogrep_samples, autogrep_rule_error = evaluate_case_bundle(
            autogrep_rule, case_dir, language, autogen.rule_validator,
            run_id, case_id, model_tag, "autogrep", vulnerable_lines=vulnerable_lines,
        )
        autogrep_gen.validation_error = autogrep_rule_error
        sample_records.extend(autogrep_samples)
    gen_records.append(autogrep_gen)

    return gen_records, sample_records


def _load_frozen_manifest_index(bench_dir: Path) -> dict:
    # Pilot (CASE-0001..0040) and final (CASE-0041..) partitions are frozen in separate files. Reading only the
    # pilot file left vulnerable_lines empty for every final case, so finding-location correctness (design
    # Section 9.3) would silently never have been measured on the final benchmark (found in the Step 2 pipeline test).
    index = {}
    for name in ("manifest_frozen.jsonl", "manifest_frozen_final.jsonl"):
        path = bench_dir / name
        if path.exists():
            for line in path.read_text().splitlines():
                if line.strip():
                    record = json.loads(line)
                    index[record["case_id"]] = record
    return index


def _completed_case_ids(gen_log: Path) -> set:
    """Case IDs that already have BOTH condition records ("raw" and
    "autogrep") written to gen_log -- i.e. evaluate_case_from_curated() ran
    to completion for them on a prior invocation. append_jsonl() is only
    called once per case, after both GenerationRecords for that case are
    built, so a case_id appearing in the log at all already implies both
    conditions are present; the explicit check below is just defense in
    depth against a hand-edited or truncated log file.

    Enables resuming an interrupted/restarted run without redoing (and
    re-billing GPU time for) cases that already finished -- there was
    previously no way to do this short of re-running every case from
    scratch."""
    if not gen_log.exists():
        return set()
    conditions_seen = defaultdict(set)
    for line in gen_log.read_text().splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        conditions_seen[record.get("case_id")].add(record.get("condition"))
    return {cid for cid, conds in conditions_seen.items() if {"raw", "autogrep"}.issubset(conds)}


def run_model_on_cases(model_tag: str, case_ids: list, results_root: Path,
                        max_retries: int, temperature: float, prompt_variant: str) -> None:
    host = MODEL_HOSTS[model_tag]
    safe_name = model_tag.replace("/", "_").replace(":", "_")
    run_id = make_run_id(model_tag)
    # Must be ABSOLUTE: `git worktree add <path>` is executed from inside the shared clone, so a relative
    # results path (the default is relative!) would create the worktree inside the cached repository
    # (found in the Step 2 pipeline test, which polluted four cached clones).
    results_root = Path(results_root).resolve()
    run_dir = results_root / f"{safe_name}__{prompt_variant}"

    bench_dir = Path(__file__).resolve().parent.parent / "benchmark"
    frozen_manifest = _load_frozen_manifest_index(bench_dir)

    config = build_config(
        model_tag, temperature=temperature, max_retries=max_retries, max_files_changed=1,
        prompt_variant=prompt_variant,
        patches_dir=run_dir / "synthetic_patch_names",  # never read; see evaluate_case_from_curated()
        generated_rules_dir=run_dir / "generated_rules",
        repos_cache_dir=run_dir / "cache" / "repos",
        # Shared across every model/prompt run under the same results_root --
        # each repo's full history is cloned once here; repos_cache_dir above
        # gets a lightweight per-run `git worktree` instead of its own full
        # clone. See GitManager.prepare_repo().
        shared_repos_cache_dir=results_root / "shared_cache" / "repos",
    )
    config.generated_rules_dir.mkdir(parents=True, exist_ok=True)
    config.repos_cache_dir.mkdir(parents=True, exist_ok=True)
    config.patches_dir.mkdir(parents=True, exist_ok=True)
    config.shared_repos_cache_dir.mkdir(parents=True, exist_ok=True)
    config.benchmark_cases_dir = bench_dir / "cases"

    record_environment(run_dir, model_tag, config)

    autogen = AutoGrep(config)
    autogen.rule_manager.load_initial_rules()
    recorder = RawCaptureRecorder(run_dir, run_id)
    wrap_llm_client(autogen.llm_client, recorder)

    gen_log = run_dir / "generation_log.jsonl"
    sample_log = run_dir / "sample_execution_log.jsonl"

    already_done = _completed_case_ids(gen_log)
    pending = [c for c in case_ids if c not in already_done]
    if already_done:
        logging.info(f"[{model_tag}] resuming: {len(already_done)}/{len(case_ids)} case(s) "
                      f"already complete in {gen_log}, {len(pending)} remaining")
    logging.info(f"[{model_tag}] processing {len(pending)} curated case(s), run_id={run_id}")

    for case_id in pending:
        try:
            gen_records, sample_records = evaluate_case_from_curated(
                autogen, case_id, recorder, run_id, model_tag, host, config, frozen_manifest
            )
        except Exception as e:
            logging.error(f"[{case_id}] unexpected error: {e}", exc_info=True)
            continue
        append_jsonl(gen_records, gen_log)
        append_jsonl(sample_records, sample_log)

    logging.info(f"[{model_tag}] done -> {gen_log}")


def run_model(model_tag: str, patches_dir: Path, results_root: Path,
              max_retries: int, temperature: float, prompt_variant: str) -> None:
    host = MODEL_HOSTS[model_tag]
    safe_name = model_tag.replace("/", "_").replace(":", "_")
    run_id = make_run_id(model_tag)
    run_dir = results_root / f"{safe_name}__{prompt_variant}"

    config = build_config(
        model_tag, temperature=temperature, max_retries=max_retries, max_files_changed=1,
        prompt_variant=prompt_variant,
        patches_dir=patches_dir,
        generated_rules_dir=run_dir / "generated_rules",
        repos_cache_dir=run_dir / "cache" / "repos",
        shared_repos_cache_dir=results_root / "shared_cache" / "repos",
    )
    config.generated_rules_dir.mkdir(parents=True, exist_ok=True)
    config.repos_cache_dir.mkdir(parents=True, exist_ok=True)
    config.shared_repos_cache_dir.mkdir(parents=True, exist_ok=True)

    record_environment(run_dir, model_tag, config)

    autogen = AutoGrep(config)
    autogen.rule_manager.load_initial_rules()
    recorder = RawCaptureRecorder(run_dir, run_id)
    wrap_llm_client(autogen.llm_client, recorder)

    gen_log = run_dir / "generation_log.jsonl"
    sample_log = run_dir / "sample_execution_log.jsonl"

    patch_files = sorted(patches_dir.glob("*.patch"))
    already_done = _completed_case_ids(gen_log)
    pending_files = [p for p in patch_files if p.stem not in already_done]
    if already_done:
        logging.info(f"[{model_tag}] resuming: {len(already_done)}/{len(patch_files)} case(s) "
                      f"already complete in {gen_log}, {len(pending_files)} remaining")
    logging.info(f"[{model_tag}] processing {len(pending_files)} case(s), run_id={run_id}")

    for patch_file in pending_files:
        try:
            gen_records, sample_records = evaluate_case(
                autogen, patch_file, recorder, run_id, model_tag, host, config
            )
        except Exception as e:
            logging.error(f"[{patch_file.stem}] unexpected error: {e}", exc_info=True)
            continue
        append_jsonl(gen_records, gen_log)
        append_jsonl(sample_records, sample_log)

    logging.info(f"[{model_tag}] done -> {gen_log}")


def preflight_auth(hosts) -> None:
    """Fail fast if the GPT-Lab key is rejected. Found in the Step 2 real-model smoke test: with a bad key every
    model call failed instantly, the run recorded blank failures for every case, and Autogrep's own cache marked
    them all 'processed' so a re-run would silently skip them."""
    import requests
    from gptlab_config import host_base_url, get_api_key
    key = get_api_key()
    for host in sorted(set(hosts)):
        try:
            r = requests.get(f"{host_base_url(host)}/models", headers={"Authorization": f"Bearer {key}"}, timeout=30)
        except requests.RequestException as e:
            sys.exit(f"Preflight FAILED: cannot reach {host}: {e}")
        if r.status_code != 200:
            sys.exit(f"Preflight FAILED on {host}: HTTP {r.status_code} - {r.text[:120]}. "
                     f"Nothing was run. Check GPTLAB_API_KEY (no quotes/spaces, not expired).")
        logging.info(f"Preflight OK on {host} ({len(r.json().get('data', []))} models visible)")


def main():
    parser = argparse.ArgumentParser(
        description="Orchestrator: run GPT-Lab models over either a directory of raw "
                     ".patch cases (Phase 1 smoke-test flow) or a curated benchmark/cases/ "
                     "case set (Phase 2 pilot onward, real CVE/CWE/function data + full "
                     "Section 9 six-sample bundle evaluation)."
    )
    parser.add_argument("--models", required=True,
                         help="Comma-separated model tags, or 'primary' for all 8 verified primary models.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--patches-dir", type=Path,
                         help="Directory of raw .patch files (Phase 1 flow).")
    source.add_argument("--cases", type=str,
                         help="Curated case set: 'pilot' for the 40 pilot cases (manifest_frozen.jsonl), "
                              "'final' for the 300 final cases (manifest_frozen_final.jsonl), "
                              "'stability' for the Section 13.4 100-case frozen subset "
                              "(benchmark/stability_subset_100.json), "
                              "or a comma-separated list of case IDs (e.g. CASE-0001,CASE-0009).")
    parser.add_argument("--results-dir", type=Path, default=Path("results") / "runs")
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--prompt-variant", choices=["autogrep_default", "design_v1"],
                         default="autogrep_default")
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

    # Group models by GPU host and run each host's models on its own thread,
    # so distinct hosts execute concurrently but models sharing a host still
    # run sequentially against it (avoids piling concurrent load onto an
    # already-contended host -- e.g. GPU-farmi-004 alone serves 5 of the 8
    # primary models, so "8-way parallel" would mostly just be 5-way
    # contention on one GPU, not a real speedup). Each thread only touches
    # its own run_dir/config/AutoGrep instance -- no shared mutable state.
    host_groups = defaultdict(list)
    for m in models:
        host_groups[MODEL_HOSTS[m]].append(m)
    if len(host_groups) > 1:
        logging.info("Running across %d host(s) concurrently: %s", len(host_groups),
                      {h: ms for h, ms in host_groups.items()})

    if args.cases:
        bench_dir = Path(__file__).resolve().parent.parent / "benchmark"
        if args.cases in ("pilot", "final"):
            # list_case_ids() lists every directory under benchmark/cases/, which now holds pilot AND final
            # cases together -- 'pilot' used to correctly mean "all cases" back when only the 40 pilot cases
            # existed there, but silently drifted to mean "all 340" once the final 300 were added to the same
            # directory. Read the authoritative frozen manifest for each instead. Found+fixed in the Section
            # 30 preregistration audit follow-up, Implementation Log Section 12.27.
            manifest_name = "manifest_frozen.jsonl" if args.cases == "pilot" else "manifest_frozen_final.jsonl"
            case_ids = [json.loads(line)["case_id"] for line in (bench_dir / manifest_name).read_text().splitlines() if line.strip()]
        elif args.cases == "stability":
            case_ids = json.loads((bench_dir / "stability_subset_100.json").read_text())["case_ids"]
        else:
            case_ids = [c.strip() for c in args.cases.split(",") if c.strip()]

        def run_host_group(model_list):
            for model_tag in model_list:
                run_model_on_cases(model_tag, case_ids, args.results_dir, args.max_retries,
                                    args.temperature, args.prompt_variant)
    else:
        def run_host_group(model_list):
            for model_tag in model_list:
                run_model(model_tag, args.patches_dir, args.results_dir, args.max_retries,
                          args.temperature, args.prompt_variant)

    with ThreadPoolExecutor(max_workers=len(host_groups)) as executor:
        futures = {executor.submit(run_host_group, ms): h for h, ms in host_groups.items()}
        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception:
                logging.error(f"[{host}] host group failed", exc_info=True)


if __name__ == "__main__":
    main()
