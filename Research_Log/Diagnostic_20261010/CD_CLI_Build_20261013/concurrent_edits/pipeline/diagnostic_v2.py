"""Isolated diagnostic runner: complete artifacts, fixed denominators, no hidden feedback.

References are assistant-authored, post-inspection candidates, not expert labels.
Model raw/iterative conditions share the first response. Historical files are read
only. Every invocation creates a NEW output directory and refuses to overwrite one.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]
from config import Config
from llm_client import LLMClient
from raw_capture import RawCaptureRecorder, wrap_llm_client
from case_loader import load_case
from eligible_cases import load_manifest, eligible_supported_cases
# combined_gate/dev_probe (and dev_probe's tree_sitter grammars) are imported LOCALLY inside
# run_model_case_cd(), never at module level -- CD_Integration_Followup_Review_20261013.md
# Finding 3 found that a module-level import here made EVERY import of diagnostic_v2, including
# plain A/B runs that never call run_model_case_cd() at all, initialize the probe builder and its
# tree-sitter dependencies. Section 5 explicitly requires "Conditions A and B's code path must
# not import the probe module at all" -- confirmed directly (a fresh subprocess importing only
# diagnostic_v2 had dev_probe/tree_sitter in sys.modules before the fix); local imports close
# this without changing run_model_case()'s own body at all.

VERSION = "diagnostic-v2.1"
SEMGREP = ROOT / ".venv/bin/semgrep"
DEFAULT_SELECTION = ROOT / "benchmark/diagnostic_20261010/selection.json"
SAMPLES = [("original_vulnerable", "vulnerable_source", True),
           ("original_patched", "patched_source", False),
           ("variant_vulnerable_1", "variant_vulnerable_01", True),
           ("variant_vulnerable_2", "variant_vulnerable_02", True),
           ("variant_safe", "variant_safe_01", False),
           ("benign_lookalike", "benign_lookalike", False)]
EXT = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def semgrep_env(out):
    env = os.environ.copy()
    # semgrep's launcher delegates to pysemgrep via PATH. An absolute launcher
    # path alone can therefore execute the unrelated system-wide installation.
    env["PATH"] = str(ROOT / ".venv/bin") + os.pathsep + env.get("PATH", "")
    env.update(SEMGREP_SETTINGS_FILE=str(out / "semgrep-settings.yml"),
               SEMGREP_LOG_FILE=str(out / "semgrep.log"),
               SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    return env


def load_merged_ann():
    """Finding-1's original location ranges PLUS the 2026-10-11 v2-additive ranges (4 cases where a
    restructured variant moved the real construct into a new helper, confirmed against the actual
    source files -- see Correction_Log.md's 2026-10-11 entry). Additive only: a finding is correct
    if it falls in EITHER range, never narrower than the original annotation."""
    base = {}
    for line in (ROOT / "benchmark/variant_vulnerable_lines.jsonl").read_text().splitlines():
        a = json.loads(line)
        base[(a["case_id"], a["variant"])] = [(a["start_line"], a["end_line"])]
    v2_path = ROOT / "benchmark/variant_vulnerable_lines_v2_additions.jsonl"
    if v2_path.exists():
        for line in v2_path.read_text().splitlines():
            if not line.strip():
                continue
            a = json.loads(line)
            key = (a["case_id"], a["variant"])
            base.setdefault(key, []).append((a["start_line"], a["end_line"]))
    return base


def resolve_target_path(cid, stem, language):
    """Most cases: the frozen benchmark file directly. The one confirmed exception (CASE-0298,
    upstream file is .tsx but the frozen bundle stores .ts, a genuine Semgrep target-parse bug --
    see Correction_Log.md's 2026-10-11 entry) is staged as a byte-identical .tsx copy in a stable,
    run-independent location, never touching benchmark/cases/ itself. Checks the dataset-wide
    condition (upstream changed_file ends .tsx, stored sample ends .ts) rather than hardcoding the
    one case id, in case a future case addition hits the same gap.

    Every staged file's bytes are verified against the frozen source on EVERY call, not just at
    first creation -- an independent review (2026-10-12) found the prior version trusted an
    existing stage_dir unconditionally, so a stale or partially-written directory (e.g. from an
    interrupted prior run) would be silently reused without any check. A mismatch (or a missing
    file within an existing dir) is repaired in place -- never silently served wrong bytes, never
    left half-written."""
    case_dir = ROOT / "benchmark/cases" / cid
    default_path = case_dir / f"{stem}.{EXT[language]}"
    if language != "typescript":
        return default_path
    meta = json.loads((case_dir / "metadata.json").read_text())
    if not meta.get("changed_file", "").endswith(".tsx") or default_path.suffix == ".tsx":
        return default_path
    # No per-process cache guard here, deliberately: a follow-up review (2026-10-12) found the
    # previous version's `if cid not in _TSX_STAGE_CACHE` guard meant bytes were only ever verified
    # on the FIRST call per case within a process -- directly contradicting the "verified on EVERY
    # call" claim in this docstring at the time. Every call now actually re-checks; the cost is
    # negligible (reading 6 small files) next to the Semgrep scan that follows it.
    stage_dir = ROOT / "results" / "_diagnostic_tsx_stage" / cid
    stage_dir.mkdir(parents=True, exist_ok=True)
    for _, s, _ in SAMPLES:
        src = case_dir / f"{s}.ts"
        dst = stage_dir / f"{s}.tsx"
        src_bytes = src.read_bytes()
        if not dst.exists() or dst.read_bytes() != src_bytes:
            dst.write_bytes(src_bytes)
    return stage_dir / f"{stem}.tsx"


def scan(rule_path, cid, manifest, ann, out, *, hidden):
    out.mkdir(parents=True, exist_ok=False)
    language = manifest[cid]["language"]
    specs = SAMPLES if hidden else SAMPLES[:2]
    targets = [(kind, resolve_target_path(cid, stem, language), positive)
               for kind, stem, positive in specs]
    missing = [str(p) for _, p, _ in targets if not p.is_file()]
    if missing:
        result = {"scan_ok": False, "errors": ["Missing bundle files: " + repr(missing)], "samples": []}
        save(out / "evaluation.json", result)
        return result
    command = [str(SEMGREP), "--config", str(rule_path), "--json", "--metrics=off",
               "--disable-version-check", "--no-git-ignore", "--jobs=1", *[str(p) for _, p, _ in targets]]
    start = time.monotonic()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, env=semgrep_env(out), timeout=120)
        raw_stdout, raw_stderr, returncode = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        raw_stdout = exc.stdout or b""
        raw_stderr = exc.stderr or b""
        raw_stdout = raw_stdout.decode(errors="replace") if isinstance(raw_stdout, bytes) else raw_stdout
        raw_stderr = raw_stderr.decode(errors="replace") if isinstance(raw_stderr, bytes) else raw_stderr
        returncode = -1
    elapsed = time.monotonic() - start
    (out / "stdout.json").write_text(raw_stdout)
    (out / "stderr.txt").write_text(raw_stderr)
    try:
        data = json.loads(raw_stdout)
    except json.JSONDecodeError:
        data = {"errors": [{"message": "Semgrep did not return JSON"}], "results": []}
    errors = data.get("errors", [])
    scanned = {str(Path(p).resolve()) for p in data.get("paths", {}).get("scanned", [])}
    all_scanned = all(str(p.resolve()) in scanned for _, p, _ in targets)
    if returncode:
        errors = [*errors, {"message": f"Semgrep exited with status {returncode}"}]
    if not all_scanned:
        errors = [*errors, {"message": "Semgrep did not scan every requested sample"}]
    ok = returncode == 0 and not errors and all_scanned
    findings = data.get("results", [])
    records = []
    for kind, path, positive in targets:
        found = [r for r in findings if Path(r["path"]).resolve() == path.resolve()]
        lines = [r["start"]["line"] for r in found]
        location = None
        if positive:
            if kind == "original_vulnerable":
                bounds_list = [manifest[cid]["vulnerable_lines"]] if manifest[cid].get("vulnerable_lines") else None
            else:
                bounds_list = ann.get((cid, kind))
            if bounds_list is None:
                ok = False
                errors = [*errors, {"message": f"Missing location annotation for {cid}/{kind}"}]
            location = bool(bounds_list and any(b[0] <= line <= b[1] for b in bounds_list for line in lines))
        outcome = ("TP" if location else "FN") if positive else ("FP" if found else "TN")
        records.append({"sample_type": kind, "label": "positive" if positive else "negative",
                        "detected": bool(found), "finding_location_correct": location,
                        "finding_lines": lines, "outcome": outcome,
                        "sample_path": str(path.relative_to(ROOT)), "sample_sha256": sha(path)})
    by_type = {r["sample_type"]: r for r in records}
    legacy_accepted = ok and by_type["original_vulnerable"]["detected"] and not by_type["original_patched"]["detected"]
    visible_correct = ok and by_type["original_vulnerable"]["outcome"] == "TP" and by_type["original_patched"]["outcome"] == "TN"
    result = {"scan_ok": ok, "returncode": returncode, "all_targets_scanned": all_scanned,
              "errors": errors, "command": command, "validation_seconds": elapsed,
              "legacy_accepted": legacy_accepted, "visible_correct": visible_correct,
              "complete_success": bool(hidden and ok and all(r["outcome"] in {"TP", "TN"} for r in records)),
              "samples": records}
    save(out / "evaluation.json", result)
    return result


def run_model_case(cid, llm, config, recorder, manifest, ann, out, acceptance_policy="legacy"):
    """All model calls and visible scans finish before ANY hidden evaluation.

    acceptance_policy, added 2026-10-12 after an independent review found the generation/repair
    loop's actual stopping decision still gated on location-blind `legacy_accepted` even after
    report()'s corrected *_corrected fields were added -- those only changed aggregate reporting,
    never the loop that decides whether a wrong-location rule gets another repair attempt. Default
    stays "legacy" (byte-identical behavior to every already-completed run, qwen3_v3 through
    qwen3_mechanism_v5 -- reproducibility preserved, not silently changed underneath them).
    "corrected" is the new, explicitly-named policy that requires visible_correct (location-aware)
    to accept, feeding back specific "right call, wrong line" feedback so the model gets a real
    chance to fix the location rather than the loop terminating on a false win."""
    patch = load_case(cid, config)
    recorder.begin_case(cid)
    attempts, error, accepted_rule = [], None, None
    for attempt in range(1, 4):
        rule = llm.generate_rule(patch, error_feedback=error)
        folder = out / cid / f"attempt_{attempt}"
        folder.mkdir(parents=True, exist_ok=False)
        evaluation = None
        if rule is not None:
            rule_path = folder / "rule.yml"
            rule_path.write_text(yaml.safe_dump({"rules": [rule]}, sort_keys=False))
            evaluation = scan(rule_path, cid, manifest, ann, folder / "visible", hidden=False)
            accept = evaluation["visible_correct"] if acceptance_policy == "corrected" else evaluation["legacy_accepted"]
            if accept:
                accepted_rule = rule_path
                error = None
            elif not evaluation["scan_ok"]:
                error = "Semgrep scan error: " + json.dumps(evaluation["errors"])
            else:
                visible = {r["sample_type"]: r for r in evaluation["samples"]}
                if (acceptance_policy == "corrected" and evaluation["legacy_accepted"]
                        and not visible["original_vulnerable"]["finding_location_correct"]):
                    error = (f"Rule detected something in the original vulnerable version, but NOT at the "
                             f"correct location (found at line(s) {visible['original_vulnerable']['finding_lines']}, "
                             f"expected within {manifest[cid]['vulnerable_lines']}). Fix the pattern to match "
                             f"the actual vulnerable construct, not an unrelated part of the file.")
                else:
                    error = ("Rule incorrectly detected vulnerability in fixed version" if visible["original_patched"]["detected"]
                             else "Rule failed to detect vulnerability in original version")
        else:
            error = llm.last_error
        item = {"attempt": attempt, "parsed": rule is not None,
                "rule_path": str(folder / "rule.yml") if rule is not None else None,
                "visible_evaluation": evaluation, "feedback": error}
        save(folder / "attempt.json", item)
        attempts.append(item)
        if accepted_rule:
            break
    # No hidden results or reference rules are accessible to the model call path.
    raw_rule = attempts[0]["rule_path"]
    raw = scan(Path(raw_rule), cid, manifest, ann, out / cid / "raw_hidden", hidden=True) if raw_rule else None
    final = scan(accepted_rule, cid, manifest, ann, out / cid / "iterative_hidden", hidden=True) if accepted_rule else None
    if accepted_rule:
        (out / cid / "final_rule.yml").write_bytes(accepted_rule.read_bytes())
    payloads = []
    for p in [recorder.raw_dir / f"{cid}.json", *sorted(recorder.retries_dir.glob(f"{cid}_attempt*.json"))]:
        if p.exists():
            payloads.append(json.loads(p.read_text()))
    def total(field):
        values = [p.get(field) for p in payloads]
        return sum(values) if values and all(v is not None for v in values) else None
    episode = {"case_id": cid, "attempts": attempts, "raw": raw, "iterative": final,
               "final_rule_path": str(out / cid / "final_rule.yml") if accepted_rule else None,
               "final_rule_sha256": sha(accepted_rule) if accepted_rule else None,
               "calls_recorded": len(payloads), "input_tokens": total("input_tokens"),
               "output_tokens": total("output_tokens"), "generation_seconds": total("generation_seconds")}
    save(out / cid / "episode.json", episode)
    return episode


def run_model_case_cd(cid, llm, config, recorder, manifest, ann, out, condition, probe_result,
                       probe_paths=None, scan_probe_fn=None, probe_provenance=None):
    """Condition C/D's episode runner -- Controlled_2x2_Protocol_Draft_20261012.md Section 4's
    combined accept/stop gate (`combined_gate.py`, offline-tested in `test_combined_gate.py`;
    reviewed in `CD_Gate_Cache_Review_20261013.md`), wired into a real generation/scan retry loop
    for the first time here. This is a SEPARATE function, not a modification of
    `run_model_case()` -- that function remains byte-for-byte untouched and is what every A/B run
    (including the already-completed 288-episode development pilot) continues to use; there is no
    shared code path for the two functions to diverge on by accident. `condition` must be "C" or
    "D" (call `run_model_case()` for A/B).

    The visible-side acceptance policy is always "corrected" (location-aware) here, matching
    Section 3's "Acceptance policy: corrected, not legacy" -- this is fixed, shared infrastructure
    across all 4 cells, not a free parameter the way it is for historical A/B reproduction.

    probe_result: the ALREADY-RESOLVED ProbeResult/ProbeIneligible for this case -- resolution
    (cache lookup or frozen-manifest validation via `probe_cache.py`) happens OUTSIDE this
    function, so this function never imports `probe_cache.py` and stays testable with a plain
    synthetic ProbeResult/ProbeIneligible, exactly like `run_model_case()`'s own tests already
    inject a fake LLM/scan rather than exercising the real ones.
    probe_paths: (vulnerable_probe_path, patched_probe_path) -- the probe's ALREADY-MATERIALIZED
    source files on disk (never written by this function). Required when `probe_result` is an
    eligible ProbeResult; ignored otherwise. Firewalling (never under benchmark/cases/) is the
    caller's responsibility, matching `dev_probe.py`'s own existing invariant -- "forbid hidden
    evaluation files as generation/probe inputs" holds here by construction, since this function
    never reads anything from `benchmark/cases/` beyond what `scan()` itself already reads for
    the visible pair.
    scan_probe_fn: a `probe_coverage_check.scan_probe()`-shaped callable
    `(rule_path, vulnerable_probe_path, patched_probe_path, out_dir) -> dict`, injected so tests
    never need real Semgrep (mirrors how `scan` itself is already monkeypatched in existing
    `test_diagnostic_regressions.py` tests) -- defaults to the real
    `probe_coverage_check.scan_probe` if not supplied.

    Hidden evaluation happens only after the ENTIRE attempt loop finishes, exactly like
    `run_model_case()` -- no hidden result or reference rule is ever accessible to the model call
    or probe-feedback path. The probe scan for an attempt runs ONLY after that attempt's visible
    check has already passed (never before, never when visible already failed), matching the
    protocol's "fed into the REPAIR step only, after a rule already passes the visible pair" and
    `combined_gate.combined_decision`'s own short-circuit -- this is also why resource accounting
    (via `AttemptEvent`/`summarize_episode_resources`) never overcounts a probe scan for an
    attempt that never reached it.

    CORRECTED 2026-10-13 (CD_Integration_Followup_Review_20261013.md, all four issues reproduced
    directly before fixing): (1) `probe_result` must now be a genuine `ProbeResult`/`ProbeIneligible`
    instance -- `None` or any other unresolved value raises before any model call, instead of
    silently being treated as a reviewed ineligibility decision (reproduced: `probe_result=None`
    previously still generated a rule, accepted on visible alone, and reported
    `probe_fallback_used=True`, indistinguishable from a real reviewed ineligibility). (2) when
    eligible, the files actually at `probe_paths` are hashed and compared against
    `probe_result.vulnerable_probe`/`.patched_probe` ONCE, before any generation call -- a mismatch
    raises `ProbeMaterializationError` rather than silently scanning whatever bytes happen to be on
    disk (reproduced: a probe file edited in place after materialization, independent of the
    validated `probe_result` object, still reached the mocked scanner and was accepted). (3) all
    probe-specific imports (`dev_probe`, `combined_gate`) are LOCAL to this function, not
    module-level -- see the import block near the top of this file. (4) a probe scan timeout
    (`subprocess.TimeoutExpired`, the exception `probe_coverage_check.scan_probe`'s real
    `subprocess.run(..., timeout=120)` raises) is now caught and converted into an ordinary
    `scan_ok=False` probe-scan-error result, flowing through the EXISTING error-handling path
    (recorded, retried within budget) instead of propagating uncaught and skipping
    `attempt.json`/`episode.json` entirely for that attempt (reproduced directly: an injected
    `TimeoutExpired` previously exited the function after one generation call with neither file
    written)."""
    from dev_probe import ProbeResult, ProbeIneligible
    from combined_gate import combined_decision, evaluate_probe_pair, AttemptEvent, summarize_episode_resources

    if condition not in ("C", "D"):
        raise ValueError(f"run_model_case_cd is for conditions C/D only, got {condition!r}")
    if not isinstance(probe_result, (ProbeResult, ProbeIneligible)):
        raise ValueError(f"probe_result must be a resolved ProbeResult or ProbeIneligible, got "
                         f"{type(probe_result).__name__} -- an unresolved/unknown probe state must "
                         f"never be treated as a reviewed ineligibility decision")
    if probe_result.case_id != cid or probe_result.language != manifest[cid]["language"]:
        raise ValueError(f"probe_result identity mismatch: resolved for case_id={probe_result.case_id!r}/"
                         f"language={probe_result.language!r}, but this episode is {cid!r}/"
                         f"{manifest[cid]['language']!r}")
    if scan_probe_fn is None:
        from probe_coverage_check import scan_probe as scan_probe_fn

    probe_eligible = isinstance(probe_result, ProbeResult)
    probe_ineligible_reason = probe_result.reason if isinstance(probe_result, ProbeIneligible) else None
    verified_probe_hashes = None
    snapshot_paths = None
    expected_probe_bytes = None
    if probe_eligible:
        if probe_paths is None:
            raise ValueError("probe_paths is required when probe_result is an eligible ProbeResult")
        vuln_probe_path, patched_probe_path = probe_paths
        # CORRECTED 2026-10-13 (CD_Materialization_Followup_Review_20261013.md): compare RAW BYTES,
        # never `read_text()` -- `read_text()` universal-newline-translates CRLF to LF, so a file
        # actually written with CRLF bytes passed the old text comparison while its real on-disk
        # bytes (what Semgrep actually scans) hashed differently from what got recorded. Reproduced
        # directly: a CRLF-written file's `read_text()` matched the LF-encoded expected string, but
        # `sha256(actual_bytes)` != `sha256(read_text().encode())`.
        expected_vuln_bytes = probe_result.vulnerable_probe.encode()
        expected_patched_bytes = probe_result.patched_probe.encode()
        actual_vuln_bytes = Path(vuln_probe_path).read_bytes()
        actual_patched_bytes = Path(patched_probe_path).read_bytes()
        if actual_vuln_bytes != expected_vuln_bytes or actual_patched_bytes != expected_patched_bytes:
            raise ProbeMaterializationError(
                f"{cid}: materialized probe file(s) at {probe_paths} do not match the validated "
                f"probe_result's text -- refusing to scan unverified/tampered probe input")
        expected_probe_bytes = (expected_vuln_bytes, expected_patched_bytes)
        verified_probe_hashes = {"vulnerable_probe_sha256": hashlib.sha256(expected_vuln_bytes).hexdigest(),
                                  "patched_probe_sha256": hashlib.sha256(expected_patched_bytes).hexdigest()}
        # CORRECTED 2026-10-13 (same review): a single check before the retry loop only proves the
        # files matched AT THAT MOMENT -- reproduced directly, both "changed during generation"
        # (before the first scan) and "changed between attempts" (after the first probe scan, before
        # the second) let different bytes reach the scanner while `verified_probe_hashes` kept
        # reporting the original, now-stale hash. Copying the verified bytes into a snapshot this
        # function exclusively owns (a fresh subdirectory of `out`, which `main()` itself already
        # creates with `exist_ok=False`) and scanning ONLY that copy closes the gap for anything
        # written by code OUTSIDE this function after this point; each attempt additionally
        # re-verifies the snapshot's own bytes immediately before scanning it (defensive, per the
        # review's explicit request), treating any detected drift as an ordinary probe-scan error
        # (the same established, tested path a timeout already uses) rather than inventing a new
        # fallback or silently granting a fresh budget.
        # CORRECTED 2026-10-13 (CD_Snapshot_Review_20261013.md Finding 1): both destinations were
        # previously built from `Path(input_path).name` in the SAME directory -- two valid,
        # independently-supplied inputs sharing a basename (e.g. `input_vulnerable/function.py`
        # and `input_patched/function.py`, a real possibility since nothing requires distinct
        # names across directories) silently overwrote one snapshot file with the other's bytes.
        # Reproduced directly: the snapshot ended up containing only ONE file, holding the
        # PATCHED content, and every attempt failed its own integrity re-check against the
        # (overwritten) vulnerable snapshot. Role-specific subdirectories make a basename
        # collision between the two roles structurally impossible, regardless of caller-supplied
        # names.
        snapshot_dir = out / cid / "_probe_snapshot"
        snapshot_vuln_dir = snapshot_dir / "vulnerable"
        snapshot_patched_dir = snapshot_dir / "patched"
        snapshot_vuln_dir.mkdir(parents=True, exist_ok=False)
        snapshot_patched_dir.mkdir(parents=True, exist_ok=False)
        snapshot_vuln_path = snapshot_vuln_dir / Path(vuln_probe_path).name
        snapshot_patched_path = snapshot_patched_dir / Path(patched_probe_path).name
        snapshot_vuln_path.write_bytes(expected_vuln_bytes)
        snapshot_patched_path.write_bytes(expected_patched_bytes)
        snapshot_paths = (snapshot_vuln_path, snapshot_patched_path)

    patch = load_case(cid, config)
    recorder.begin_case(cid)
    attempts, error, accepted_rule = [], None, None
    events = []
    for attempt in range(1, 4):
        rule = llm.generate_rule(patch, error_feedback=error)
        folder = out / cid / f"attempt_{attempt}"
        folder.mkdir(parents=True, exist_ok=False)
        evaluation = None
        probe_scan_result = None
        decision = None
        if rule is not None:
            rule_path = folder / "rule.yml"
            rule_path.write_text(yaml.safe_dump({"rules": [rule]}, sort_keys=False))
            evaluation = scan(rule_path, cid, manifest, ann, folder / "visible", hidden=False)
            visible_correct = evaluation["visible_correct"]

            probe_checks = None
            scanner_invocations = 0
            if probe_eligible and visible_correct:
                snapshot_vuln_path, snapshot_patched_path = snapshot_paths
                expected_vuln_bytes, expected_patched_bytes = expected_probe_bytes
                drift = (snapshot_vuln_path.read_bytes() != expected_vuln_bytes
                         or snapshot_patched_path.read_bytes() != expected_patched_bytes)
                if drift:
                    # Structurally should not happen (this function owns the snapshot exclusively),
                    # but verified before every use anyway, per the review's explicit request --
                    # treated as an ordinary probe-scan error, never a fresh budget or a fallback.
                    # CORRECTED 2026-10-13 (CD_Snapshot_Review_20261013.md Finding 2):
                    # `scanner_invocations` was previously set to 1 unconditionally after this
                    # if/else, even on THIS branch where `scan_probe_fn` is deliberately never
                    # called -- reproduced directly: zero actual scanner calls were made, but
                    # `resource_accounting.probe_scans` reported 3. The integrity guard skipping
                    # the scan must not be counted as a scan; it stays 0 on this branch.
                    probe_scan_result = {"scan_ok": False, "error": "probe snapshot integrity check failed before scan"}
                else:
                    try:
                        probe_scan_result = scan_probe_fn(rule_path, snapshot_vuln_path, snapshot_patched_path, folder / "probe")
                    except subprocess.TimeoutExpired as exc:
                        probe_scan_result = {"scan_ok": False, "error": f"probe scan timed out: {exc}"}
                    scanner_invocations = 1  # the scan call was actually entered, including a timeout
                probe_checks = evaluate_probe_pair(probe_scan_result, probe_scan_result)

            decision = combined_decision(condition=condition, attempt=attempt, max_attempts=3,
                                          visible_correct=visible_correct,
                                          probe_eligible=probe_eligible, probe_checks=probe_checks)
            events.append(AttemptEvent(attempt=attempt, generation_ok=True, decision=decision,
                                        probe_scanner_invocations=scanner_invocations))

            if decision.accept:
                accepted_rule = rule_path
                error = None
            elif not evaluation["scan_ok"]:
                error = "Semgrep scan error: " + json.dumps(evaluation["errors"])
            elif not visible_correct:
                visible = {r["sample_type"]: r for r in evaluation["samples"]}
                if (evaluation["legacy_accepted"] and not visible["original_vulnerable"]["finding_location_correct"]):
                    error = (f"Rule detected something in the original vulnerable version, but NOT at the "
                             f"correct location (found at line(s) {visible['original_vulnerable']['finding_lines']}, "
                             f"expected within {manifest[cid]['vulnerable_lines']}). Fix the pattern to match "
                             f"the actual vulnerable construct, not an unrelated part of the file.")
                else:
                    error = ("Rule incorrectly detected vulnerability in fixed version" if visible["original_patched"]["detected"]
                             else "Rule failed to detect vulnerability in original version")
            else:
                # Visible passed but the probe check(s) failed -- probe-specific repair feedback.
                error = ("Rule correctly handled the original vulnerable/patched pair, but failed an "
                         f"additional development-time test case ({decision.reason}). Your rule must also "
                         "correctly handle this additional test case.")
        else:
            error = llm.last_error
            events.append(AttemptEvent(attempt=attempt, generation_ok=False))
        item = {"attempt": attempt, "parsed": rule is not None,
                "rule_path": str(folder / "rule.yml") if rule is not None else None,
                "visible_evaluation": evaluation, "probe_evaluation": probe_scan_result,
                "gate_decision": asdict(decision) if decision is not None else None, "feedback": error}
        save(folder / "attempt.json", item)
        attempts.append(item)
        if accepted_rule:
            break
    # No hidden results or reference rules are accessible to the model call path.
    raw_rule = attempts[0]["rule_path"]
    raw = scan(Path(raw_rule), cid, manifest, ann, out / cid / "raw_hidden", hidden=True) if raw_rule else None
    final = scan(accepted_rule, cid, manifest, ann, out / cid / "iterative_hidden", hidden=True) if accepted_rule else None
    if accepted_rule:
        (out / cid / "final_rule.yml").write_bytes(accepted_rule.read_bytes())
    payloads = []
    for p in [recorder.raw_dir / f"{cid}.json", *sorted(recorder.retries_dir.glob(f"{cid}_attempt*.json"))]:
        if p.exists():
            payloads.append(json.loads(p.read_text()))
    def total(field):
        values = [p.get(field) for p in payloads]
        return sum(values) if values and all(v is not None for v in values) else None
    resources = summarize_episode_resources(events)
    episode = {"case_id": cid, "condition": condition, "attempts": attempts, "raw": raw, "iterative": final,
               "final_rule_path": str(out / cid / "final_rule.yml") if accepted_rule else None,
               "final_rule_sha256": sha(accepted_rule) if accepted_rule else None,
               "probe_eligible": probe_eligible, "probe_ineligible_reason": probe_ineligible_reason,
               "verified_probe_hashes": verified_probe_hashes,
               "probe_provenance": probe_provenance,
               "probe_snapshot_paths": [str(p.relative_to(out)) for p in snapshot_paths] if snapshot_paths else None,
               "probe_fallback_used": bool(events and events[-1].generation_ok and events[-1].decision.is_fallback),
               "resource_accounting": resources,
               "calls_recorded": len(payloads), "input_tokens": total("input_tokens"),
               "output_tokens": total("output_tokens"), "generation_seconds": total("generation_seconds")}
    save(out / cid / "episode.json", episode)
    return episode


class ProbeMaterializationError(Exception):
    """Raised by run_model_case_cd() when the files actually at `probe_paths` do not match the
    validated `probe_result`'s text -- the approved-source boundary is enforced here, at the
    runner, rather than left to a docstring's prohibition on hidden/arbitrary input paths."""


def run_cd_case_from_manifest(cid, llm, config, recorder, manifest, ann, out, condition,
                               probe_manifest_entries, vulnerable_function=None, patched_function=None,
                               probe_cache_dir=None, scan_probe_fn=None):
    """The complete C/D per-case path: resolve this case's probe against the frozen manifest
    (`probe_cache.load_probe_for_experiment` -- raises if the case is missing from the manifest or
    its inputs/builder/parser/language no longer match what was reviewed), materialize an eligible
    probe's validated text to real files (the ONLY place C/D's probe inputs come from -- never
    `benchmark/cases/`, never a hidden variant file, matching `dev_probe.py`'s own firewalling
    invariant), then run the episode via `run_model_case_cd()` (which independently re-verifies
    these bytes and copies them into its own exclusively-owned per-episode snapshot before
    scanning). Factored out of `main()`'s per-case loop so this complete path -- manifest
    resolution through episode completion -- is directly testable offline with a mocked
    `llm`/`scan_probe_fn`, not just `run_model_case_cd()` in isolation (already covered by
    `test_run_model_case_cd.py`) or the manifest loader alone (already covered by
    `test_combined_gate.py`).

    vulnerable_function/patched_function: the case's probe-construction INPUT text. Supplied by
    the caller (defaults to reading `benchmark/model_context/{cid}.json`, matching every other
    script in this project that reads that file -- `probe_binding_audit_report.py`,
    `build_cd_probe_manifest.py`) rather than hardcoded here, so this function stays testable
    against a purely synthetic manifest/case that has no real `benchmark/model_context/` entry at
    all -- it must never require real on-disk case data just to exercise the gate/cache logic.

    probe_cache_dir defaults to `out / "_probe_cache"`; probe source text is materialized under
    `out / "_probe_materialized" / cid /`. Returns the episode dict, with `probe_cache_status`
    (one of "hit"/"miss_built"/"mismatch_rebuilt") added for provenance."""
    from probe_cache import load_probe_for_experiment
    from dev_probe import ProbeResult as _ProbeResult

    language = manifest[cid]["language"]
    if vulnerable_function is None or patched_function is None:
        context = json.loads((ROOT / f"benchmark/model_context/{cid}.json").read_text())
        vulnerable_function = context["vulnerable_function"]
        patched_function = context["patched_function"]
    probe_result, cache_status = load_probe_for_experiment(
        cid, language, vulnerable_function, patched_function,
        cache_dir=probe_cache_dir if probe_cache_dir is not None else out / "_probe_cache",
        manifest=probe_manifest_entries)
    probe_paths = None
    if isinstance(probe_result, _ProbeResult):
        materialized_dir = out / "_probe_materialized" / cid
        materialized_dir.mkdir(parents=True, exist_ok=False)
        ext = EXT[language]
        vuln_probe_path = materialized_dir / f"vulnerable_probe.{ext}"
        patched_probe_path = materialized_dir / f"patched_probe.{ext}"
        vuln_probe_path.write_bytes(probe_result.vulnerable_probe.encode())
        patched_probe_path.write_bytes(probe_result.patched_probe.encode())
        probe_paths = (vuln_probe_path, patched_probe_path)
    episode = run_model_case_cd(cid, llm, config, recorder, manifest, ann, out,
                                 condition=condition, probe_result=probe_result,
                                 probe_paths=probe_paths, scan_probe_fn=scan_probe_fn)
    episode["probe_cache_status"] = cache_status
    return episode


def report(episodes, requested, mode):
    """Reports BOTH gates side by side, per Research_Direction_20261011.md item 1 ("preserve
    historical scores and record a separate corrected protocol" / "apply the same protocol to every
    newly compared condition") -- legacy_accepted (location-blind: any finding on vulnerable, none
    on patched) is kept exactly as it always was; *_corrected fields use visible_correct (location-
    aware: the finding on vulnerable must also be at the right line) as the gate instead. Scan
    errors are counted once, separately, never folded into either gate's denominator."""
    conditions = ("reference",) if mode == "references" else ("raw", "iterative")
    result = {"requested_cases": len(requested), "completed_cases": len(episodes), "conditions": {}}
    for condition in conditions:
        evaluations = [e.get(condition) for e in episodes]
        def gated(predicate):
            return sum(2 for e in evaluations if e and predicate(e) and e["scan_ok"])
        def hidden_tp(predicate):
            return sum(sum(s["outcome"] == "TP" for s in e["samples"] if s["sample_type"].startswith("variant_vulnerable"))
                       for e in evaluations if e and predicate(e) and e["scan_ok"])
        def hidden_fp(predicate):
            return sum(sum(s["outcome"] == "FP" for s in e["samples"] if s["sample_type"] in {"variant_safe", "benign_lookalike"})
                       for e in evaluations if e and predicate(e) and e["scan_ok"])
        legacy = lambda e: e["legacy_accepted"]
        corrected = lambda e: e["visible_correct"]
        result["conditions"][condition] = {
            "evaluated": sum(e is not None for e in evaluations),
            "scan_errors": sum(bool(e and not e["scan_ok"]) for e in evaluations),
            "accepted": sum(bool(e and legacy(e)) for e in evaluations),
            "visible_correct": sum(bool(e and corrected(e)) for e in evaluations),
            "complete_success": sum(bool(e and e["complete_success"]) for e in evaluations),
            "expected_hidden_positives": 2 * len(requested),
            "hidden_positive_hits_all_requested": hidden_tp(legacy),
            "hidden_false_positives_accepted": hidden_fp(legacy),
            "accepted_hidden_negatives_evaluated": gated(legacy),
            "hidden_positive_hits_all_requested_corrected": hidden_tp(corrected),
            "hidden_false_positives_accepted_corrected": hidden_fp(corrected),
            "accepted_hidden_negatives_evaluated_corrected": gated(corrected)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["preflight", "references", "model"])
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference-version", default="v1")
    parser.add_argument("--model", default="qwen3-coder:30b")
    parser.add_argument("--prompt-variant", default="autogrep_default",
                         choices=["autogrep_default", "design_v1", "diagnostic_mechanism_v1",
                                  "diagnostic_mechanism_v2", "diagnostic_mechanism_v3", "diagnostic_mechanism_v4"],
                         help="autogrep_default (default) reproduces the historical qwen3_v3 condition "
                              "exactly. diagnostic_mechanism_v1 (2026-10-11) is the revised-workflow condition "
                              "as actually run for qwen3_mechanism_v1/v2 -- kept exactly as-is for "
                              "reproducibility, including its inherited-from-upstream invalid-YAML example "
                              "indentation. diagnostic_mechanism_v2 (2026-10-11, same day) is identical except "
                              "it uses EXAMPLE_RULES_V2 (valid YAML) -- as actually run for qwen3_mechanism_v3. "
                              "diagnostic_mechanism_v3 (2026-10-11, same day) is identical to v2 except it uses "
                              "EXAMPLE_RULES_V3 (one rule per language instead of two, plus a new typescript "
                              "entry) and adds explicit colon-quoting + exactly-one-rule guidance -- as actually "
                              "run for qwen3_mechanism_v4, which reached 6/24, parity with autogrep_default. "
                              "diagnostic_mechanism_v4 (2026-10-11) is identical to v3 plus one more guidance "
                              "addition targeting a recurring pattern-either+pattern-not composition gotcha "
                              "(CASE-0276 in qwen3_mechanism_v4) -- not yet run live. See "
                              "autogrep/llm_client.py's _build_prompt_diagnostic_mechanism_v1 for what each "
                              "changes and why.")
    parser.add_argument("--acceptance-policy", default=None, choices=["legacy", "corrected"],
                         help="legacy (default) reproduces every already-completed run's exact "
                              "behavior: accepts on any finding on vulnerable + none on patched, "
                              "location-blind. corrected (2026-10-12, not yet run live) requires "
                              "visible_correct (the finding must also be at the right line) to "
                              "accept, and gives specific wrong-location repair feedback instead of "
                              "silently taking a false win -- see run_model_case()'s docstring.")
    parser.add_argument("--construction-mode", default=None,
                         choices=["original_prompt", "typed_json"],
                         help="Controlled_2x2_Protocol_Draft_20261012.md condition A vs B (or C vs "
                              "D when --use-probes is set). original_prompt (default) is every "
                              "historical run's output contract unchanged -- --prompt-variant still "
                              "selects which free-form-YAML prompt. typed_json (not yet run live) "
                              "is condition B/D: the model emits a single JSON object matching "
                              "pipeline/typed_rule.py's TypedRule fields; --prompt-variant is "
                              "ignored in this mode. See autogrep/llm_client.py's "
                              "_generate_rule_typed_json().")
    parser.add_argument("--use-probes", action="store_true",
                         help="Controlled_2x2_Protocol_Draft_20261012.md condition C/D (not yet run "
                              "live): adds development-probe feedback via "
                              "diagnostic_v2.run_model_case_cd() and combined_gate.py's combined "
                              "accept/stop gate, instead of run_model_case()'s visible-only gate. "
                              "Condition label is derived from --construction-mode: original_prompt "
                              "-> C, typed_json -> D. Acceptance policy is always 'corrected' in "
                              "this mode (--acceptance-policy is accepted but ignored and recorded "
                              "as such, matching Section 3's fixed, shared infrastructure). "
                              "Requires --probe-manifest; only the real 24-case development "
                              "selection's cases are validated against it (a different --selection "
                              "with --use-probes will fail at the per-case manifest lookup, by "
                              "design -- see probe_cache.load_probe_for_experiment()).")
    parser.add_argument("--probe-manifest", type=Path,
                         default=ROOT / "Research_Log/Diagnostic_20261010/CD_Probe_Manifest_v1_20261013.json",
                         help="Frozen probe manifest (pipeline/build_cd_probe_manifest.py's output) "
                              "to validate every C/D case's probe against. Ignored unless --use-probes.")
    parser.add_argument("--condition", choices=["C", "D"],
                        help="Explicit development probe condition: C=original prompt, D=typed JSON; both corrected acceptance.")
    parser.add_argument("--probe-manifest", type=Path,
                        help="Reviewed development probe manifest (C/D only; defaults to dev_probe_manifest_v1.json).")
    args = parser.parse_args()
    cd_inputs = None
    if args.condition:
        if args.mode == "references":
            parser.error("--condition C/D is only valid for preflight or model mode")
        construction = "original_prompt" if args.condition == "C" else "typed_json"
        if args.construction_mode not in (None, construction):
            parser.error(f"Condition {args.condition} requires --construction-mode {construction}")
        if args.acceptance_policy not in (None, "corrected"):
            parser.error("Conditions C/D require corrected acceptance")
        if args.prompt_variant != "autogrep_default":
            parser.error("Conditions C/D use the frozen autogrep_default prompt/examples")
        args.construction_mode, args.acceptance_policy = construction, "corrected"
        from cd_experiment import DEFAULT_MANIFEST, validate_frozen_manifest, prepare_probes, summarize_cd
        args.probe_manifest = args.probe_manifest or DEFAULT_MANIFEST
        cd_inputs = validate_frozen_manifest(args.probe_manifest, args.selection)
    else:
        if args.probe_manifest:
            parser.error("--probe-manifest requires --condition C or D")
        # Preserve historical A/B defaults without importing any probe modules.
        args.construction_mode = args.construction_mode or "original_prompt"
        args.acceptance_policy = args.acceptance_policy or "legacy"
    if args.use_probes and args.mode == "model" and not args.probe_manifest.exists():
        parser.error(f"--probe-manifest {args.probe_manifest} does not exist -- run "
                     f"pipeline/build_cd_probe_manifest.py first, or pass an existing one")
    out = args.output.resolve()
    # Permit only the dedicated namespace, never a historical run directory.
    permitted = ROOT / "results/diagnostic_20261010"
    if permitted not in out.parents:
        parser.error(f"Output must be a fresh directory beneath {permitted}")
    if args.condition and out.exists():
        parser.error("C/D output already exists; refusing to restart an episode with a fresh budget")
    # Credential checks happen BEFORE the output directory is created, so a missing or rejected
    # key never consumes a run name (out.mkdir below is exist_ok=False -- a retry after a bad-key
    # failure must be able to reuse the same --output path, not need a fresh one every time). The
    # diagnostic_audit.py command log already captures this failure's evidence (exit code, stderr),
    # so nothing is lost by not also writing a blocked.json inside a namespace we never created.
    resolved_host = None
    if args.mode == "model":
        from gptlab_config import MODEL_HOSTS, host_base_url, get_key_for_host
        import requests
        # CORRECTED 2026-10-12 after an independent review found this previously checked
        # GPTLAB_API_KEY unconditionally, BEFORE resolving which host the selected model actually
        # needs -- an environment with only OPENAI_API_KEY set (e.g. to run gpt-4o, the protocol's
        # contrasting model) was rejected before get_key_for_host() ever got a chance to resolve
        # the correct, host-specific credential. Resolve the host FIRST, then let
        # get_key_for_host() raise its own specific, correctly-targeted error.
        resolved_host = MODEL_HOSTS[args.model]
        try:
            key = get_key_for_host(resolved_host)
        except RuntimeError as e:
            raise SystemExit(f"{e} No model calls made; no output directory created.")
        r = requests.get(f"{host_base_url(resolved_host)}/models", headers={"Authorization": f"Bearer {key}"}, timeout=30)
        if r.status_code != 200:
            key_name = "OPENAI_API_KEY" if resolved_host == "OPENAI" else "GPTLAB_API_KEY"
            raise SystemExit(f"Preflight FAILED on {resolved_host}: HTTP {r.status_code} - {r.text[:200]}. "
                              f"Nothing was run, no output directory created. "
                              f"Check {key_name} (no quotes/spaces, not expired).")
    out.mkdir(parents=True, exist_ok=False)
    selection = json.loads(args.selection.read_text())
    ids = selection["case_ids"]
    manifest = load_manifest()
    if not set(ids) <= eligible_supported_cases(manifest) or len(ids) != len(set(ids)):
        raise RuntimeError("Selection contains ineligible or duplicate cases")
    ann = load_merged_ann()
    version = subprocess.run([str(SEMGREP), "--version"], capture_output=True, text=True, env=semgrep_env(out))
    if version.returncode or version.stdout.strip() != "1.177.0":
        save(out / "preflight_error.json", {"error": "Pinned Semgrep 1.177.0 required", "stdout": version.stdout, "stderr": version.stderr})
        raise SystemExit("Pinned Semgrep preflight failed; see preflight_error.json")
    code = [Path(__file__), ROOT / "pipeline/raw_capture.py", ROOT / "autogrep/llm_client.py",
            ROOT / "autogrep/config.py", ROOT / "pipeline/case_loader.py", ROOT / "pipeline/gptlab_config.py",
            ROOT / "autogrep/patch_processor.py", ROOT / "pipeline/eligible_cases.py",
            ROOT / "pipeline/typed_rule.py"]
    if args.use_probes:
        code += [ROOT / "pipeline/combined_gate.py", ROOT / "pipeline/probe_cache.py",
                 ROOT / "pipeline/dev_probe.py", ROOT / "pipeline/probe_coverage_check.py"]
    prepared = None
    if args.condition:
        frozen, contexts, manifest_bytes = cd_inputs
        if any(manifest[cid]["language"] != frozen["entries"][cid]["language"] for cid in ids):
            raise RuntimeError("Benchmark language identity differs from reviewed probe manifest")
        with (out / "probe_manifest.json").open("xb") as handle:
            handle.write(manifest_bytes)
        prepared = prepare_probes(frozen, contexts, manifest_bytes, out)
        code += [ROOT / "pipeline" / name for name in
                 ("cd_experiment.py", "probe_cache.py", "dev_probe.py", "combined_gate.py", "probe_coverage_check.py")]
    # Annotation DATA files, tracked separately from code: a code hash alone wouldn't catch someone
    # editing the location ranges themselves (e.g. the v2-additions file) without touching any .py
    # file -- an independent review (2026-10-12) noted this gap.
    annotation_files = [ROOT / "benchmark/variant_vulnerable_lines.jsonl"]
    v2_ann_path = ROOT / "benchmark/variant_vulnerable_lines_v2_additions.jsonl"
    if v2_ann_path.exists():
        annotation_files.append(v2_ann_path)
    env = {"version": VERSION, "created_utc": datetime.now(timezone.utc).isoformat(), "mode": args.mode,
           "model": args.model if args.mode == "model" else None, "temperature": 0, "max_tokens": 2048,
           "max_attempts": 3, "schema_policy": "semgrep_search_taint_v2",
           # prompt_policy must check construction_mode FIRST -- confirmed by an independent
           # review (2026-10-12) that with construction_mode=="typed_json" and the default
           # (unset) --prompt-variant, this previously recorded "historical_autogrep_default_
           # unchanged" even though generation actually used _build_prompt_typed_json(), which
           # ignores prompt_variant entirely. requested_prompt_variant is kept separately so a
           # --prompt-variant passed alongside typed_json (which has no effect) is still visible
           # as "requested but ignored," never silently dropped.
           "prompt_policy": ("CONDITION_B_TYPED_JSON" if args.construction_mode == "typed_json"
                              else "historical_autogrep_default_unchanged" if args.prompt_variant == "autogrep_default"
                              else f"EXPLICIT_REVISED_CONDITION:{args.prompt_variant}"),
           "requested_prompt_variant": args.prompt_variant,
           "prompt_variant_ignored": args.construction_mode == "typed_json",
           "prompt_variant": args.prompt_variant,
           # C/D's acceptance policy is always "corrected" (Section 3: fixed, shared
           # infrastructure across all 4 cells, not a free parameter) -- --acceptance-policy is
           # recorded as requested-but-ignored in that mode, the same "requested vs. effective"
           # pattern already used above for prompt_variant under typed_json.
           "acceptance_policy": "corrected" if args.use_probes else args.acceptance_policy,
           "requested_acceptance_policy": args.acceptance_policy,
           "acceptance_policy_ignored": args.use_probes,
           "construction_mode": args.construction_mode,
           "use_probes": args.use_probes,
           "condition": (("D" if args.construction_mode == "typed_json" else "C") if args.use_probes
                          else ("B" if args.construction_mode == "typed_json" else "A")),
           "probe_manifest_path": str(args.probe_manifest.relative_to(ROOT)) if args.use_probes else None,
           "probe_manifest_sha256": sha(args.probe_manifest) if args.use_probes else None,
           "semgrep_version": version.stdout.strip(), "selection_sha256": sha(args.selection),
           "code_sha256": {str(p.relative_to(ROOT)): sha(p) for p in code},
           "annotation_sha256": {str(p.relative_to(ROOT)): sha(p) for p in annotation_files},
           # Host-aware, not hardcoded to GPTLAB_API_KEY -- a gpt-4o (OPENAI host) run's actual
           # credential is OPENAI_API_KEY; this previously always reported GPTLAB_API_KEY's
           # presence regardless of which key the resolved host actually needed.
           "credential_available": bool(os.environ.get("OPENAI_API_KEY")) if resolved_host == "OPENAI"
                                     else bool(os.environ.get("GPTLAB_API_KEY")),
           "reference_authorship": "assistant-authored after bundle inspection; independent expert review pending"}
    if args.condition:
        env.update(condition=args.condition,
                   prompt_policy=f"CONDITION_{args.condition}_" +
                                 ("TYPED_JSON_WITH_PROBES" if args.condition == "D" else "AUTOGREP_DEFAULT_WITH_PROBES"),
                   probe_manifest_sha256=sha(out / "probe_manifest.json"),
                   probe_coverage={"requested_cases": len(ids), "eligible_cases": frozen["eligible_cases"],
                                   "ineligible_cases": frozen["ineligible_cases"]},
                   probe_parser_versions=frozen["entries"][ids[0]]["parser_versions"],
                   probe_builder_sha256=frozen["entries"][ids[0]]["dev_probe_sha256"])
    save(out / "environment.json", env)
    save(out / "selection.json", selection)
    if args.mode == "preflight":
        print(json.dumps(env, indent=2))
        return
    config = Config(openrouter_api_key="offline-reference", repos_cache_dir=out / "cache",
                    rule_schema_policy="semgrep_search_taint_v2", max_output_tokens=2048)
    if args.mode == "model":
        from gptlab_config import build_config
        # Credential presence + live validity were already checked above, before out.mkdir().
        config = build_config(args.model, temperature=0, max_retries=3, max_output_tokens=2048,
                              prompt_variant=args.prompt_variant,
                              construction_mode=args.construction_mode,
                              repos_cache_dir=out / "cache", generated_rules_dir=out / "rules")
        config.rule_schema_policy = "semgrep_search_taint_v2"
        config.benchmark_cases_dir = ROOT / "benchmark/cases"
        recorder = RawCaptureRecorder(out, "diagnostic")
        llm = LLMClient(config)
        # Retries are part of this recorded protocol, never hidden SDK retries.
        llm.client.max_retries = 0
        wrap_llm_client(llm, recorder)
    probe_manifest_entries = None
    if args.use_probes and args.mode == "model":
        # run_cd_case_from_manifest()/run_model_case_cd() do their OWN local probe-module imports
        # (Section 5: "Conditions A and B's code path must not import the probe module at all") --
        # this block only reads the manifest JSON, never touching dev_probe/combined_gate itself.
        probe_manifest_entries = json.loads(args.probe_manifest.read_text())["entries"]
    episodes = []
    for cid in ids:
        if args.mode == "references":
            source = ROOT / "benchmark/diagnostic_20261010/reference_rules" / args.reference_version / f"{cid}.yml"
            if not source.exists():
                episode = {"case_id": cid, "reference": None, "status": "reference_not_authored"}
            else:
                target = out / cid / "rule.yml"
                target.parent.mkdir(parents=True, exist_ok=False)
                target.write_bytes(source.read_bytes())
                parser_client = object.__new__(LLMClient)
                parser_client.config = config
                doc = yaml.safe_load(target.read_text())
                valid, error = parser_client.validate_rule_schema(doc["rules"][0])
                if not valid:
                    raise RuntimeError(f"Reference {cid} failed envelope validation: {error}")
                evaluation = scan(target, cid, manifest, ann, out / cid / "bundle", hidden=True)
                episode = {"case_id": cid, "reference": evaluation, "source_rule_sha256": sha(source)}
            save(out / cid / "episode.json", episode)
        elif args.use_probes:
            episode = run_cd_case_from_manifest(cid, llm, config, recorder, manifest, ann, out,
                                                 condition=env["condition"],
                                                 probe_manifest_entries=probe_manifest_entries)
        elif args.condition:
            probe, paths, provenance = prepared[cid]
            try:
                episode = run_model_case_cd(cid, llm, config, recorder, manifest, ann, out,
                                            args.condition, probe, paths, probe_provenance=provenance)
            except Exception as exc:
                captures = [recorder.raw_dir / f"{cid}.json", *recorder.retries_dir.glob(f"{cid}_attempt*.json")]
                save(out / "interrupted.json", {"case_id": cid, "condition": args.condition,
                     "error_type": type(exc).__name__, "error": str(exc),
                     "calls_recorded": sum(p.exists() for p in captures),
                     "completed_cases": [e["case_id"] for e in episodes],
                     "status": "incomplete; resume requires preserving already-consumed calls"})
                raise
        else:
            episode = run_model_case(cid, llm, config, recorder, manifest, ann, out,
                                      acceptance_policy=args.acceptance_policy)
        episodes.append(episode)
        print(f"{cid}: " + json.dumps(report([episode], [cid], args.mode)["conditions"]), flush=True)
    summary = report(episodes, ids, args.mode)
    if args.condition:
        summary["development_probes"] = summarize_cd(episodes, ids)
    save(out / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
