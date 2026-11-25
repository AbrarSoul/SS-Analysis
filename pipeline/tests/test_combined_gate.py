"""
Offline tests for pipeline/combined_gate.py and pipeline/probe_cache.py -- the C/D combined
accept/stop gate and deterministic probe caching required before any new C/D inference, per
Binding_Form_Audit_Closure_20261013.md's six specified scenarios:

  1. Visible pass + probe failure -> repair within the same attempt budget (not accepted, not stopped).
  2. Visible AND both probe checks pass -> accept and stop.
  3. Budget exhaustion -> retain failure; never reset calls or silently accept.
  4. Ineligible case -> explicit visible-only fallback, flagged as a fallback.
  5. Probe scan error -> failure/error handling, never collapsed into the ineligibility fallback.
  6. Cache mismatch -> reject or rebuild under a new version; never silently reuse stale input.

Also covers CD_Gate_Cache_Review_20261013.md's three further findings, each reproduced directly
against the pre-fix code before the corresponding fix was accepted: (1) tampered cache payloads
were served as hits even in strict mode; (2) the cache key omitted language/parser identity, so a
TypeScript request could return a cached JavaScript probe; (3) resource accounting assumed one
scan per attempt, overcounting visible scans (or undercounting repairs) whenever an attempt's
generation failed before any scan could run.

No model calls, no real Semgrep scans -- every evaluation input here is a synthetic dict shaped
like diagnostic_v2.py's scan()/probe_coverage_check.py's scan_probe() already return.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
from combined_gate import combined_decision, evaluate_probe_pair, summarize_episode_resources, AttemptEvent
import probe_cache
from probe_cache import (get_or_build_probe, cache_key, CacheMismatchError,
                          build_experiment_manifest_entry, load_probe_for_experiment,
                          ExperimentManifestError)
from dev_probe import ProbeResult, ProbeIneligible


# --------------------------------------------------------------------------------------------
# evaluate_probe_pair -- the scan_probe()-shaped dict -> three-boolean reduction
# --------------------------------------------------------------------------------------------


def test_evaluate_probe_pair_both_checks_pass():
    vuln_scan = {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}
    patched_scan = {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}
    r = evaluate_probe_pair(vuln_scan, patched_scan)
    assert r == {"vulnerable_probe_correct": True, "patched_probe_correct": True, "probe_scan_error": False}


def test_evaluate_probe_pair_vulnerable_missed():
    vuln_scan = {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False}
    r = evaluate_probe_pair(vuln_scan, vuln_scan)
    assert r["vulnerable_probe_correct"] is False
    assert r["probe_scan_error"] is False


def test_evaluate_probe_pair_patched_false_positive():
    scan = {"scan_ok": True, "vulnerable_detected": True, "patched_detected": True}
    r = evaluate_probe_pair(scan, scan)
    assert r["patched_probe_correct"] is False
    assert r["probe_scan_error"] is False


def test_evaluate_probe_pair_scan_error_is_conservative_failure():
    """Scenario 5: a scan error must produce FALSE for both checks (never treated as a pass),
    and must be flagged distinctly as a scan error, not folded into an ordinary wrong-answer."""
    ok_scan = {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}
    error_scan = {"scan_ok": False, "error": "non-JSON output"}
    r = evaluate_probe_pair(error_scan, ok_scan)
    assert r == {"vulnerable_probe_correct": False, "patched_probe_correct": False, "probe_scan_error": True}
    r2 = evaluate_probe_pair(ok_scan, error_scan)
    assert r2["probe_scan_error"] is True


# --------------------------------------------------------------------------------------------
# combined_decision -- the full gate state machine
# --------------------------------------------------------------------------------------------


def test_scenario_1_visible_pass_probe_fail_triggers_repair_within_budget():
    probe_checks = evaluate_probe_pair(
        {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False},
        {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False})
    d = combined_decision(condition="D", attempt=1, max_attempts=3, visible_correct=True,
                           probe_eligible=True, probe_checks=probe_checks)
    assert d.accept is False
    assert d.stop is False  # repair: more attempts remain, loop must continue
    assert "probe check" in d.reason
    assert d.is_fallback is False


def test_scenario_2_visible_and_both_probes_pass_accepts_and_stops():
    probe_checks = evaluate_probe_pair(
        {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False},
        {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False})
    d = combined_decision(condition="C", attempt=1, max_attempts=3, visible_correct=True,
                           probe_eligible=True, probe_checks=probe_checks)
    assert d.accept is True
    assert d.stop is True
    assert d.is_fallback is False


def test_scenario_3_budget_exhaustion_retains_failure_no_reset():
    probe_checks = evaluate_probe_pair(
        {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False},
        {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False})
    # Attempts 1 and 2: not yet exhausted, loop continues.
    d1 = combined_decision(condition="D", attempt=1, max_attempts=3, visible_correct=True,
                            probe_eligible=True, probe_checks=probe_checks)
    d2 = combined_decision(condition="D", attempt=2, max_attempts=3, visible_correct=True,
                            probe_eligible=True, probe_checks=probe_checks)
    assert d1.accept is False and d1.stop is False
    assert d2.accept is False and d2.stop is False
    # Attempt 3 (the ceiling): exhausted -- stop, but never accept, and the reason records why.
    d3 = combined_decision(condition="D", attempt=3, max_attempts=3, visible_correct=True,
                            probe_eligible=True, probe_checks=probe_checks)
    assert d3.accept is False
    assert d3.stop is True
    assert "budget exhausted" in d3.reason


def test_attempt_beyond_max_attempts_is_rejected_outright():
    """CD_Gate_Cache_Review_20261013.md's hardening note: a call past the declared ceiling must
    raise, not silently be evaluated (the real runner's `range(1, 4)` never does this, but the
    gate itself should not rely on the caller's discipline alone)."""
    probe_checks = evaluate_probe_pair(
        {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False},
        {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False})
    with pytest.raises(ValueError):
        combined_decision(condition="D", attempt=4, max_attempts=3, visible_correct=True,
                           probe_eligible=True, probe_checks=probe_checks)


def test_unknown_condition_is_rejected_outright():
    """An unrecognized condition string must raise, not silently fall through to A/B behavior."""
    with pytest.raises(ValueError):
        combined_decision(condition="E", attempt=1, max_attempts=3, visible_correct=True,
                           probe_eligible=False)


def test_scenario_4_ineligible_case_falls_back_to_visible_only_and_is_flagged():
    d = combined_decision(condition="C", attempt=1, max_attempts=3, visible_correct=True,
                           probe_eligible=False)
    assert d.accept is True
    assert d.stop is True
    assert d.is_fallback is True  # explicitly recorded, never indistinguishable from a real probe pass
    assert d.probe_checks is None
    assert d.probe_eligible is False


def test_scenario_4b_ineligible_case_with_failing_visible_still_repairs_like_ab():
    """is_fallback stays False here (the episode didn't accept), but probe_eligible must still
    correctly record that this was never a probe-eligible case at all -- tracked independently,
    per the review's note that is_fallback alone would omit unsuccessful ineligible episodes from
    any eligibility/fallback coverage count."""
    d = combined_decision(condition="D", attempt=1, max_attempts=3, visible_correct=False,
                           probe_eligible=False)
    assert d.accept is False
    assert d.stop is False
    assert d.is_fallback is False
    assert d.probe_eligible is False


def test_scenario_5_probe_scan_error_is_a_failed_check_not_an_ineligibility_fallback():
    """The central risk the closure note called out: a probe scan error must NEVER be
    silently treated as 'no eligible probe' -- probe_eligible stays True here (the probe pair
    itself is fine; its SCAN failed), and the gate must still refuse to accept."""
    probe_checks = evaluate_probe_pair({"scan_ok": False, "error": "timeout"},
                                        {"scan_ok": False, "error": "timeout"})
    d = combined_decision(condition="C", attempt=1, max_attempts=3, visible_correct=True,
                           probe_eligible=True, probe_checks=probe_checks)
    assert d.accept is False
    assert d.is_fallback is False  # the critical assertion: NOT silently treated as a fallback
    assert d.probe_eligible is True
    assert "scan error" in d.reason
    assert d.probe_checks["probe_scan_error"] is True


def test_conditions_a_b_never_consult_probe_checks():
    """A/B must behave identically regardless of what probe_checks says -- even a failing probe
    result must not affect A/B's accept decision, matching 'Conditions A and B's code path must
    not import the probe module at all.'"""
    failing_probe_checks = evaluate_probe_pair(
        {"scan_ok": True, "vulnerable_detected": False, "patched_detected": True},
        {"scan_ok": True, "vulnerable_detected": False, "patched_detected": True})
    for condition in ("A", "B"):
        d = combined_decision(condition=condition, attempt=1, max_attempts=3, visible_correct=True,
                               probe_eligible=True, probe_checks=failing_probe_checks)
        assert d.accept is True and d.stop is True and d.is_fallback is False


def test_combined_decision_requires_probe_checks_for_eligible_cd():
    with pytest.raises(ValueError):
        combined_decision(condition="C", attempt=1, max_attempts=3, visible_correct=True,
                           probe_eligible=True, probe_checks=None)


# --------------------------------------------------------------------------------------------
# Deterministic probe caching -- scenario 6, plus the review's Finding 1 (payload integrity)
# and Finding 2 (language/parser identity)
# --------------------------------------------------------------------------------------------


def test_cache_miss_then_hit(tmp_path):
    vuln = "def f():\n    token = 1\n    return token\n"
    r1, status1 = get_or_build_probe("CASE-X", "python", vuln, vuln, tmp_path)
    assert status1 == "miss_built"
    assert isinstance(r1, ProbeResult)
    r2, status2 = get_or_build_probe("CASE-X", "python", vuln, vuln, tmp_path)
    assert status2 == "hit"
    assert r2 == r1  # byte-for-byte identical, served from cache, not rebuilt


def test_cache_hit_for_ineligible_case_too(tmp_path):
    """The cache must correctly round-trip a ProbeIneligible result, not just ProbeResult."""
    src = "def f():\n    eval('1')\n    return 1\n"
    r1, status1 = get_or_build_probe("CASE-Y", "python", src, src, tmp_path)
    assert status1 == "miss_built"
    assert isinstance(r1, ProbeIneligible)
    r2, status2 = get_or_build_probe("CASE-Y", "python", src, src, tmp_path)
    assert status2 == "hit"
    assert r2 == r1


def test_scenario_6_cache_mismatch_rebuilds_not_silently_stale(tmp_path):
    """Changing the input text must invalidate the cache -- the second call must NOT silently
    return the first (now-stale) probe result."""
    vuln1 = "def f():\n    token = 1\n    return token\n"
    vuln2 = "def f():\n    other = 1\n    return other\n"
    r1, status1 = get_or_build_probe("CASE-Z", "python", vuln1, vuln1, tmp_path)
    assert status1 == "miss_built"
    assert r1.old_name == "token"
    r2, status2 = get_or_build_probe("CASE-Z", "python", vuln2, vuln2, tmp_path)
    assert status2 == "mismatch_rebuilt"
    assert r2.old_name == "other"  # NOT the stale "token" from the first input
    # A subsequent call with the SAME (new) input must now be a clean hit against the rebuilt entry.
    r3, status3 = get_or_build_probe("CASE-Z", "python", vuln2, vuln2, tmp_path)
    assert status3 == "hit"
    assert r3 == r2


def test_scenario_6b_cache_mismatch_strict_mode_rejects_instead_of_rebuilding(tmp_path):
    vuln1 = "def f():\n    token = 1\n    return token\n"
    vuln2 = "def f():\n    other = 1\n    return other\n"
    get_or_build_probe("CASE-W", "python", vuln1, vuln1, tmp_path)
    with pytest.raises(CacheMismatchError):
        get_or_build_probe("CASE-W", "python", vuln2, vuln2, tmp_path, strict=True)


def test_finding1_tampered_payload_is_detected_not_served(tmp_path):
    """Direct reproduction of Finding 1: a cache entry's payload text, edited in place while its
    key is left untouched, must no longer be served as a 'hit' -- in EITHER mode. Before the fix,
    strict mode returned the tampered text as a 'hit' because only the key was ever checked."""
    import json
    vuln = "def f():\n    token = 1\n    return token\n"
    get_or_build_probe("CASE-TAMPER", "python", vuln, vuln, tmp_path)
    entry_path = tmp_path / "CASE-TAMPER" / "probe_cache.json"
    entry = json.loads(entry_path.read_text())
    entry["payload"]["fields"]["vulnerable_probe"] = "def f():\n    return 999\n"
    entry_path.write_text(json.dumps(entry))

    with pytest.raises(CacheMismatchError):
        get_or_build_probe("CASE-TAMPER", "python", vuln, vuln, tmp_path, strict=True)

    result, status = get_or_build_probe("CASE-TAMPER", "python", vuln, vuln, tmp_path, strict=False)
    assert status == "mismatch_rebuilt"
    assert "999" not in result.vulnerable_probe  # the tampered text must never be returned


def test_finding2_language_is_part_of_the_cache_key(tmp_path):
    """Direct reproduction of Finding 2: requesting the SAME case_id/text under a DIFFERENT
    language must never return the other language's cached probe. Before the fix, a TypeScript
    request against a JavaScript-cached entry returned 'hit' with the JS result."""
    src = "function f(x) { var token = x + 1; return token; }"
    r1, s1 = get_or_build_probe("CASE-LANG", "javascript", src, src, tmp_path)
    assert s1 == "miss_built" and r1.language == "javascript"

    with pytest.raises(CacheMismatchError):
        get_or_build_probe("CASE-LANG", "typescript", src, src, tmp_path, strict=True)

    r2, s2 = get_or_build_probe("CASE-LANG", "typescript", src, src, tmp_path, strict=False)
    assert s2 == "mismatch_rebuilt"
    assert r2.language == "typescript"  # never the stale javascript result


def test_cache_key_includes_language_and_parser_versions():
    key = cache_key("python", "def f(): return 1\n", "def f(): return 1\n")
    assert key["language"] == "python"
    assert key["dev_probe_sha256"] == probe_cache.dev_probe_sha256()
    assert key["parser_versions"] == probe_cache.parser_versions()
    assert len(key["dev_probe_sha256"]) == 64  # a real sha256 hex digest, not a placeholder


def test_parser_version_change_invalidates_cache(tmp_path, monkeypatch):
    """A changed parser/runtime version must invalidate the cache exactly like a changed builder
    hash already does -- simulated by monkeypatching parser_versions() between the two calls,
    since actually installing a different tree-sitter version is out of scope for a unit test."""
    vuln = "def f():\n    token = 1\n    return token\n"
    get_or_build_probe("CASE-PARSER", "python", vuln, vuln, tmp_path)
    monkeypatch.setattr(probe_cache, "parser_versions", lambda: {"tree_sitter": "9.9.9"})
    with pytest.raises(CacheMismatchError):
        get_or_build_probe("CASE-PARSER", "python", vuln, vuln, tmp_path, strict=True)
    _, status = get_or_build_probe("CASE-PARSER", "python", vuln, vuln, tmp_path, strict=False)
    assert status == "mismatch_rebuilt"


# --------------------------------------------------------------------------------------------
# Frozen experiment manifest -- the stricter loader for the fixed, reviewed 24-case selection
# --------------------------------------------------------------------------------------------


def test_manifest_round_trip_for_eligible_case(tmp_path):
    vuln = "def f():\n    token = 1\n    return token\n"
    entry = build_experiment_manifest_entry("CASE-M1", "python", vuln, vuln)
    manifest = {"CASE-M1": entry}
    result, status = load_probe_for_experiment("CASE-M1", "python", vuln, vuln, tmp_path, manifest)
    assert isinstance(result, ProbeResult)
    assert status == "miss_built"
    # A second load must be a clean, still-validated hit.
    result2, status2 = load_probe_for_experiment("CASE-M1", "python", vuln, vuln, tmp_path, manifest)
    assert status2 == "hit"
    assert result2 == result


def test_manifest_round_trip_for_ineligible_case(tmp_path):
    src = "def f():\n    eval('1')\n    return 1\n"
    entry = build_experiment_manifest_entry("CASE-M2", "python", src, src)
    manifest = {"CASE-M2": entry}
    result, status = load_probe_for_experiment("CASE-M2", "python", src, src, tmp_path, manifest)
    assert isinstance(result, ProbeIneligible)


def test_manifest_rejects_case_missing_from_manifest(tmp_path):
    vuln = "def f():\n    token = 1\n    return token\n"
    with pytest.raises(ExperimentManifestError):
        load_probe_for_experiment("CASE-UNKNOWN", "python", vuln, vuln, tmp_path, manifest={})


def test_manifest_rejects_changed_input_text(tmp_path):
    """'A changed or additional case may be built offline for review, but must not automatically
    inherit the old review' -- a case whose text no longer matches the manifest must raise, not
    silently rebuild and proceed as if it were still the reviewed artifact."""
    vuln = "def f():\n    token = 1\n    return token\n"
    entry = build_experiment_manifest_entry("CASE-M3", "python", vuln, vuln)
    manifest = {"CASE-M3": entry}
    changed_vuln = "def f():\n    token = 2\n    return token\n"
    with pytest.raises(ExperimentManifestError):
        load_probe_for_experiment("CASE-M3", "python", changed_vuln, changed_vuln, tmp_path, manifest)


def test_manifest_rejects_language_mismatch(tmp_path):
    src = "function f(x) { var token = x + 1; return token; }"
    entry = build_experiment_manifest_entry("CASE-M4", "javascript", src, src)
    manifest = {"CASE-M4": entry}
    with pytest.raises(ExperimentManifestError):
        load_probe_for_experiment("CASE-M4", "typescript", src, src, tmp_path, manifest)


def test_manifest_rejects_builder_version_drift(tmp_path, monkeypatch):
    """If dev_probe.py changes after the manifest was frozen, loading must raise rather than
    silently serving a probe built under the new, un-reviewed builder as if it still matched."""
    vuln = "def f():\n    token = 1\n    return token\n"
    entry = build_experiment_manifest_entry("CASE-M5", "python", vuln, vuln)
    manifest = {"CASE-M5": entry}
    monkeypatch.setattr(probe_cache, "dev_probe_sha256", lambda: "0" * 64)
    with pytest.raises(ExperimentManifestError):
        load_probe_for_experiment("CASE-M5", "python", vuln, vuln, tmp_path, manifest)


def test_manifest_detects_probe_text_deviation_even_with_matching_hashes(tmp_path):
    """Even if every input/builder/language hash matches, a probe whose actual generated text
    differs from what the manifest recorded (e.g. a non-deterministic builder bug) must be
    caught -- simulated here by hand-corrupting the manifest's recorded probe hash."""
    vuln = "def f():\n    token = 1\n    return token\n"
    entry = build_experiment_manifest_entry("CASE-M6", "python", vuln, vuln)
    entry["vulnerable_probe_sha256"] = "0" * 64  # simulate a manifest that expects different output
    manifest = {"CASE-M6": entry}
    with pytest.raises(ExperimentManifestError):
        load_probe_for_experiment("CASE-M6", "python", vuln, vuln, tmp_path, manifest)


# --------------------------------------------------------------------------------------------
# Full-episode simulation -- repair-then-accept and full-exhaustion trajectories, threading
# combined_decision() across multiple synthetic attempts the way run_model_case()'s real retry
# loop would, without calling any real model or Semgrep code. Resource accounting operates on
# AttemptEvent, not raw decisions, so a generation-failure attempt (no scan at all) is
# represented correctly -- see Finding 3.
# --------------------------------------------------------------------------------------------


def _simulate_episode(condition, max_attempts, probe_eligible, attempt_outcomes):
    """attempt_outcomes: list of one of:
      ("generation_failed",)                                  -- no scan, no decision
      (visible_correct, probe_checks_or_None, scanner_invocations)  -- a real scanned attempt
    Returns (final_decision_or_None, events) -- stops at the first `stop=True` decision, exactly
    like the real loop's `if accepted_rule: break`; final_decision is None if the episode ends on
    a generation failure with no attempts left (not exercised by the tests below, but kept honest)."""
    events = []
    final_decision = None
    for i, outcome in enumerate(attempt_outcomes, start=1):
        if outcome[0] == "generation_failed":
            events.append(AttemptEvent(attempt=i, generation_ok=False))
            continue
        visible_correct, probe_checks, scanner_invocations = outcome
        decision = combined_decision(condition=condition, attempt=i, max_attempts=max_attempts,
                                      visible_correct=visible_correct, probe_eligible=probe_eligible,
                                      probe_checks=probe_checks)
        events.append(AttemptEvent(attempt=i, generation_ok=True, decision=decision,
                                    probe_scanner_invocations=scanner_invocations))
        final_decision = decision
        if decision.stop:
            return final_decision, events
    return final_decision, events


def test_full_episode_repair_then_accept_trajectory():
    """A realistic C/D episode: attempt 1 fails the probe, attempt 2 fails visible entirely,
    attempt 3 finally passes everything -- the gate must repair through both failures and only
    accept on the third, consuming exactly 3 attempts, never fewer or more."""
    failing_probe = evaluate_probe_pair({"scan_ok": True, "vulnerable_detected": False, "patched_detected": False},
                                         {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False})
    passing_probe = evaluate_probe_pair({"scan_ok": True, "vulnerable_detected": True, "patched_detected": False},
                                         {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False})
    outcomes = [(True, failing_probe, 1), (False, None, 0), (True, passing_probe, 1)]
    decision, events = _simulate_episode("C", 3, True, outcomes)
    assert len(events) == 3
    assert decision.accept is True and decision.stop is True
    resources = summarize_episode_resources(events)
    assert resources["generation_calls"] == 3
    assert resources["visible_scans"] == 3
    assert resources["repair_calls"] == 2
    # attempt 2 failed visible, so its probe was never scanned -- only attempts 1 and 3 ran one.
    assert resources["probe_scans"] == 2


def test_full_episode_exhaustion_trajectory_never_accepts():
    """All 3 attempts fail the probe check -- the episode must end in budget exhaustion, never
    accept, and consume exactly the 3-attempt ceiling (not fewer, not silently extended)."""
    failing_probe = evaluate_probe_pair({"scan_ok": True, "vulnerable_detected": False, "patched_detected": False},
                                         {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False})
    outcomes = [(True, failing_probe, 1)] * 3
    decision, events = _simulate_episode("D", 3, True, outcomes)
    assert len(events) == 3
    assert decision.accept is False
    assert decision.stop is True  # stops because exhausted, not because it accepted
    assert "budget exhausted" in decision.reason
    resources = summarize_episode_resources(events)
    assert resources == {"generation_calls": 3, "visible_scans": 3, "probe_scans": 3, "repair_calls": 2}


def test_resource_accounting_never_counts_a_probe_scan_for_a_failed_visible_attempt():
    """An ineligible-fallback episode (A/B-like, no probes ever consulted) must report zero probe
    scans even though multiple attempts were made -- 'different numbers of probes consume
    resources' must not overcount when no probe was ever actually eligible/run."""
    outcomes = [(False, None, 0), (False, None, 0), (True, None, 0)]
    decision, events = _simulate_episode("A", 3, False, outcomes)
    assert decision.accept is True
    resources = summarize_episode_resources(events)
    assert resources == {"generation_calls": 3, "visible_scans": 3, "probe_scans": 0, "repair_calls": 2}


def test_finding3_decode_failure_then_success_counts_correctly():
    """Direct reproduction of Finding 3: a decode/parse failure (no rule produced, no scan at
    all) followed by a successful, visibly-passing generation must report exactly 2 generation
    calls, 1 visible scan, and 1 repair call -- never 2 visible scans (overcounting the failed
    attempt as if it had been scanned) and never 0 repair calls (undercounting the failed
    attempt's retry as if it hadn't happened)."""
    outcomes = [("generation_failed",), (True, None, 0)]
    decision, events = _simulate_episode("A", 3, False, outcomes)
    assert decision.accept is True
    resources = summarize_episode_resources(events)
    assert resources == {"generation_calls": 2, "visible_scans": 1, "probe_scans": 0, "repair_calls": 1}


def test_attempt_event_rejects_inconsistent_construction():
    with pytest.raises(ValueError):
        AttemptEvent(attempt=1, generation_ok=False, decision=combined_decision(
            condition="A", attempt=1, max_attempts=3, visible_correct=True, probe_eligible=False))
    with pytest.raises(ValueError):
        AttemptEvent(attempt=1, generation_ok=True, decision=None)
