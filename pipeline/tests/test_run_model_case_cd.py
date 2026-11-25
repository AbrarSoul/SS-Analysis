"""
Offline integration tests for diagnostic_v2.run_model_case_cd() -- the real retry/feedback loop
for conditions C/D, wired to combined_gate.py's accept/stop logic for the first time (not just
the standalone module tests in test_combined_gate.py). Follows the exact same mocking pattern
test_diagnostic_regressions.py already establishes for run_model_case(): monkeypatch the
module-level `scan` function and inject a fake LLM object with `.generate_rule()`/`.last_error`.
No real model calls, no real Semgrep -- `scan` and `scan_probe_fn` are both fully synthetic here.

Per CD_Gate_Cache_Review_20261013.md's explicit "next step": verify probe feedback reaches the
next call, hidden results remain unavailable until generation finishes, no budget reset occurs,
A/B stay unchanged (run_model_case() itself is untouched -- see test_diagnostic_regressions.py,
rerun unchanged after this file was added), and episode/provenance records retain the real
decisions and resource events.
"""
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]
import diagnostic_v2 as diagnostic
from dev_probe import ProbeResult, ProbeIneligible


def rule(rid="x", **body):
    return {"id": rid, "message": "m", "severity": "ERROR", "languages": ["python"], **body}


class _FakeRecorder:
    def __init__(self, tmp_path):
        self.raw_dir = tmp_path / "raw"
        self.retries_dir = tmp_path / "retries"
        self.raw_dir.mkdir()
        self.retries_dir.mkdir()

    def begin_case(self, cid):
        pass


def _visible_eval(*, scan_ok=True, visible_correct=True, legacy_accepted=None, location_correct=True,
                   patched_detected=False):
    if legacy_accepted is None:
        legacy_accepted = visible_correct
    return {
        "scan_ok": scan_ok, "returncode": 0, "all_targets_scanned": True,
        "errors": [] if scan_ok else [{"message": "synthetic scan error"}],
        "legacy_accepted": legacy_accepted, "visible_correct": visible_correct,
        "complete_success": False,
        "samples": [
            {"sample_type": "original_vulnerable", "label": "positive", "detected": True,
             "finding_location_correct": location_correct, "finding_lines": [99], "outcome": "TP" if location_correct else "FN"},
            {"sample_type": "original_patched", "label": "negative", "detected": patched_detected,
             "finding_location_correct": None, "finding_lines": [], "outcome": "FP" if patched_detected else "TN"},
        ],
    }


def _eligible_probe():
    return ProbeResult(case_id="CASE-TEST", language="python", old_name="token", new_name="token_renamed",
                        vulnerable_probe="def f(): return token_renamed", patched_probe="def f(): return token_renamed",
                        patched_probe_renamed=True)


def _materialize_probe(probe_result, tmp_path):
    """Writes the probe's OWN validated text to real files under tmp_path, matching what a real
    caller's materialization step would do -- CD_Integration_Followup_Review_20261013.md Finding 1
    found the prior fake `/dev/null/...` paths could never catch a verification gap, since nothing
    ever read them. Returns (vulnerable_probe_path, patched_probe_path)."""
    probe_dir = tmp_path / "_dev_probes" / probe_result.case_id
    probe_dir.mkdir(parents=True, exist_ok=True)
    vuln_path = probe_dir / "vulnerable_probe.py"
    patched_path = probe_dir / "patched_probe.py"
    vuln_path.write_text(probe_result.vulnerable_probe)
    patched_path.write_text(probe_result.patched_probe)
    return vuln_path, patched_path


def _ineligible_probe():
    return ProbeIneligible(case_id="CASE-TEST", language="python", reason="no eligible local binding found")


def _manifest():
    return {"CASE-TEST": {"language": "python", "vulnerable_lines": [1, 1]}}


# --------------------------------------------------------------------------------------------
# Scenario 1: visible pass + probe failure -> repair, feedback reaches the NEXT call
# --------------------------------------------------------------------------------------------


def test_probe_feedback_reaches_the_next_generation_call(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())

    feedback_seen = []

    def generate(patch, error_feedback=None):
        feedback_seen.append(error_feedback)
        return rule()

    probe_scan_calls = []

    def scan_probe_fn(rule_path, vuln_path, patched_path, out_dir):
        probe_scan_calls.append(rule_path)
        # Fails the probe on attempt 1, passes on attempt 2.
        passed = len(probe_scan_calls) >= 2
        return {"scan_ok": True, "vulnerable_detected": passed, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=generate, last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=_eligible_probe(), probe_paths=_materialize_probe(_eligible_probe(), tmp_path), scan_probe_fn=scan_probe_fn)

    assert len(episode["attempts"]) == 2
    assert episode["final_rule_path"] is not None  # accepted on attempt 2
    # The probe-failure feedback from attempt 1 must have reached attempt 2's generate_rule call.
    assert feedback_seen[0] is None
    assert "additional development-time test case" in feedback_seen[1]
    assert len(probe_scan_calls) == 2
    assert episode["probe_eligible"] is True
    assert episode["probe_fallback_used"] is False


# --------------------------------------------------------------------------------------------
# Scenario 2: visible AND both probe checks pass -> accept and stop immediately
# --------------------------------------------------------------------------------------------


def test_all_checks_pass_accepts_and_stops_on_first_attempt(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    calls = []

    def generate(patch, error_feedback=None):
        calls.append(1)
        return rule()

    def scan_probe_fn(rule_path, vuln_path, patched_path, out_dir):
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=generate, last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="C", probe_result=_eligible_probe(), probe_paths=_materialize_probe(_eligible_probe(), tmp_path), scan_probe_fn=scan_probe_fn)

    assert len(episode["attempts"]) == 1
    assert len(calls) == 1  # no retry triggered
    assert episode["final_rule_path"] is not None
    assert episode["resource_accounting"] == {"generation_calls": 1, "visible_scans": 1, "probe_scans": 1, "repair_calls": 0}


# --------------------------------------------------------------------------------------------
# Scenario 3: budget exhaustion -> no reset, failure retained, exactly 3 attempts consumed
# --------------------------------------------------------------------------------------------


def test_budget_exhaustion_consumes_exactly_three_attempts_and_never_accepts(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())

    def generate(patch, error_feedback=None):
        return rule()

    def scan_probe_fn(rule_path, vuln_path, patched_path, out_dir):
        return {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False}  # always fails

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=generate, last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=_eligible_probe(), probe_paths=_materialize_probe(_eligible_probe(), tmp_path), scan_probe_fn=scan_probe_fn)

    assert len(episode["attempts"]) == 3  # exactly the ceiling, never fewer, never more
    assert episode["final_rule_path"] is None
    assert episode["final_rule_sha256"] is None
    assert episode["resource_accounting"]["generation_calls"] == 3
    assert episode["resource_accounting"]["repair_calls"] == 2


# --------------------------------------------------------------------------------------------
# Scenario 4: ineligible case -> visible-only fallback, flagged, hidden results still gated
# --------------------------------------------------------------------------------------------


def test_ineligible_case_falls_back_to_visible_only_and_is_flagged(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_scan_calls = []

    def scan_probe_fn(rule_path, vuln_path, patched_path, out_dir):
        probe_scan_calls.append(1)
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="C", probe_result=_ineligible_probe(), probe_paths=None, scan_probe_fn=scan_probe_fn)

    assert len(episode["attempts"]) == 1
    assert episode["final_rule_path"] is not None  # accepted on visible alone
    assert episode["probe_eligible"] is False
    assert episode["probe_fallback_used"] is True  # explicitly recorded, not silently indistinguishable
    assert probe_scan_calls == []  # the probe scanner must never even be called for an ineligible case


# --------------------------------------------------------------------------------------------
# Scenario 5: probe scan error -> treated as a failed check, triggers repair, never a fallback
# --------------------------------------------------------------------------------------------


def test_probe_scan_error_triggers_repair_not_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())

    def scan_probe_fn(rule_path, vuln_path, patched_path, out_dir):
        return {"scan_ok": False, "error": "non-JSON output"}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=_eligible_probe(), probe_paths=_materialize_probe(_eligible_probe(), tmp_path), scan_probe_fn=scan_probe_fn)

    assert episode["final_rule_path"] is None  # never accepted
    assert episode["probe_fallback_used"] is False  # critical: NOT silently treated as a fallback
    assert len(episode["attempts"]) == 3  # repaired through to budget exhaustion, like any failure
    assert "additional development-time test case" in episode["attempts"][0]["feedback"]


# --------------------------------------------------------------------------------------------
# Hidden-result gating and decode-failure accounting (Finding 3's exact scenario, through the
# real runner this time, not just the standalone simulation)
# --------------------------------------------------------------------------------------------


def test_hidden_results_unavailable_until_generation_finishes(monkeypatch, tmp_path):
    """Mirrors test_hidden_samples_never_enter_repair_feedback's existing A/B check, for C/D:
    the probe scanner and visible scan must never run against hidden samples mid-loop, and
    hidden evaluation must happen only after accept/exhaustion."""
    events = []

    def scan(path, cid, manifest, annotations, out, *, hidden):
        events.append("hidden" if hidden else "visible")
        return _visible_eval() if not hidden else {**_visible_eval(), "complete_success": True}
    monkeypatch.setattr(diagnostic, "scan", scan)
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())

    def scan_probe_fn(rule_path, vuln_path, patched_path, out_dir):
        events.append("probe")
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="C", probe_result=_eligible_probe(), probe_paths=_materialize_probe(_eligible_probe(), tmp_path), scan_probe_fn=scan_probe_fn)

    # Exactly one visible scan, one probe scan, then hidden scans -- hidden never interleaved early.
    assert events == ["visible", "probe", "hidden", "hidden"]


def test_decode_failure_then_success_counts_correctly_through_real_runner(monkeypatch, tmp_path):
    """Direct reproduction of Finding 3 through the ACTUAL runner, not the standalone simulation:
    a decode failure (rule=None, no scan at all) followed by a passing generation must report
    exactly 2 generation calls, 1 visible scan, 1 repair call."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    attempt_count = [0]

    def generate(patch, error_feedback=None):
        attempt_count[0] += 1
        if attempt_count[0] == 1:
            return None  # decode/parse failure -- no rule produced
        return rule()

    def scan_probe_fn(rule_path, vuln_path, patched_path, out_dir):
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=generate, last_error="synthetic decode error"), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=_eligible_probe(), probe_paths=_materialize_probe(_eligible_probe(), tmp_path), scan_probe_fn=scan_probe_fn)

    assert len(episode["attempts"]) == 2
    assert episode["attempts"][0]["parsed"] is False
    assert episode["attempts"][0]["feedback"] == "synthetic decode error"
    assert episode["resource_accounting"] == {"generation_calls": 2, "visible_scans": 1, "probe_scans": 1, "repair_calls": 1}


# --------------------------------------------------------------------------------------------
# A/B stay unchanged, and the new function refuses to be misused for A/B
# --------------------------------------------------------------------------------------------


def test_run_model_case_cd_refuses_conditions_a_and_b():
    for condition in ("A", "B"):
        with pytest.raises(ValueError):
            diagnostic.run_model_case_cd("CASE-TEST", NS(), config=NS(), recorder=NS(), manifest={},
                                          ann={}, out=Path("/tmp"), condition=condition, probe_result=None)


def test_eligible_probe_requires_probe_paths():
    with pytest.raises(ValueError):
        diagnostic.run_model_case_cd("CASE-TEST", NS(), config=NS(), recorder=NS(), manifest=_manifest(),
                                      ann={}, out=Path("/tmp"), condition="C",
                                      probe_result=_eligible_probe(), probe_paths=None)


# --------------------------------------------------------------------------------------------
# CD_Integration_Followup_Review_20261013.md's four findings, each reproduced directly against
# the pre-fix code before the corresponding fix was accepted.
# --------------------------------------------------------------------------------------------


def test_finding1_tampered_probe_file_is_rejected_before_scanning(monkeypatch, tmp_path):
    """Direct reproduction: a probe file edited in place AFTER materialization (independent of the
    validated probe_result object) must never reach the scanner. Before the fix, the runner never
    read the files back at all, so the tampered bytes were scanned and the episode was accepted."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_result = _eligible_probe()
    vuln_path, patched_path = _materialize_probe(probe_result, tmp_path)
    vuln_path.write_text("def f():\n    return 999\n")  # tamper, bypassing the validated object
    scan_calls = []

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        scan_calls.append(Path(vp).read_text())
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    with pytest.raises(diagnostic.ProbeMaterializationError):
        diagnostic.run_model_case_cd(
            "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
            config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
            condition="D", probe_result=probe_result, probe_paths=(vuln_path, patched_path), scan_probe_fn=scan_probe_fn)
    assert scan_calls == []  # the scanner must never even be invoked


def test_finding1_matching_materialized_files_are_accepted(tmp_path, monkeypatch):
    """Companion to the fix above: UNTAMPERED, correctly materialized files must still work --
    this is a correctness fix, not a new blanket rejection."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_result = _eligible_probe()
    probe_paths = _materialize_probe(probe_result, tmp_path)

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=probe_result, probe_paths=probe_paths, scan_probe_fn=scan_probe_fn)
    assert episode["final_rule_path"] is not None
    assert episode["verified_probe_hashes"] is not None
    assert len(episode["verified_probe_hashes"]["vulnerable_probe_sha256"]) == 64


def test_finding2_unresolved_probe_state_is_rejected_outright(tmp_path):
    """Direct reproduction: probe_result=None must never be silently treated as a reviewed
    ineligibility decision. Before the fix, this generated a rule, skipped probe scanning,
    accepted on visible success, and reported probe_fallback_used=True indistinguishably from a
    real reviewed ineligibility."""
    with pytest.raises(ValueError):
        diagnostic.run_model_case_cd(
            "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
            config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
            condition="C", probe_result=None, probe_paths=None, scan_probe_fn=lambda *a, **kw: None)


def test_finding2_probe_identity_mismatch_is_rejected(tmp_path):
    """A probe_result resolved for a DIFFERENT case/language must never be silently used for this
    episode -- validates case/language identity, per the review's explicit requirement."""
    wrong_case_probe = ProbeResult(case_id="CASE-OTHER", language="python", old_name="token",
                                    new_name="token_renamed", vulnerable_probe="def f(): return token_renamed",
                                    patched_probe="def f(): return token_renamed", patched_probe_renamed=True)
    with pytest.raises(ValueError):
        diagnostic.run_model_case_cd(
            "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
            config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
            condition="C", probe_result=wrong_case_probe, probe_paths=(Path("/tmp/a"), Path("/tmp/b")))


def test_finding2_ineligible_reason_is_persisted_on_the_episode(monkeypatch, tmp_path):
    """The review noted the episode recorded eligibility but dropped ProbeIneligible.reason --
    confirm it is now persisted."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="C", probe_result=_ineligible_probe(), probe_paths=None, scan_probe_fn=lambda *a, **kw: None)
    assert episode["probe_ineligible_reason"] == _ineligible_probe().reason


def test_finding3_ab_import_isolation(tmp_path):
    """Direct reproduction, in a fresh subprocess: merely importing diagnostic_v2 must never pull
    in dev_probe or tree_sitter -- confirmed broken before the fix (both were in sys.modules after
    a bare `import diagnostic_v2`), confirmed closed after (local imports inside
    run_model_case_cd only)."""
    import subprocess as sp
    script = (
        "import sys; sys.path.insert(0, 'pipeline'); sys.path.insert(0, 'autogrep')\n"
        "import diagnostic_v2\n"
        "assert 'dev_probe' not in sys.modules, 'dev_probe leaked into A/B import path'\n"
        "assert 'tree_sitter' not in sys.modules, 'tree_sitter leaked into A/B import path'\n"
        "print('OK')\n"
    )
    proc = sp.run([sys.executable, "-c", script], cwd=str(ROOT), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


def test_finding4_probe_timeout_is_handled_not_propagated(monkeypatch, tmp_path):
    """Direct reproduction: a probe scan timeout (subprocess.TimeoutExpired, what the real
    scan_probe's subprocess.run(timeout=120) actually raises) must be caught and treated as an
    ordinary probe-scan error, continuing the retry loop within budget -- never propagate uncaught
    and skip attempt.json/episode.json entirely, as it did before the fix."""
    import subprocess as sp
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_result = _eligible_probe()
    probe_paths = _materialize_probe(probe_result, tmp_path)
    call_count = [0]

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        call_count[0] += 1
        if call_count[0] == 1:
            raise sp.TimeoutExpired(cmd="semgrep", timeout=120)
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=probe_result, probe_paths=probe_paths, scan_probe_fn=scan_probe_fn)

    # Both attempts' records must exist -- the exception must never skip attempt.json/episode.json.
    assert (tmp_path / "out" / "CASE-TEST" / "attempt_1" / "attempt.json").exists()
    assert (tmp_path / "out" / "CASE-TEST" / "episode.json").exists()
    assert len(episode["attempts"]) == 2
    assert "timed out" in episode["attempts"][0]["probe_evaluation"]["error"]
    assert "development-time test case" in episode["attempts"][0]["feedback"]
    assert episode["final_rule_path"] is not None  # recovered on the second attempt, budget preserved
    assert episode["resource_accounting"]["repair_calls"] == 1  # no reset: exactly one repair consumed


# --------------------------------------------------------------------------------------------
# CD_Materialization_Followup_Review_20261013.md -- the startup-only check verified the files
# ONCE, before the retry loop, which cannot catch the file changing afterward, and compared
# `read_text()` (newline-normalizing) instead of raw bytes. All three reproduced directly before
# the fix: changed-during-generation, changed-between-attempts, and CRLF-vs-LF hash disagreement.
# --------------------------------------------------------------------------------------------


def test_materialization_change_during_generation_does_not_reach_the_scanner(monkeypatch, tmp_path):
    """Direct reproduction: the ORIGINAL caller-supplied probe file changing during the mocked
    generation call (before the first scan) must have NO effect on what gets scanned -- the
    function must freeze its own verified snapshot before `load_case`/generation ever runs."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_result = _eligible_probe()
    vuln_path, patched_path = _materialize_probe(probe_result, tmp_path)
    seen = []

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        seen.append(Path(vp).read_bytes())
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    def generate(patch, error_feedback=None):
        vuln_path.write_text("def f(): return 999\n")  # tamper the ORIGINAL file mid-generation
        return rule()

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=generate, last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=probe_result, probe_paths=(vuln_path, patched_path), scan_probe_fn=scan_probe_fn)

    assert seen[0] == probe_result.vulnerable_probe.encode()  # scanned the FROZEN snapshot, not the tampered original
    assert episode["final_rule_path"] is not None


def test_materialization_change_between_attempts_does_not_reach_the_scanner(monkeypatch, tmp_path):
    """Direct reproduction: the ORIGINAL caller-supplied probe file changing BETWEEN attempt 1 and
    attempt 2 must have NO effect on attempt 2's scan, and the episode's verified_probe_hashes
    must remain consistent with what was ACTUALLY scanned both times, never silently stale."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_result = _eligible_probe()
    vuln_path, patched_path = _materialize_probe(probe_result, tmp_path)
    call_count = [0]
    seen = []

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        call_count[0] += 1
        seen.append(Path(vp).read_bytes())
        if call_count[0] == 1:
            vuln_path.write_text("def f(): return 999\n")  # tamper the ORIGINAL file between attempts
            return {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False}
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=probe_result, probe_paths=(vuln_path, patched_path), scan_probe_fn=scan_probe_fn)

    assert seen[0] == seen[1] == probe_result.vulnerable_probe.encode()  # both attempts scanned the SAME frozen bytes
    expected_hash = hashlib.sha256(probe_result.vulnerable_probe.encode()).hexdigest()
    assert episode["verified_probe_hashes"]["vulnerable_probe_sha256"] == expected_hash


def test_materialization_rejects_crlf_bytes_that_read_text_would_normalize(monkeypatch, tmp_path):
    """Direct reproduction: a probe file written with CRLF line endings must be rejected, even
    though `Path.read_text()` would silently normalize it to match the expected (LF) string --
    the comparison must use raw bytes, never a newline-normalizing read."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    probe_result = ProbeResult(case_id="CASE-TEST", language="python", old_name="token", new_name="token_renamed",
                                vulnerable_probe="def f():\n    return token_renamed\n",
                                patched_probe="def f():\n    return token_renamed\n", patched_probe_renamed=True)
    probe_dir = tmp_path / "_dev_probes" / probe_result.case_id
    probe_dir.mkdir(parents=True)
    vuln_path = probe_dir / "vulnerable_probe.py"
    patched_path = probe_dir / "patched_probe.py"
    crlf_bytes = probe_result.vulnerable_probe.replace("\n", "\r\n").encode()
    assert crlf_bytes != probe_result.vulnerable_probe.encode()  # sanity: the test fixture is genuinely CRLF
    vuln_path.write_bytes(crlf_bytes)
    patched_path.write_text(probe_result.patched_probe)

    with pytest.raises(diagnostic.ProbeMaterializationError):
        diagnostic.run_model_case_cd(
            "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
            config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
            condition="D", probe_result=probe_result, probe_paths=(vuln_path, patched_path),
            scan_probe_fn=lambda *a, **kw: {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False})


# --------------------------------------------------------------------------------------------
# CD_Snapshot_Review_20261013.md -- same-basename inputs from different directories silently
# overwrote one snapshot side, and an integrity-check-skipped attempt was still counted as a
# scanner invocation. Both reproduced directly before the fix.
# --------------------------------------------------------------------------------------------


def test_finding1_same_basename_different_directories_does_not_collide(monkeypatch, tmp_path):
    """Direct reproduction: vulnerable and patched probe inputs sharing a basename
    (`function.py`) in DIFFERENT source directories must not collide in the snapshot -- before
    the fix, the second write silently overwrote the first, so the scanner always saw the
    patched content for BOTH roles and every attempt failed its own integrity check."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_result = ProbeResult(case_id="CASE-TEST", language="python", old_name="token", new_name="token_renamed",
                                vulnerable_probe="def f(): return 1\n", patched_probe="def f(): return 2\n",
                                patched_probe_renamed=True)
    vuln_dir = tmp_path / "input_vulnerable"
    patched_dir = tmp_path / "input_patched"
    vuln_dir.mkdir()
    patched_dir.mkdir()
    vuln_path = vuln_dir / "function.py"   # SAME basename as the patched input below
    patched_path = patched_dir / "function.py"
    vuln_path.write_text(probe_result.vulnerable_probe)
    patched_path.write_text(probe_result.patched_probe)
    seen = []

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        seen.append((Path(vp).read_text(), Path(pp).read_text()))
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=probe_result, probe_paths=(vuln_path, patched_path), scan_probe_fn=scan_probe_fn)

    assert seen == [(probe_result.vulnerable_probe, probe_result.patched_probe)]  # neither side overwritten
    assert episode["final_rule_path"] is not None


def test_finding2_integrity_failure_reports_zero_scans_not_one(monkeypatch, tmp_path):
    """Direct reproduction: when the defensive snapshot integrity check fails (so
    `scan_probe_fn` is deliberately never called), `resource_accounting.probe_scans` must report
    ZERO for that attempt, not one -- before the fix, every attempt incremented the scan count
    regardless of whether the scanner was actually invoked."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    probe_result = _eligible_probe()
    vuln_path, patched_path = _materialize_probe(probe_result, tmp_path)
    scan_calls = []

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        scan_calls.append(1)
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    def generate(patch, error_feedback=None):
        # Corrupt the snapshot directly (bypassing this function's own write) to force the
        # defensive drift branch on every attempt -- scan_probe_fn must never be reached.
        snapshot_dir = tmp_path / "out" / "CASE-TEST" / "_probe_snapshot"
        if snapshot_dir.exists():
            for f in snapshot_dir.rglob("*.py"):
                f.write_text("corrupted")
        return rule()

    episode = diagnostic.run_model_case_cd(
        "CASE-TEST", NS(generate_rule=generate, last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=_manifest(), ann={}, out=tmp_path / "out",
        condition="D", probe_result=probe_result, probe_paths=(vuln_path, patched_path), scan_probe_fn=scan_probe_fn)

    assert scan_calls == []  # the scanner must never actually be invoked
    assert episode["resource_accounting"]["probe_scans"] == 0  # not 3 -- zero actual scans occurred
    assert episode["final_rule_path"] is None  # every attempt correctly failed its probe check
