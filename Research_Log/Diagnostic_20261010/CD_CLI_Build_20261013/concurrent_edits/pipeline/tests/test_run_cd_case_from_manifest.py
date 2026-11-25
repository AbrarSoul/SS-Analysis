"""
Offline tests for diagnostic_v2.run_cd_case_from_manifest() -- the complete C/D per-case path
(frozen-manifest resolution -> probe materialization -> run_model_case_cd() -> episode), factored
out of main()'s --use-probes loop specifically so this full path is directly testable without
real model calls, real Semgrep scans, or live API credentials.

This is the bounded C/D infrastructure task's completion criterion 3: "Verify the complete path
offline, covering acceptance, repair, exhaustion, ineligible fallback, and scan errors -- with
accurate provenance and resource counts." Uses the REAL frozen manifest
(Research_Log/Diagnostic_20261010/CD_Probe_Manifest_v1_20261013.json) and REAL benchmark/
model_context case data for two real cases (one eligible, one not), plus synthetic manifests for
the scenarios the real 24-case set doesn't happen to exercise (e.g. forcing a scan error).
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]
import diagnostic_v2 as diagnostic
from probe_cache import build_experiment_manifest_entry, ExperimentManifestError
from dev_probe import ProbeResult

REAL_MANIFEST_PATH = ROOT / "Research_Log/Diagnostic_20261010/CD_Probe_Manifest_v1_20261013.json"


def _real_manifest_entries():
    return json.loads(REAL_MANIFEST_PATH.read_text())["entries"]


def rule():
    return {"id": "x", "message": "m", "severity": "ERROR", "languages": ["python"], "pattern": "sink($X)"}


def _visible_eval(**overrides):
    base = {
        "scan_ok": True, "returncode": 0, "all_targets_scanned": True, "errors": [],
        "legacy_accepted": True, "visible_correct": True, "complete_success": False,
        "samples": [
            {"sample_type": "original_vulnerable", "label": "positive", "detected": True,
             "finding_location_correct": True, "finding_lines": [1], "outcome": "TP"},
            {"sample_type": "original_patched", "label": "negative", "detected": False,
             "finding_location_correct": None, "finding_lines": [], "outcome": "TN"},
        ],
    }
    base.update(overrides)
    return base


class _FakeRecorder:
    def __init__(self, tmp_path):
        self.raw_dir = tmp_path / "raw"
        self.retries_dir = tmp_path / "retries"
        self.raw_dir.mkdir()
        self.retries_dir.mkdir()

    def begin_case(self, cid):
        pass


def _manifest_for(cid, language, vulnerable_lines=(1, 1)):
    return {cid: {"language": language, "vulnerable_lines": list(vulnerable_lines)}}


# --------------------------------------------------------------------------------------------
# Against the REAL frozen manifest and REAL benchmark/model_context data
# --------------------------------------------------------------------------------------------


def test_real_eligible_case_full_acceptance_path(monkeypatch, tmp_path):
    """CASE-0046 is a real, eligible (Python) case in the frozen manifest. A rule that passes
    visible AND the probe on the first attempt must accept and stop, with accurate provenance."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    manifest = _manifest_for("CASE-0046", "python")

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}

    episode = diagnostic.run_cd_case_from_manifest(
        "CASE-0046", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=manifest, ann={}, out=tmp_path / "out",
        condition="D", probe_manifest_entries=_real_manifest_entries(), scan_probe_fn=scan_probe_fn)

    assert episode["final_rule_path"] is not None
    assert episode["probe_eligible"] is True
    assert episode["probe_cache_status"] == "miss_built"
    assert episode["resource_accounting"]["generation_calls"] == 1


def test_real_ineligible_case_falls_back_correctly(monkeypatch, tmp_path):
    """CASE-0063 is a real case in the frozen manifest whose vulnerable_function does not parse
    cleanly -- a reviewed, recorded ineligibility, not an unresolved state. The episode must
    accept on visible alone and record the real reason from the manifest."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    manifest = _manifest_for("CASE-0063", "javascript")

    episode = diagnostic.run_cd_case_from_manifest(
        "CASE-0063", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
        config=NS(), recorder=_FakeRecorder(tmp_path), manifest=manifest, ann={}, out=tmp_path / "out",
        condition="C", probe_manifest_entries=_real_manifest_entries(),
        scan_probe_fn=lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must never be called")))

    assert episode["final_rule_path"] is not None  # accepted on visible alone
    assert episode["probe_eligible"] is False
    assert episode["probe_fallback_used"] is True
    assert episode["probe_ineligible_reason"] == "vulnerable_function does not parse cleanly"


def test_case_missing_from_manifest_raises(tmp_path):
    """A case requested that is not in the frozen manifest must raise immediately -- 'a changed
    or additional case may be built offline for review, but must not automatically inherit the
    old review.'"""
    with pytest.raises(ExperimentManifestError):
        diagnostic.run_cd_case_from_manifest(
            "CASE-NOT-IN-MANIFEST", NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None),
            config=NS(), recorder=_FakeRecorder(tmp_path), manifest=_manifest_for("CASE-NOT-IN-MANIFEST", "python"),
            ann={}, out=tmp_path / "out", condition="C", probe_manifest_entries=_real_manifest_entries(),
            vulnerable_function="def f(): pass\n", patched_function="def f(): pass\n")


# --------------------------------------------------------------------------------------------
# Synthetic manifests covering the remaining required scenarios: repair, exhaustion, scan error
# --------------------------------------------------------------------------------------------


def _synthetic_eligible_manifest(cid="CASE-SYN", language="python"):
    vuln = "def f():\n    token = 1\n    return token\n"
    entry = build_experiment_manifest_entry(cid, language, vuln, vuln)
    return {cid: entry}, vuln


def test_repair_then_accept_through_complete_path(monkeypatch, tmp_path):
    """A probe failure on attempt 1, then a pass on attempt 2 -- feedback must reach the second
    generate_rule() call, and the episode must accept with correct resource accounting, all
    through the COMPLETE path (manifest resolution through episode completion)."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    manifest_entries, vuln_src = _synthetic_eligible_manifest()
    cid = next(iter(manifest_entries))
    manifest = _manifest_for(cid, "python")
    feedback_seen = []

    def generate(patch, error_feedback=None):
        feedback_seen.append(error_feedback)
        return rule()

    call_count = [0]

    def scan_probe_fn(rule_path, vp, pp, out_dir):
        call_count[0] += 1
        return {"scan_ok": True, "vulnerable_detected": call_count[0] >= 2, "patched_detected": False}

    episode = diagnostic.run_cd_case_from_manifest(
        cid, NS(generate_rule=generate, last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=manifest, ann={}, out=tmp_path / "out",
        condition="D", probe_manifest_entries=manifest_entries, scan_probe_fn=scan_probe_fn,
        vulnerable_function=vuln_src, patched_function=vuln_src)

    assert len(episode["attempts"]) == 2
    assert feedback_seen[0] is None
    assert "additional development-time test case" in feedback_seen[1]
    assert episode["final_rule_path"] is not None
    assert episode["resource_accounting"] == {"generation_calls": 2, "visible_scans": 2, "probe_scans": 2, "repair_calls": 1}


def test_budget_exhaustion_through_complete_path(monkeypatch, tmp_path):
    """A probe that never passes must exhaust the 3-attempt budget without ever accepting,
    through the complete path."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    manifest_entries, vuln_src = _synthetic_eligible_manifest()
    cid = next(iter(manifest_entries))
    manifest = _manifest_for(cid, "python")

    episode = diagnostic.run_cd_case_from_manifest(
        cid, NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=manifest, ann={}, out=tmp_path / "out",
        condition="D", probe_manifest_entries=manifest_entries,
        scan_probe_fn=lambda *a, **kw: {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False},
        vulnerable_function=vuln_src, patched_function=vuln_src)

    assert len(episode["attempts"]) == 3
    assert episode["final_rule_path"] is None
    assert episode["resource_accounting"]["generation_calls"] == 3


def test_scan_error_through_complete_path_never_becomes_a_fallback(monkeypatch, tmp_path):
    """A probe scan error (scan_ok=False) must repair through to exhaustion, never silently
    treated as an ineligibility fallback, through the complete path."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _visible_eval())
    manifest_entries, vuln_src = _synthetic_eligible_manifest()
    cid = next(iter(manifest_entries))
    manifest = _manifest_for(cid, "python")

    episode = diagnostic.run_cd_case_from_manifest(
        cid, NS(generate_rule=lambda patch, error_feedback=None: rule(), last_error=None), config=NS(),
        recorder=_FakeRecorder(tmp_path), manifest=manifest, ann={}, out=tmp_path / "out",
        condition="D", probe_manifest_entries=manifest_entries,
        scan_probe_fn=lambda *a, **kw: {"scan_ok": False, "error": "synthetic scan error"},
        vulnerable_function=vuln_src, patched_function=vuln_src)

    assert episode["final_rule_path"] is None
    assert episode["probe_fallback_used"] is False  # never collapsed into a fallback
    assert len(episode["attempts"]) == 3
    assert episode["attempts"][0]["probe_evaluation"]["error"] == "synthetic scan error"
