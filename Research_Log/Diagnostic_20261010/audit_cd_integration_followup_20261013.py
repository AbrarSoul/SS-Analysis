"""Bounded offline follow-up: temporary caches/files, fake generation/scanning only."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
import probe_cache as pc
import diagnostic_v2 as dv
from dev_probe import ProbeResult


def main():
    evidence = {"real_model_calls": 0, "real_semgrep_scans": 0, "closed_findings": {}, "new_reproductions": {}}
    with tempfile.TemporaryDirectory(prefix="cd_followup_") as tmp:
        base = Path(tmp)
        cid = "AUDIT-CD"
        src = "def f():\n    token = 1\n    return token\n"
        manifest = {cid: pc.build_experiment_manifest_entry(cid, "python", src, src)}
        probe, _ = pc.load_probe_for_experiment(cid, "python", src, src, base / "cache", manifest)
        cache_path = base / "cache" / cid / "probe_cache.json"
        original = cache_path.read_text()
        entry = json.loads(original)
        entry["payload"]["fields"]["vulnerable_probe"] = "def f(): return 999\n"
        cache_path.write_text(json.dumps(entry))
        try:
            pc.get_or_build_probe(cid, "python", src, src, base / "cache", strict=True)
        except pc.CacheMismatchError:
            evidence["closed_findings"]["payload_mutation_rejected"] = True
        else:
            raise AssertionError("payload mutation was accepted")
        # Even recomputing the cache-local digest must not bypass the external manifest.
        entry["payload_sha256"] = pc._sha256_obj(entry["payload"])
        cache_path.write_text(json.dumps(entry))
        try:
            pc.load_probe_for_experiment(cid, "python", src, src, base / "cache", manifest)
        except pc.ExperimentManifestError:
            evidence["closed_findings"]["self_consistent_wrong_payload_rejected_by_manifest"] = True
        else:
            raise AssertionError("manifest did not reject altered text")
        cache_path.write_text(original)
        for label, kwargs in [("language", {"language": "javascript"}), ("parser", {})]:
            if label == "language":
                try:
                    pc.get_or_build_probe(cid, kwargs["language"], src, src, base / "cache", strict=True)
                except pc.CacheMismatchError:
                    evidence["closed_findings"]["language_drift_rejected"] = True
                else:
                    raise AssertionError("language drift accepted")
            else:
                versions = {**pc.parser_versions(), "python": "synthetic-different-version"}
                with patch.object(pc, "parser_versions", return_value=versions):
                    try:
                        pc.load_probe_for_experiment(cid, "python", src, src, base / "cache", manifest)
                    except pc.ExperimentManifestError:
                        evidence["closed_findings"]["parser_drift_rejected"] = True
                    else:
                        raise AssertionError("parser drift accepted")

        probe_dir = base / "materialized"
        probe_dir.mkdir()
        vp, pp = probe_dir / "vulnerable.py", probe_dir / "patched.py"
        vp.write_text(probe.vulnerable_probe)
        pp.write_text(probe.patched_probe)
        vp.write_text("def f(): return 999\n")  # A stale/changed materialization, not the validated probe.

        def run(label, probe_arg, scanner, decode_first=False):
            calls, scans = [], []
            def generate(*args, **kwargs):
                calls.append(kwargs)
                if decode_first and len(calls) == 1:
                    return None
                return {"id": "offline-audit", "pattern": "foo()"}
            def visible_scan(*args, **kwargs):
                scans.append(kwargs["hidden"])
                return {"scan_ok": True, "visible_correct": True, "legacy_accepted": True,
                        "errors": [], "samples": [], "complete_success": True}
            out = base / label
            rec = NS(begin_case=lambda _: None, raw_dir=base / "raw", retries_dir=base / "retries")
            with patch.object(dv, "load_case", return_value=object()), patch.object(dv, "scan", side_effect=visible_scan):
                try:
                    episode = dv.run_model_case_cd(cid, NS(generate_rule=generate, last_error="synthetic decode error"),
                        NS(), rec, {}, {}, out, "C", probe_arg, (vp, pp), scanner)
                except subprocess.TimeoutExpired:
                    return {"raised": "TimeoutExpired", "generation_calls": len(calls),
                            "attempt_record_exists": (out / cid / "attempt_1/attempt.json").exists(),
                            "episode_record_exists": (out / cid / "episode.json").exists()}
            return {"episode": episode, "generation_calls": len(calls), "visible_scans": scans.count(False)}

        observed = []
        def passing_scanner(rule, vulnerable, patched, out):
            observed.append(vulnerable.read_text())
            return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}
        result = run("unbound_files", probe, passing_scanner)
        assert observed[-1] != probe.vulnerable_probe and result["episode"]["final_rule_path"]
        evidence["new_reproductions"]["validated_object_unbound_to_scanned_files"] = {
            "validated_text": probe.vulnerable_probe, "scanner_received_text": observed[-1],
            "accepted_under_mocked_passing_scan": True}

        def must_not_scan(*args):
            raise AssertionError("unexpected probe scan")
        result = run("none_fallback", None, must_not_scan)
        assert result["episode"]["final_rule_path"] and result["episode"]["probe_fallback_used"]
        evidence["new_reproductions"]["missing_probe_resolution_becomes_fallback"] = {
            "probe_argument": None, "generation_calls": result["generation_calls"],
            "probe_eligible": result["episode"]["probe_eligible"], "probe_fallback_used": True}

        result = run("accounting", probe, passing_scanner, decode_first=True)
        resources = result["episode"]["resource_accounting"]
        assert resources == {"generation_calls": 2, "visible_scans": 1, "probe_scans": 1, "repair_calls": 1}
        assert result["visible_scans"] == 1
        evidence["closed_findings"]["decode_failure_accounting"] = resources

        def timeout(*args):
            raise subprocess.TimeoutExpired("synthetic-semgrep", 120)
        result = run("timeout", probe, timeout)
        assert result == {"raised": "TimeoutExpired", "generation_calls": 1,
                          "attempt_record_exists": False, "episode_record_exists": False}
        evidence["integration_requirements"] = {"probe_timeout": result,
            "limit": "Synthetic backend exception; no real timeout or inference. RawCapture may independently retain the call; runner writes no attempt/episode status."}

    # New process: establish that importing the A/B runner now imports the probe module.
    code = "import sys; sys.path.insert(0, 'pipeline'); import diagnostic_v2; print('dev_probe' in sys.modules)"
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert proc.stdout.strip() == "True"
    evidence["new_reproductions"]["ab_import_loads_probe_module"] = True
    blocked_code = """import sys, importlib.abc
sys.path.insert(0, 'pipeline')
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('tree_sitter'):
            raise ModuleNotFoundError('synthetic absent probe dependency: ' + fullname)
sys.meta_path.insert(0, Block())
import diagnostic_v2
"""
    proc = subprocess.run([sys.executable, "-c", blocked_code], cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode != 0 and "synthetic absent probe dependency" in proc.stderr
    evidence["new_reproductions"]["ab_import_fails_without_probe_dependencies"] = {"returncode": proc.returncode,
        "error": proc.stderr.splitlines()[-1]}
    paths = ["pipeline/combined_gate.py", "pipeline/probe_cache.py", "pipeline/diagnostic_v2.py",
             "pipeline/dev_probe.py", "pipeline/tests/test_combined_gate.py", "pipeline/tests/test_run_model_case_cd.py"]
    evidence["reviewed_sha256"] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    output = Path(__file__).with_name("CD_Integration_Followup_Evidence_20261013.json")
    with output.open("x") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
