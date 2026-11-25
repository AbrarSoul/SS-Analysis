"""Offline review reproductions, not production tests or inference. Temporary caches only."""
import hashlib
import importlib.metadata
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
import combined_gate as gate
import dev_probe as dp
import diagnostic_v2 as dv2
import probe_cache as cache


def main():
    evidence = {"model_calls": 0, "real_semgrep_scans": 0, "findings": {}}
    findings = evidence["findings"]
    with tempfile.TemporaryDirectory(prefix="cd_gate_cache_review_") as tmp:
        base = Path(tmp)
        source = "def f():\n    token = 1\n    return token\n"
        original, status = cache.get_or_build_probe("AUDIT-PAYLOAD", "python", source, source, base)
        assert isinstance(original, dp.ProbeResult)
        entry_path = base / "AUDIT-PAYLOAD" / "probe_cache.json"
        entry = json.loads(entry_path.read_text())
        entry["payload"]["fields"]["vulnerable_probe"] = "def f():\n    return 999\n"
        entry_path.write_text(json.dumps(entry))
        changed, status = cache.get_or_build_probe("AUDIT-PAYLOAD", "python", source, source, base, strict=True)
        assert status == "hit" and changed.vulnerable_probe != original.vulnerable_probe
        findings["unchecked_payload"] = {"status": status, "strict": True,
            "original": original.vulnerable_probe, "returned": changed.vulnerable_probe}

        js = "function f() { let token = 1; return token; }"
        first, _ = cache.get_or_build_probe("AUDIT-LANGUAGE", "javascript", js, js, base)
        second, status = cache.get_or_build_probe("AUDIT-LANGUAGE", "typescript", js, js, base, strict=True)
        fresh = dp.build_probe("AUDIT-LANGUAGE", "typescript", js, js)
        assert isinstance(first, dp.ProbeResult) and isinstance(fresh, dp.ProbeResult)
        assert status == "hit" and second.language == "javascript" and fresh.language == "typescript"
        findings["language_not_in_key"] = {"status": status, "requested": "typescript",
            "returned": second.language, "fresh_builder": fresh.language,
            "key_fields": sorted(cache.cache_key(js, js))}

        new, status = cache.get_or_build_probe("UNREVIEWED-CASE", "python", source, source, base, strict=True)
        assert status == "miss_built" and isinstance(new, dp.ProbeResult)
        findings["strict_is_not_reviewed_manifest_enforcement"] = {"status": status, "case_id": new.case_id,
            "explanation": "Strict mode builds unseen cases; there is no reviewed input/artifact allowlist."}

        # Execute the existing runner, substituting every model/scanner dependency.
        calls = []
        scans = []
        def generate_rule(*args, **kwargs):
            calls.append(kwargs)
            return None if len(calls) == 1 else {"id": "offline-audit", "pattern": "foo()"}
        def scan(*args, **kwargs):
            scans.append({"hidden": kwargs["hidden"]})
            return {"visible_correct": True, "legacy_accepted": True, "scan_ok": True, "errors": [], "samples": []}
        recorder = SimpleNamespace(begin_case=lambda cid: None, raw_dir=base / "raw", retries_dir=base / "retries")
        with patch.object(dv2, "load_case", return_value={}), patch.object(dv2, "scan", side_effect=scan):
            episode = dv2.run_model_case("AUDIT-ACCOUNTING", SimpleNamespace(generate_rule=generate_rule,
                last_error="synthetic decode error"), None, recorder, {}, {}, base / "runner", "corrected")
        decisions = [gate.combined_decision(condition="B", attempt=a["attempt"], max_attempts=3,
            visible_correct=bool(a["visible_evaluation"] and a["visible_evaluation"]["visible_correct"]),
            probe_eligible=False) for a in episode["attempts"]]
        actual = {"model_calls": len(calls), "visible_scans": sum(not s["hidden"] for s in scans), "repair_calls": len(calls)-1}
        counted = gate.summarize_episode_resources(decisions)
        assert actual["visible_scans"] == 1 and counted["visible_scans"] == 2
        findings["decision_count_is_not_scan_count"] = {"actual_mocked_runner_events": actual,
            "reported": counted, "if_unparsed_attempt_omitted": gate.summarize_episode_resources(decisions[1:])}

    ok = {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}
    checks = gate.evaluate_probe_pair(ok, ok)
    over = gate.combined_decision(condition="C", attempt=4, max_attempts=3,
        visible_correct=True, probe_eligible=True, probe_checks=checks)
    unknown = gate.combined_decision(condition="TYPO", attempt=1, max_attempts=3,
        visible_correct=True, probe_eligible=True)
    assert over.accept and unknown.accept
    evidence["boundary_hardening_observations"] = {"over_budget_pass": asdict(over),
        "unknown_condition_pass": asdict(unknown),
        "limit": "Current real runner bounds attempts with range(1,4); no actual budget overrun demonstrated."}
    failed_fallback = gate.combined_decision(condition="C", attempt=3, max_attempts=3,
        visible_correct=False, probe_eligible=False)
    assert not failed_fallback.is_fallback
    evidence["integration_metadata_requirement"] = {"failed_ineligible_decision": asdict(failed_fallback),
        "requirement": "Record eligibility and rejection reason separately for ALL episodes, not only accepted fallback decisions."}
    evidence["versions"] = {"python": sys.version, **{n: importlib.metadata.version(n) for n in
        ("tree_sitter", "tree_sitter_java", "tree_sitter_javascript", "tree_sitter_typescript")}}
    paths = ["pipeline/combined_gate.py", "pipeline/probe_cache.py", "pipeline/dev_probe.py",
        "pipeline/diagnostic_v2.py", "pipeline/tests/test_combined_gate.py"]
    evidence["reviewed_sha256"] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    output = Path(__file__).with_name("CD_Gate_Cache_Review_Evidence_20261013.json")
    if output.exists():
        raise FileExistsError(f"Preserve existing evidence: {output}")
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
