"""Offline checks of C/D fixes and the remaining materialization boundary; no real scans."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
import diagnostic_v2 as dv
from dev_probe import ProbeResult, ProbeIneligible


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    evidence = {"real_model_calls": 0, "real_semgrep_scans": 0, "verified_fixes": {}, "remaining_gap": {}}
    suite = ["pipeline/tests/" + name for name in ("test_combined_gate.py", "test_run_model_case_cd.py",
        "test_diagnostic_regressions.py", "test_dev_probe.py", "test_typed_json_construction.py", "test_typed_rule.py")]
    collect = subprocess.run([sys.executable, "-m", "pytest", *suite, "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True, check=True)
    count = re.search(r"(\d+) tests collected", collect.stdout)
    assert count, collect.stdout
    evidence["collection"] = {"count": int(count.group(1)), "files": suite, "summary": collect.stdout.strip().splitlines()[-1],
        "scope": "Collection only, not full-suite execution. Independently executed 70 focused tests."}
    with tempfile.TemporaryDirectory(prefix="cd_materialization_review_") as tmp:
        base = Path(tmp)
        cid = "AUDIT-CD"
        text = "def f():\n    token_renamed = 1\n    return token_renamed\n"
        probe = ProbeResult(cid, "python", "token", "token_renamed", text, text, True)

        def run(label, mode, probe_arg=probe):
            case_dir = base / label
            case_dir.mkdir()
            vp, pp = case_dir / "vulnerable.py", case_dir / "patched.py"
            vp.write_bytes(text.encode())
            pp.write_bytes(text.encode())
            if mode == "prechanged":
                vp.write_text("def f(): return 999\n")
            if mode == "crlf":
                vp.write_bytes(text.replace("\n", "\r\n").encode())
            generated, scanned, hidden = [], [], []
            def generate(*args, **kwargs):
                generated.append(kwargs)
                if mode == "changed_during_generation":
                    vp.write_text("def f(): return 999\n")
                return None if mode == "decode_fail" else {"id": "audit", "pattern": "foo()"}
            def visible_scan(*args, **kwargs):
                hidden.append(kwargs["hidden"])
                return {"scan_ok": True, "visible_correct": True, "legacy_accepted": True,
                    "complete_success": True, "errors": [], "samples": []}
            def probe_scan(rule, vuln, patched, out):
                scanned.append(digest(Path(vuln).read_bytes()))
                if mode == "timeout":
                    raise subprocess.TimeoutExpired("synthetic-semgrep", 120)
                if mode == "changed_between_attempts" and len(scanned) == 1:
                    vp.write_text("def f(): return 999\n")
                    return {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False}
                return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}
            rec = NS(begin_case=lambda _: None, raw_dir=case_dir / "raw", retries_dir=case_dir / "retries")
            with patch.object(dv, "load_case", return_value=object()), patch.object(dv, "scan", side_effect=visible_scan):
                try:
                    episode = dv.run_model_case_cd(cid, NS(generate_rule=generate, last_error="synthetic decode error"),
                        NS(), rec, {cid: {"language": "python"}}, {}, case_dir / "out", "D", probe_arg,
                        (vp, pp), probe_scan)
                except (ValueError, dv.ProbeMaterializationError) as exc:
                    return {"exception": type(exc).__name__, "generation_calls": len(generated), "probe_scans": len(scanned)}
            return {"accepted": episode["final_rule_path"] is not None, "generation_calls": len(generated),
                "resources": episode["resource_accounting"], "recorded_hashes": episode["verified_probe_hashes"],
                "scanner_input_hashes": scanned, "final_disk_hash": digest(vp.read_bytes()),
                "ineligible_reason": episode["probe_ineligible_reason"],
                "attempt_records": sum((case_dir / "out" / cid / f"attempt_{i}" / "attempt.json").exists() for i in range(1,4)),
                "episode_record_exists": (case_dir / "out" / cid / "episode.json").exists()}

        pre = run("prechanged", "prechanged")
        assert pre == {"exception": "ProbeMaterializationError", "generation_calls": 0, "probe_scans": 0}
        evidence["verified_fixes"]["preexisting_file_mismatch_rejected"] = pre
        unresolved = run("none", "normal", None)
        assert unresolved == {"exception": "ValueError", "generation_calls": 0, "probe_scans": 0}
        evidence["verified_fixes"]["unresolved_state_rejected"] = unresolved
        wrong = ProbeIneligible(cid, "javascript", "synthetic reason")
        wrong_result = run("wrong_language", "normal", wrong)
        assert wrong_result["exception"] == "ValueError" and wrong_result["generation_calls"] == 0
        evidence["verified_fixes"]["wrong_language_rejected"] = wrong_result
        failed = run("failed_ineligible", "decode_fail", ProbeIneligible(cid, "python", "no eligible local"))
        assert not failed["accepted"] and failed["generation_calls"] == 3 and failed["ineligible_reason"] == "no eligible local"
        evidence["verified_fixes"]["reason_preserved_on_all_decode_failures"] = failed
        timeout = run("timeout", "timeout")
        assert not timeout["accepted"] and timeout["generation_calls"] == 3 and timeout["attempt_records"] == 3
        assert timeout["episode_record_exists"] and timeout["resources"]["probe_scans"] == 3
        evidence["verified_fixes"]["three_timeouts_recorded_within_budget"] = timeout

        for mode in ("changed_during_generation", "changed_between_attempts", "crlf"):
            result = run(mode, mode)
            assert result["accepted"]
            assert result["recorded_hashes"]["vulnerable_probe_sha256"] != result["scanner_input_hashes"][-1]
            evidence["remaining_gap"][mode] = result

    script = """import sys, importlib.abc
sys.path.insert(0, 'pipeline')
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'dev_probe' or fullname.startswith('tree_sitter'):
            raise ModuleNotFoundError('probe imports prohibited: ' + fullname)
sys.meta_path.insert(0, Block())
import diagnostic_v2
assert 'dev_probe' not in sys.modules
assert 'tree_sitter' not in sys.modules
print('A/B import isolation verified with probe imports prohibited')
"""
    proc = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, check=True)
    evidence["verified_fixes"]["ab_import_isolation"] = proc.stdout.strip()
    paths = ["pipeline/diagnostic_v2.py", "pipeline/tests/test_run_model_case_cd.py", "pipeline/probe_cache.py",
        "pipeline/combined_gate.py", "pipeline/dev_probe.py"]
    evidence["reviewed_sha256"] = {p: digest((ROOT / p).read_bytes()) for p in paths}
    output = Path(__file__).with_name("CD_Materialization_Followup_Evidence_20261013.json")
    with output.open("x") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
