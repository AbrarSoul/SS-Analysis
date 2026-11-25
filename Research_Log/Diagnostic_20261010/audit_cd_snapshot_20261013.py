"""Snapshot follow-up with fake generation/scanning and temporary real files only."""
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
from dev_probe import ProbeResult


def main():
    evidence = {"real_model_calls": 0, "real_semgrep_scans": 0, "scenarios": {}}
    with tempfile.TemporaryDirectory(prefix="cd_snapshot_review_") as tmp:
        for mode in ("normal", "original_during_generation", "original_between_attempts", "crlf", "same_basename", "snapshot_drift"):
            root = Path(tmp) / mode
            vulnerable = root / "input_vulnerable" / ("function.py" if mode == "same_basename" else "vulnerable.py")
            patched = root / "input_patched" / ("function.py" if mode == "same_basename" else "patched.py")
            vulnerable.parent.mkdir(parents=True)
            patched.parent.mkdir(parents=True)
            vp = b"def f():\n    token_renamed = 1\n    return token_renamed\n"
            pp = b"def f():\n    token_renamed = 2\n    return token_renamed\n"
            vulnerable.write_bytes(vp.replace(b"\n", b"\r\n") if mode == "crlf" else vp)
            patched.write_bytes(pp)
            probe = ProbeResult("AUDIT", "python", "token", "token_renamed", vp.decode(), pp.decode(), True)
            out = root / "out"
            calls, observed = [], []
            def generate(*args, **kwargs):
                calls.append(kwargs)
                if mode == "original_during_generation":
                    vulnerable.write_bytes(b"def f(): return 999\n")
                if mode == "snapshot_drift":
                    (out / "AUDIT/_probe_snapshot/vulnerable.py").write_bytes(b"def f(): return 999\n")
                return {"id": "audit", "pattern": "foo()"}
            def scan_probe(rule, vpath, ppath, scan_out):
                assert vpath != vulnerable and ppath != patched
                assert vpath.read_bytes() == vp and ppath.read_bytes() == pp
                observed.append({"vulnerable_sha256": hashlib.sha256(vpath.read_bytes()).hexdigest(),
                                 "patched_sha256": hashlib.sha256(ppath.read_bytes()).hexdigest()})
                if mode == "original_between_attempts" and len(observed) == 1:
                    vulnerable.write_bytes(b"def f(): return 999\n")
                    return {"scan_ok": True, "vulnerable_detected": False, "patched_detected": False}
                return {"scan_ok": True, "vulnerable_detected": True, "patched_detected": False}
            evaluation = {"scan_ok": True, "visible_correct": True, "legacy_accepted": True,
                          "complete_success": True, "samples": [], "errors": []}
            recorder = NS(begin_case=lambda _: None, raw_dir=root / "raw", retries_dir=root / "retries")
            with patch.object(dv, "load_case", return_value=object()), patch.object(dv, "scan", return_value=evaluation):
                try:
                    episode = dv.run_model_case_cd("AUDIT", NS(generate_rule=generate, last_error=None), NS(),
                        recorder, {"AUDIT": {"language": "python"}}, {}, out, "C", probe,
                        (vulnerable, patched), scan_probe)
                except dv.ProbeMaterializationError:
                    assert mode == "crlf" and not calls and not observed
                    evidence["scenarios"][mode] = {"rejected_before_generation": True}
                    continue
            row = {"accepted": episode["final_rule_path"] is not None, "generation_calls": len(calls),
                   "actual_probe_invocations": len(observed), "reported_resources": episode["resource_accounting"],
                   "verified_probe_hashes": episode["verified_probe_hashes"], "scan_inputs": observed,
                   "probe_errors": [a["probe_evaluation"].get("error") for a in episode["attempts"]],
                   "snapshot_filenames": sorted(p.name for p in (out / "AUDIT/_probe_snapshot").iterdir())}
            if mode in ("same_basename", "snapshot_drift"):
                assert not row["accepted"] and len(calls) == 3 and not observed
                assert row["reported_resources"]["probe_scans"] == 3
                if mode == "same_basename":
                    assert row["snapshot_filenames"] == ["function.py"]
                    assert (out / "AUDIT/_probe_snapshot/function.py").read_bytes() == pp
            else:
                assert row["accepted"]
                for seen in observed:
                    assert seen["vulnerable_sha256"] == row["verified_probe_hashes"]["vulnerable_probe_sha256"]
                    assert seen["patched_sha256"] == row["verified_probe_hashes"]["patched_probe_sha256"]
            evidence["scenarios"][mode] = row

    files = ["pipeline/tests/" + n for n in ("test_combined_gate.py", "test_run_model_case_cd.py",
        "test_diagnostic_regressions.py", "test_dev_probe.py", "test_typed_json_construction.py",
        "test_typed_rule.py", "test_rule_validator_classification.py")]
    proc = subprocess.run([sys.executable, "-m", "pytest", *files, "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True, check=True)
    count = int(re.search(r"(\d+) tests collected", proc.stdout).group(1))
    assert count == 143
    evidence["collection"] = {"count": count, "files": files, "summary": proc.stdout.strip().splitlines()[-1],
                              "full_suite_executed_by_review": False}
    paths = ["pipeline/diagnostic_v2.py", "pipeline/tests/test_run_model_case_cd.py", "pipeline/dev_probe.py",
             "pipeline/probe_cache.py", "pipeline/combined_gate.py"]
    evidence["reviewed_sha256"] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    with Path(__file__).with_name("CD_Snapshot_Review_Evidence_20261013.json").open("x") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
