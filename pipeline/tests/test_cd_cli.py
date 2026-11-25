"""Complete frozen-manifest -> CLI -> real prompt/parser -> snapshot/runner path, offline.

Only provider responses and Semgrep are substituted. Model-context loading, JSON/YAML
construction, raw capture, cache/manifest checks, files, retry decisions and reports are real.
"""
import json
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace as NS

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
import cd_experiment as cd
import diagnostic_v2 as dv
import gptlab_config
import probe_coverage_check


@pytest.fixture
def cli(monkeypatch, tmp_path):
    # Keep the CLI's fresh-output namespace policy while all outputs stay in pytest's temp root.
    for name in ("pipeline", "autogrep", "benchmark", "Research_Log"):
        (tmp_path / name).symlink_to(ROOT / name, target_is_directory=True)
    monkeypatch.setattr(dv, "ROOT", tmp_path)
    monkeypatch.setattr(dv, "__file__", str(tmp_path / "pipeline/diagnostic_v2.py"))
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **kw: pytest.fail("Real network forbidden"))
    auth_calls = []
    monkeypatch.setattr(gptlab_config, "get_key_for_host", lambda _: "offline-fake-key")
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: auth_calls.append(a[0]) or NS(status_code=200))
    def version(command, **kwargs):
        assert command == [str(dv.SEMGREP), "--version"]
        return NS(returncode=0, stdout="1.177.0\n", stderr="")
    monkeypatch.setattr(dv.subprocess, "run", version)
    def invoke(mode, condition=None, extra=(), label="run"):
        out = tmp_path / "results/diagnostic_20261010" / label
        argv = ["diagnostic_v2.py", mode, "--output", str(out)]
        if condition:
            argv += ["--condition", condition]
        monkeypatch.setattr(sys, "argv", argv + list(extra))
        dv.main()
        return out
    return invoke, auth_calls


def test_real_frozen_manifest_reproduces_reviewed_24_cases():
    frozen, contexts, _ = cd.validate_frozen_manifest(cd.DEFAULT_MANIFEST)
    assert frozen == cd.build_frozen_manifest()
    assert len(contexts) == 24
    assert sum(e["eligible"] for e in frozen["entries"].values()) == 11


@pytest.mark.parametrize("condition,construction", [("C", "original_prompt"), ("D", "typed_json")])
def test_cd_cli_complete_offline_24_case_run(cli, monkeypatch, condition, construction):
    invoke, auth_calls = cli
    active = {}
    events = []
    original_load = dv.load_case
    def load(cid, config):
        active.update(cid=cid, call=0)
        return original_load(cid, config)
    monkeypatch.setattr(dv, "load_case", load)
    real_llm = dv.LLMClient
    def factory(config):
        assert config.construction_mode == construction
        llm = object.__new__(real_llm)
        llm.config, llm.last_error = config, None
        def completion(**kwargs):
            active["call"] += 1
            cid, attempt = active["cid"], active["call"]
            events.append((cid, "generation", attempt))
            assert kwargs["temperature"] == 0 and kwargs["max_tokens"] == 2048
            rule = {"id": "offline-rule", "message": "offline", "severity": "ERROR",
                    "languages": [cd.validate_frozen_manifest(cd.DEFAULT_MANIFEST)[0]["entries"][cid]["language"]],
                    "pattern": "foo($X)"}
            # Decoder failure consumes a call, not a scan, in both construction paths.
            text = "unparseable output" if cid == "CASE-0134" and attempt == 1 else (
                json.dumps(rule) if construction == "typed_json" else yaml.safe_dump({"rules": [rule]}))
            return NS(choices=[NS(message=NS(content=text))], usage=NS(prompt_tokens=10, completion_tokens=5))
        llm.client = NS(chat=NS(completions=NS(create=completion)))
        return llm
    monkeypatch.setattr(dv, "LLMClient", factory)
    def visible(rule, cid, manifest, ann, out, *, hidden):
        events.append((cid, "hidden" if hidden else "visible", active["call"]))
        return {"scan_ok": True, "visible_correct": True, "legacy_accepted": True,
                "complete_success": hidden, "samples": [], "errors": []}
    monkeypatch.setattr(dv, "scan", visible)
    def probe_scan(rule, vp, pp, out):
        cid, attempt = active["cid"], active["call"]
        events.append((cid, "probe", attempt))
        assert "_probe_snapshot" in vp.parts and vp != pp
        assert vp.is_file() and pp.is_file()
        if cid == "CASE-0136":
            raise subprocess.TimeoutExpired("offline-semgrep", 120)
        return {"scan_ok": True, "vulnerable_detected": not (cid == "CASE-0046" and attempt == 1),
                "patched_detected": False}
    monkeypatch.setattr(probe_coverage_check, "scan_probe", probe_scan)
    out = invoke("model", condition)
    env = json.loads((out / "environment.json").read_text())
    assert env["condition"] == condition and env["construction_mode"] == construction
    assert env["acceptance_policy"] == "corrected"
    assert env["probe_coverage"] == {"requested_cases": 24, "eligible_cases": 11, "ineligible_cases": 13}
    assert len(auth_calls) == 1  # mocked provider preflight; socket connections prohibited
    episodes = [json.loads((out / cid / "episode.json").read_text()) for cid in cd.build_frozen_manifest()["case_ids"]]
    for episode in episodes:
        cid = episode["case_id"]
        assert episode["calls_recorded"] == episode["resource_accounting"]["generation_calls"]
        assert episode["input_tokens"] == 10 * episode["calls_recorded"]
        assert episode["probe_provenance"]["manifest_sha256"] == env["probe_manifest_sha256"]
        if not episode["probe_eligible"]:
            assert episode["probe_ineligible_reason"] and episode["probe_fallback_used"]
        seq = [event for c, event, _ in events if c == cid]
        assert "generation" not in seq[seq.index("hidden"):] if "hidden" in seq else True
    by_id = {e["case_id"]: e for e in episodes}
    assert len(by_id["CASE-0046"]["attempts"]) == 2
    assert "additional development-time test case" in by_id["CASE-0046"]["attempts"][0]["feedback"]
    assert by_id["CASE-0134"]["resource_accounting"]["visible_scans"] == 1
    assert by_id["CASE-0136"]["final_rule_path"] is None
    assert by_id["CASE-0136"]["calls_recorded"] == 3
    summary = json.loads((out / "summary.json").read_text())
    probes = summary["development_probes"]
    assert probes["requested_cases"] == probes["completed_cases"] == 24
    assert probes["eligible_cases_completed"] == 11 and probes["ineligible_cases_completed"] == 13
    assert probes["probe_scan_errors"] == 3
    assert probes["resources"] == {"generation_calls": 28, "visible_scans": 27, "probe_scans": 14, "repair_calls": 4}


@pytest.mark.parametrize("condition,extra", [
    ("C", ["--construction-mode", "typed_json"]), ("D", ["--construction-mode", "original_prompt"]),
    ("C", ["--acceptance-policy", "legacy"]), ("D", ["--prompt-variant", "design_v1"])])
def test_conflicting_condition_flags_fail_before_provider_access(cli, condition, extra):
    invoke, auth_calls = cli
    with pytest.raises(SystemExit):
        invoke("model", condition, extra)
    assert auth_calls == []


def test_manifest_deviation_rejected_before_provider_access(cli, tmp_path):
    invoke, auth_calls = cli
    frozen = json.loads(cd.DEFAULT_MANIFEST.read_bytes())
    frozen["entries"]["CASE-0046"]["vulnerable_probe_sha256"] = "0" * 64
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps(frozen))
    with pytest.raises(cd.ExperimentManifestError):
        invoke("model", "C", ["--probe-manifest", str(wrong)])
    assert auth_calls == []


@pytest.mark.parametrize("condition", ["C", "D"])
def test_preflight_prepares_all_inputs_without_credentials_or_models(cli, monkeypatch, condition):
    invoke, auth_calls = cli
    monkeypatch.setattr(dv, "LLMClient", lambda *a: pytest.fail("preflight must not construct a model"))
    out = invoke("preflight", condition)
    assert auth_calls == []
    assert len(list((out / "_probe_inputs").iterdir())) == 11
    assert len(list((out / "_probe_cache").iterdir())) == 24
    with pytest.raises(SystemExit):
        invoke("model", condition)  # same namespace refused before provider access
    assert auth_calls == []


def test_ab_preflight_defaults_remain_unchanged(cli, monkeypatch):
    invoke, auth_calls = cli
    monkeypatch.setattr(cd, "validate_frozen_manifest", lambda *a: pytest.fail("A/B must not call probe loader"))
    out = invoke("preflight")
    env = json.loads((out / "environment.json").read_text())
    assert env["construction_mode"] == "original_prompt" and env["acceptance_policy"] == "legacy"
    assert env["prompt_policy"] == "historical_autogrep_default_unchanged"
    assert "condition" not in env and not (out / "_probe_inputs").exists()
    assert auth_calls == []
