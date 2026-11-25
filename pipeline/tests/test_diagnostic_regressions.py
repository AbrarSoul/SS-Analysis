"""Regression checks for actual schema, capture, and C3/C4 handoff failures."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]
from llm_client import LLMClient
from raw_capture import RawCaptureRecorder, _CompletionsProxy
import run_c3
import run_c4
import diagnostic_v2 as diagnostic


def client(policy="semgrep_search_taint_v2"):
    llm = object.__new__(LLMClient)
    llm.config = NS(rule_schema_policy=policy)
    llm.last_error = None
    return llm


def rule(rid="initial", **body):
    return {"id": rid, "message": "Diagnostic test", "severity": "ERROR", "languages": ["python"], **body}


@pytest.mark.parametrize("body", [
    {"pattern": "sink($X)"},
    {"patterns": [{"pattern": "sink($X)"}, {"pattern-not": "sink('safe')"}]},
    {"pattern-either": [{"pattern": "sink($X)"}, {"pattern": "other($X)"}]},
    {"pattern-regex": "sink"},
    {"mode": "taint", "pattern-sources": [{"pattern": "source()"}], "pattern-sinks": [{"pattern": "sink(...)"}]},
])
def test_standard_rule_forms_allowed(body):
    assert client().validate_rule_schema(rule(**body)) == (True, None)
    patch = NS(repo_owner="owner", repo_name="repo", commit_id="abcd", file_changes=[NS(language="python")])
    parsed = client().parse_and_sanitize_response(yaml.safe_dump({"rules": [rule(**body)]}), patch)
    assert parsed is not None and all(parsed[k] == v for k, v in body.items())


def test_legacy_policy_reproduces_composite_rejection():
    ok, error = client("legacy_pattern_only").validate_rule_schema(rule(patterns=[{"pattern": "sink($X)"}]))
    assert not ok and "pattern" in error


@pytest.mark.parametrize("body", [{}, {"mode": "taint", "pattern-sources": []}])
def test_incomplete_rule_rejected(body):
    assert client().validate_rule_schema(rule(**body))[0] is False


def test_multiple_rules_rejected_in_v2():
    llm = client()
    assert llm.parse_and_sanitize_response(yaml.safe_dump({"rules": [rule(), rule()]}), NS()) is None
    assert "exactly one" in llm.last_error


def test_capture_retains_messages_usage_finish_reason_and_failure(tmp_path):
    recorder = RawCaptureRecorder(tmp_path, "run")
    recorder.begin_case("CASE-TEST")
    reply = NS(choices=[NS(message=NS(content="raw YAML"), finish_reason="length")],
               usage=NS(prompt_tokens=23, completion_tokens=17))
    proxy = _CompletionsProxy(NS(create=lambda **kw: reply), recorder)
    messages = [{"role": "system", "content": "system evidence"}, {"role": "user", "content": "patch"}]
    assert proxy.create(model="fake", messages=messages, temperature=0) is reply
    saved = json.loads((recorder.raw_dir / "CASE-TEST.json").read_text())
    assert saved["request"]["messages"] == messages
    assert saved["response"]["choices"][0]["finish_reason"] == "length"
    assert saved["input_tokens"] == 23 and saved["output_tokens"] == 17
    assert saved["generation_seconds"] >= 0
    def fail(**kwargs):
        raise TimeoutError("synthetic timeout")
    with pytest.raises(TimeoutError):
        _CompletionsProxy(NS(create=fail), recorder).create(model="fake", messages=messages)
    failure = json.loads((recorder.retries_dir / "CASE-TEST_attempt2.json").read_text())
    assert failure["error"]["type"] == "TimeoutError" and failure["input_tokens"] is None
    second = RawCaptureRecorder(tmp_path, "run")
    second.begin_case("CASE-TEST")
    with pytest.raises(FileExistsError):
        second.record("fake", 0, "must not overwrite")
    assert json.loads((recorder.raw_dir / "CASE-TEST.json").read_text())["raw_content"] == "raw YAML"


@pytest.mark.parametrize("module", [run_c3, run_c4], ids=["c3", "c4"])
@pytest.mark.parametrize("failed_repair", [False, True], ids=["replacement_handoff", "unparseable_repair"])
def test_review_and_repair_follow_current_candidate(monkeypatch, module, failed_repair):
    patch = NS(repo_name="test", repo_owner="owner", commit_id="abcd1234", file_changes=[NS(language="python")])
    monkeypatch.setattr(module, "load_case", lambda *a: patch)
    monkeypatch.setattr(module, "build_patch_analysis_prompt", lambda *a: "analysis")
    monkeypatch.setattr(module, "build_rule_generation_prompt", lambda *a: "generation")
    monkeypatch.setattr(module, "build_syntax_review_prompt", lambda text, error: "SYNTAX\n" + text)
    monkeypatch.setattr(module, "build_semantic_review_prompt", lambda text, *a: "SEMANTIC\n" + text)
    monkeypatch.setattr(module, "build_rule_repair_prompt", lambda text, *a: "REPAIR\n" + text)
    monkeypatch.setattr(module, "_check_original_pair", lambda *a: (False, False))
    monkeypatch.setattr(module, "evaluate_case_bundle", lambda *a, **kw: ([], None))
    initial = yaml.safe_dump({"rules": [rule("initial", pattern="initial($X)")]})
    replacement = yaml.safe_dump({"rules": [rule("replacement", pattern="replacement($X)")]})
    repaired = "INVALID REPAIR: [" if failed_repair else yaml.safe_dump({"rules": [rule("repaired", pattern="repaired($X)")]})
    replies = ["MECHANISM: m\nSOURCE: s\nSINK: k\nFIX: f", initial,
               "DIAGNOSIS: DSL_ERROR\nCORRECTED_RULE:\n" + replacement,
               "VERDICT: NOT_ACCEPTED\nDIAGNOSIS: MISS\nREPAIR_INSTRUCTIONS: fix",
               repaired, "DIAGNOSIS: NOT_A_SYNTAX_ERROR\nCORRECTED_RULE:\nNONE"]
    prompts = []
    def call(llm, model, prompt, *a):
        prompts.append(prompt)
        return replies[len(prompts) - 1]
    monkeypatch.setattr(module, "_call", call)
    llm = client()
    validator = NS(validate_rule=lambda r, *a: (r["id"] == "repaired", "synthetic visible miss"))
    if module is run_c3:
        episode, _ = module.run_c3_episode("CASE-0041", "fake", "C3-E", llm.config, llm,
                                           validator, "unit", {}, 512)
    else:
        roles = {r: "fake" for r in module.ROLES}
        episode, _ = module.run_c4_episode("CASE-0041", "C4-B", roles, {r: llm for r in roles},
                                           llm, validator, "unit", {}, 512)
    assert "replacement($X)" in prompts[3] and "initial($X)" not in prompts[3]
    assert "replacement($X)" in prompts[4] and "initial($X)" not in prompts[4]
    if failed_repair:
        assert "INVALID REPAIR: [" in prompts[5] and "initial($X)" not in prompts[5]
        assert not episode.accepted
    else:
        assert "repaired($X)" in prompts[5] and episode.accepted
    assert episode.calls_used == 6


def test_hidden_samples_never_enter_repair_feedback(monkeypatch, tmp_path):
    events, feedback = [], []
    monkeypatch.setattr(diagnostic, "load_case", lambda *a: NS())
    def generate(patch, error_feedback=None):
        events.append("generate")
        feedback.append(error_feedback)
        return rule(pattern="sink($X)")
    def scan(path, cid, manifest, annotations, out, *, hidden):
        events.append("hidden" if hidden else "visible")
        accepted = hidden or events.count("generate") == 2
        return {"legacy_accepted": accepted, "scan_ok": True, "errors": [],
                "visible_correct": accepted, "complete_success": hidden,
                "samples": [{"sample_type": "original_patched", "detected": False}]}
    monkeypatch.setattr(diagnostic, "scan", scan)
    recorder = RawCaptureRecorder(tmp_path, "test")
    episode = diagnostic.run_model_case("CASE-TEST", NS(generate_rule=generate), NS(), recorder, {}, {}, tmp_path)
    assert events == ["generate", "visible", "generate", "visible", "hidden", "hidden"]
    assert feedback == [None, "Rule failed to detect vulnerability in original version"]
    assert episode["final_rule_sha256"] == diagnostic.sha(tmp_path / "CASE-TEST/final_rule.yml")
    assert episode["input_tokens"] is None  # An unreported cost must not become zero.


@pytest.mark.parametrize("failure", ["nonzero", "unscanned", "parser_error"])
def test_scan_failures_cannot_be_credited_as_success(monkeypatch, tmp_path, failure):
    root = tmp_path / "repo"
    bundle = root / "benchmark/cases/CASE-TEST"
    bundle.mkdir(parents=True)
    for _, stem, _ in diagnostic.SAMPLES:
        (bundle / (stem + ".py")).write_text("sink(value)\n")
    results = [{"path": str(bundle / (stem + ".py")), "start": {"line": 1}}
               for _, stem, positive in diagnostic.SAMPLES if positive]
    payload = {"results": results, "paths": {"scanned": [str(p) for p in bundle.iterdir()]}, "errors": []}
    if failure == "unscanned":
        payload["paths"]["scanned"] = []
    if failure == "parser_error":
        payload["errors"] = [{"message": "synthetic parse error"}]
    proc = NS(stdout=json.dumps(payload), stderr="", returncode=2 if failure == "nonzero" else 0)
    monkeypatch.setattr(diagnostic, "ROOT", root)
    monkeypatch.setattr(diagnostic.subprocess, "run", lambda *a, **kw: proc)
    manifest = {"CASE-TEST": {"language": "python", "vulnerable_lines": [1, 1]}}
    annotations = {("CASE-TEST", kind): [(1, 1)] for kind in ("variant_vulnerable_1", "variant_vulnerable_2")}
    result = diagnostic.scan(tmp_path / "rule.yml", "CASE-TEST", manifest, annotations, tmp_path / "scan", hidden=True)
    assert result["errors"] and not result["scan_ok"]
    assert not result["legacy_accepted"] and not result["complete_success"]


def _wrong_location_evaluation():
    """A visible evaluation that is legacy_accepted=True but visible_correct=False -- the exact
    disagreement an independent review (2026-10-12) reproduced to show run_model_case() still
    stopped the retry loop on a wrong-location rule even after report()'s *_corrected fields were
    added to diagnostic_v2.py."""
    return {
        "scan_ok": True, "returncode": 0, "all_targets_scanned": True, "errors": [],
        "legacy_accepted": True, "visible_correct": False, "complete_success": False,
        "samples": [
            {"sample_type": "original_vulnerable", "label": "positive", "detected": True,
             "finding_location_correct": False, "finding_lines": [99], "outcome": "FN"},
            {"sample_type": "original_patched", "label": "negative", "detected": False,
             "finding_location_correct": None, "finding_lines": [], "outcome": "TN"},
        ],
    }


class _FakeLLM:
    last_error = None

    def generate_rule(self, patch, error_feedback=None):
        return {"id": "x", "message": "m", "severity": "ERROR", "languages": ["python"], "pattern": "sink($X)"}


class _FakeRecorder:
    def __init__(self, tmp_path):
        self.raw_dir = tmp_path / "raw"
        self.retries_dir = tmp_path / "retries"
        self.raw_dir.mkdir()
        self.retries_dir.mkdir()

    def begin_case(self, cid):
        pass


@pytest.mark.parametrize("policy,expected_attempts,expected_accepted", [
    ("legacy", 1, True),
    ("corrected", 3, False),
])
def test_acceptance_policy_controls_wrong_location_stopping(monkeypatch, tmp_path, policy, expected_attempts, expected_accepted):
    """The regression this exists for: a wrong-location rule must keep retrying under the
    'corrected' policy (never silently accepted as a false win), but 'legacy' must reproduce the
    exact historical behavior (stop after attempt 1) unchanged."""
    monkeypatch.setattr(diagnostic, "load_case", lambda cid, config: object())
    monkeypatch.setattr(diagnostic, "scan", lambda *a, **kw: _wrong_location_evaluation())
    manifest = {"CASE-TEST": {"language": "python", "vulnerable_lines": [1, 1]}}
    episode = diagnostic.run_model_case(
        "CASE-TEST", _FakeLLM(), config=NS(), recorder=_FakeRecorder(tmp_path),
        manifest=manifest, ann={}, out=tmp_path / "out", acceptance_policy=policy)
    assert len(episode["attempts"]) == expected_attempts
    assert (episode["final_rule_path"] is not None) == expected_accepted
    if policy == "corrected" and expected_attempts > 1:
        assert "NOT at the correct location" in episode["attempts"][0]["feedback"]
