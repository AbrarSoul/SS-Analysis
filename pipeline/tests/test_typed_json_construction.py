"""
Offline exercise of Controlled_2x2_Protocol_Draft_20261012.md condition B's new typed-JSON
construction path (autogrep/llm_client.py's _generate_rule_typed_json/_parse_typed_json_response),
per Protocol_Review_Closure_20261012.md's required offline checks before any live B inference:
valid JSON -> executable rule; invalid/unsupported output -> bounded repair; a behavioral
composite-rule example so correct syntax alone cannot conceal a semantic composition failure.

No model calls are made here -- _parse_typed_json_response() is exercised directly with
hand-written JSON strings standing in for what a live model response would contain, same testing
style as pipeline/tests/test_typed_rule.py uses for TypedRule itself.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]
from config import Config
from llm_client import LLMClient
from patch_processor import FileChange, PatchInfo

SEMGREP = ROOT / ".venv/bin/semgrep"


def _semgrep_env():
    import os
    env = os.environ.copy()
    env["PATH"] = str(ROOT / ".venv/bin") + os.pathsep + env.get("PATH", "")
    env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    return env


@pytest.fixture
def client():
    config = Config(openrouter_api_key="offline-test", construction_mode="typed_json")
    return LLMClient(config)


@pytest.fixture
def patch_info():
    return PatchInfo(
        repo_owner="example-owner", repo_name="example-repo", commit_id="deadbeef00",
        file_changes=[FileChange(file_path="app.py", changes="- os.system(cmd)\n+ subprocess.run(cmd)", language="python")])


def test_valid_json_becomes_executable_rule(client, patch_info):
    """Valid JSON -> a rule dict that, wrapped and dumped exactly like run_model_case() does for
    condition A, real Semgrep accepts with --validate."""
    content = '{"id": "test-rule", "message": "m", "severity": "ERROR", "languages": ["python"], "pattern": "foo($X)"}'
    rule = client._parse_typed_json_response(content, patch_info)
    assert rule is not None
    assert client.last_error is None
    rule_yaml = yaml.dump({"rules": [rule]}, sort_keys=False, default_flow_style=False)
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
        tf.write(rule_yaml)
        rule_path = tf.name
    proc = subprocess.run([str(SEMGREP), "--validate", "--config", rule_path],
                           capture_output=True, text=True, env=_semgrep_env(), timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_valid_json_wrapped_in_fence_and_prose(client, patch_info):
    """Models ignoring "JSON only" instructions and wrapping output in a fence (or prose) must
    still be recovered, same rationale as extract_response()'s own docstring for condition A."""
    content = 'Here is the rule:\n```json\n{"id": "test-rule", "message": "m", "severity": "ERROR", "languages": ["python"], "pattern": "foo($X)"}\n```\nLet me know if you need changes.'
    rule = client._parse_typed_json_response(content, patch_info)
    assert rule is not None
    assert rule["id"] == "test-rule"


def test_invalid_json_triggers_bounded_repair_feedback(client, patch_info):
    content = '{"id": "test-rule", "message": "m", severity: ERROR}'  # unquoted keys -- invalid JSON
    rule = client._parse_typed_json_response(content, patch_info)
    assert rule is None
    assert "Invalid JSON" in client.last_error


def test_unexpected_field_triggers_bounded_repair_feedback(client, patch_info):
    """A field name TypedRule doesn't recognize (e.g. a model inventing "patternNot" instead of
    "pattern_not") must be a TypeError caught here, not an uncaught crash -- consumes one of the
    repair loop's attempts with a specific message, exactly like a YAML schema failure does for A."""
    content = '{"id": "test-rule", "message": "m", "severity": "ERROR", "languages": ["python"], "pattern": "foo($X)", "patternNot": "bar()"}'
    rule = client._parse_typed_json_response(content, patch_info)
    assert rule is None
    assert "Unexpected or missing field" in client.last_error


def test_mutually_exclusive_fields_triggers_bounded_repair_feedback(client, patch_info):
    """Setting both pattern and pattern_either (TypedRule's mutual-exclusivity rule) must surface
    as a ValueError from validate(), not silently pick one or crash."""
    content = ('{"id": "test-rule", "message": "m", "severity": "ERROR", "languages": ["python"], '
               '"pattern": "foo($X)", "pattern_either": ["bar($X)"]}')
    rule = client._parse_typed_json_response(content, patch_info)
    assert rule is None
    assert "Invalid typed rule" in client.last_error


def test_empty_response_triggers_bounded_repair_feedback(client, patch_info):
    rule = client._parse_typed_json_response(None, patch_info)
    assert rule is None
    assert client.last_error == "Empty response from LLM"


def test_composite_rule_behavioral_composition_not_just_syntax(client, patch_info, tmp_path):
    """The actual regression this whole investigation was about: correct SYNTAX alone (passing
    --validate) is not evidence a pattern_not actually excludes. This JSON response includes a
    pattern_not; the resulting rule, run through real Semgrep against real target files, must
    exclude the safe line and keep matching the unsafe one -- not just validate cleanly."""
    content = ('{"id": "test-rule", "message": "m", "severity": "ERROR", "languages": ["python"], '
               '"pattern": "foo($X)", "pattern_not": ["foo(\\"safe\\")"]}')
    rule = client._parse_typed_json_response(content, patch_info)
    assert rule is not None
    assert "patterns" in rule, "a pattern_not must always compose via patterns:, never a sibling"

    target = tmp_path / "target.py"
    target.write_text('foo("unsafe")\nfoo("safe")\n')
    rule_yaml = yaml.dump({"rules": [rule]}, sort_keys=False, default_flow_style=False)
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
        tf.write(rule_yaml)
        rule_path = tf.name
    proc = subprocess.run([str(SEMGREP), "--config", rule_path, "--json", "--metrics=off",
                            "--disable-version-check", "--jobs=1", str(target)],
                           capture_output=True, text=True, env=_semgrep_env(), timeout=60)
    import json
    data = json.loads(proc.stdout)
    matched_lines = {r["start"]["line"] for r in data["results"]}
    assert matched_lines == {1}, f"expected only line 1 (unsafe) to match, got {matched_lines}"


def test_construction_mode_default_leaves_condition_a_untouched(patch_info):
    """generate_rule()'s dispatch must default to the ORIGINAL YAML path -- construction_mode is
    opt-in, never silently changing behavior for any existing caller/config that doesn't set it."""
    config = Config(openrouter_api_key="offline-test")  # construction_mode left at its default
    assert config.construction_mode == "original_prompt"
    client = LLMClient(config)
    # _build_prompt (condition A's dispatcher) must be reachable/unchanged -- a smoke check that
    # generate_rule() would take the original branch, without making a real API call.
    prompt = client._build_prompt(patch_info)
    assert "typed_json" not in prompt.lower()
    assert "JSON object" not in prompt
