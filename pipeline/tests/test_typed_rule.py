"""
Regression tests for pipeline/typed_rule.py, added after an independent review (2026-10-12) found
that `semgrep --validate` passing is not evidence a rule's exclusion actually works -- the prior
serializer's "simple case" (top-level sibling pattern + pattern-not) silently matched BOTH the
unsafe and safe lines under real execution, despite validating cleanly. These tests run the real
pinned Semgrep compiler against real target files and check actual match behavior, not just schema
validity -- the exact gap that let the original bug through undetected.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
from typed_rule import TypedRule

SEMGREP = ROOT / ".venv/bin/semgrep"


def _semgrep_env():
    import os
    env = os.environ.copy()
    env["PATH"] = str(ROOT / ".venv/bin") + os.pathsep + env.get("PATH", "")
    env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    return env


def _matched_lines(rule_yaml: str, target_path: Path) -> set:
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
        tf.write(rule_yaml)
        rule_path = tf.name
    proc = subprocess.run([str(SEMGREP), "--config", rule_path, "--json", "--metrics=off",
                            "--disable-version-check", "--jobs=1", str(target_path)],
                           capture_output=True, text=True, env=_semgrep_env(), timeout=60)
    data = __import__("json").loads(proc.stdout)
    assert not data.get("errors"), f"Semgrep reported errors: {data['errors']}"
    return {r["start"]["line"] for r in data["results"]}


@pytest.fixture
def unsafe_safe_target(tmp_path):
    target = tmp_path / "target.py"
    target.write_text('foo("unsafe")\nfoo("safe")\n')
    return target


def test_single_exclusion_actually_excludes(unsafe_safe_target):
    """The regression this file exists for: a single pattern_not must actually exclude the safe
    line under real execution, not just pass schema validation."""
    tr = TypedRule(id="test-rule", message="m", severity="ERROR", languages=["python"],
                    pattern='foo($X)', pattern_not=['foo("safe")'])
    matched = _matched_lines(tr.to_semgrep_yaml(), unsafe_safe_target)
    assert matched == {1}, f"Expected only line 1 (unsafe) to match, got {matched}"


def test_pattern_either_with_exclusion_actually_excludes(unsafe_safe_target):
    tr = TypedRule(id="test-rule", message="m", severity="ERROR", languages=["python"],
                    pattern_either=['foo($X)', 'bar($X)'], pattern_not=['foo("safe")'])
    matched = _matched_lines(tr.to_semgrep_yaml(), unsafe_safe_target)
    assert matched == {1}, f"Expected only line 1 (unsafe) to match, got {matched}"


def test_bare_pattern_no_exclusion_still_matches_everything(unsafe_safe_target):
    """Sanity check: with NO pattern_not at all, both lines should match -- confirms the test
    fixture itself is meaningful (both lines really do match the bare pattern)."""
    tr = TypedRule(id="test-rule", message="m", severity="ERROR", languages=["python"], pattern='foo($X)')
    matched = _matched_lines(tr.to_semgrep_yaml(), unsafe_safe_target)
    assert matched == {1, 2}


@pytest.mark.parametrize("kwargs", [
    dict(pattern_either="foo()"),
    dict(pattern_either=[]),
    dict(pattern="foo()", pattern_not="bar()"),
    dict(languages="python", pattern="foo()"),
    dict(pattern="foo()", pattern_either=["bar()"]),
])
def test_invalid_shapes_rejected(kwargs):
    base = dict(id="x", message="m", severity="ERROR", languages=["python"])
    base.update(kwargs)
    with pytest.raises(ValueError):
        TypedRule(**base).validate()


def test_taint_with_pattern_not_rejected_not_silently_dropped():
    tr = TypedRule(id="x", message="m", severity="ERROR", languages=["python"],
                    taint_sources=["input()"], taint_sinks=["eval($X)"], pattern_not=["safe()"])
    with pytest.raises(ValueError):
        tr.validate()


@pytest.fixture
def inside_outside_target(tmp_path):
    target = tmp_path / "target.py"
    target.write_text('def allowed():\n    foo("inside")\n\nfoo("outside")\n')
    return target


def test_pattern_inside_actually_restricts_scope(inside_outside_target):
    """A brief, incorrect fix was made and reverted the same day (see to_dict()'s docstring for the
    full history). What actually happened: a sibling (non-nested) pattern_inside is SILENTLY
    IGNORED by Semgrep, never enforced -- reproduced directly with a probe a positive-only fixture
    can't catch: a sibling pattern_inside naming a function that doesn't exist in the target file
    still matches. This test requires BOTH an in-scope and an out-of-scope call, specifically so a
    serializer that silently drops the scope constraint (matching both lines) cannot pass it --
    the exact gap a positive-only fixture left open before."""
    tr = TypedRule(id="test-rule", message="m", severity="ERROR", languages=["python"],
                    pattern='foo($X)', pattern_inside="def allowed(...):\n    ...")
    rule_dict = tr.to_dict()
    assert "patterns" in rule_dict, "pattern_inside must be composed via patterns:, never a sibling"
    matched = _matched_lines(tr.to_semgrep_yaml(), inside_outside_target)
    assert matched == {2}, f"Expected only line 2 (inside allowed()) to match, got {matched}"


def test_bare_pattern_inside_sibling_is_silently_ignored_not_enforced(inside_outside_target):
    """Documents the actual defect found 2026-10-12 (not the misdiagnosis that briefly replaced
    it): a bare top-level sibling pattern_inside -- what to_dict() must NEVER emit -- matches both
    the in-scope and out-of-scope line, because Semgrep silently ignores an un-nested
    pattern-inside rather than enforcing or rejecting it. This test exists so a future change can't
    reintroduce the sibling form without this regression test failing first."""
    sibling_yaml = yaml.dump({"rules": [{
        "id": "test-rule", "pattern": "foo($X)", "pattern-inside": "def allowed(...):\n    ...",
        "languages": ["python"], "message": "m", "severity": "ERROR"}]}, sort_keys=False)
    matched = _matched_lines(sibling_yaml, inside_outside_target)
    assert matched == {2, 4}, (
        f"expected the sibling form to ignore the scope constraint and match both lines, got {matched}")
