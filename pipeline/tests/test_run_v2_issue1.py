"""
Run v2, supervisor Issue 1 (Research_Log/Run_v2_Specification.md): rule forms, prompt defects, failure stages.

What these tests establish:
- the run v2 examples are autogrep_default's own examples, made valid YAML, and Semgrep accepts every rule;
- for every eligible case, the run v2 prompt equals the v1 prompt with exactly the five documented edits
  applied, and nothing else;
- the run v2 checker accepts every Semgrep matching form and v1's checker is unchanged;
- each parser failure reports its stage;
- v1's defaults, prompts and system message are untouched.
"""
import csv
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

os.environ.setdefault("GPTLAB_API_KEY", "not-used-offline-test")
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

import llm_client as L  # noqa: E402
import run_v2_settings  # noqa: E402
from case_loader import load_case  # noqa: E402
from config import Config  # noqa: E402
from gptlab_config import build_config  # noqa: E402

SEMGREP = ROOT / ".venv" / "bin" / "semgrep"
ELIGIBLE = [r["case_id"] for r in csv.DictReader(open(ROOT / "benchmark" / "all_cases_reference.csv"))
            if r["status"].startswith("eligible-150")]
LEGACY_SYSTEM = """You generate Semgrep rules in YAML format.
    Return only the raw YAML content without any markdown formatting or additional text.
    Always include these required fields: id, pattern, message, severity, languages"""


def _client(v2: bool):
    cfg = build_config("qwen2.5-coder:7b-instruct")
    if v2:
        run_v2_settings.apply(cfg)
    return L.LLMClient(cfg), cfg


def _semgrep_validate(rule_yaml: str):
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(rule_yaml)
    p = subprocess.run([str(SEMGREP), "--validate", "--metrics=off", "--config", f.name],
                       capture_output=True, text=True)
    os.unlink(f.name)
    return p.returncode, p.stdout + p.stderr


# ---------------------------------------------------------------- examples
def _norm(s):
    return re.sub(r"[\s\"']", "", s)


def test_examples_are_v1_content_as_valid_yaml():
    for lang, v1 in L.EXAMPLE_RULES.items():
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load(v1)                      # the v1 defect is real
        v2 = L.EXAMPLE_RULES_RUN_V2[lang]
        assert _norm(v1) == _norm(v2), f"{lang}: content differs beyond whitespace/quoting"
        assert len(yaml.safe_load(v2)["rules"]) == 2


def test_typescript_example_is_the_javascript_one():
    ts, js = L.EXAMPLE_RULES_RUN_V2["typescript"], L.EXAMPLE_RULES_RUN_V2["javascript"]
    assert ts == js.replace("languages: [javascript]", "languages: [typescript]") and ts != js
    assert all(r["languages"] == ["typescript"] for r in yaml.safe_load(ts)["rules"])


def test_no_example_content_taken_from_benchmark_cases():
    # EXAMPLE_RULES_V3's typescript rule restates CASE-0238's own fix; it must not leak into run v2
    assert not any("escapeFormulae" in v for v in L.EXAMPLE_RULES_RUN_V2.values())


@pytest.mark.parametrize("lang", sorted(L.EXAMPLE_RULES_RUN_V2))
def test_semgrep_accepts_every_example_rule(lang):
    code, out = _semgrep_validate(L.EXAMPLE_RULES_RUN_V2[lang])
    assert code == 0, out[-800:]


# ---------------------------------------------------------------- prompt
V1_FORMAT = '''    FORMAT YOUR RESPONSE AS A SINGLE YAML DOCUMENT:
    rules:
    - id: "{sid}"
    pattern: [Your pattern here]
    pattern-not: [Fixed version pattern]
    languages: ["{lang}"]
    message: [Clear description]
    severity: ERROR
    metadata: [Additional context]'''
V2_FORMAT = '''    FORMAT YOUR RESPONSE AS A SINGLE YAML DOCUMENT CONTAINING EXACTLY ONE RULE:
    rules:
    - id: "{sid}"
      pattern: [Your pattern here]
      pattern-not: [Fixed version pattern]
      languages: ["{lang}"]
      message: [Clear description]
      severity: ERROR
      metadata: [Additional context]'''
V1_REQ2 = "    2. pattern: Clear pattern matching the vulnerable code structure\n"
V2_REQ2 = ("    2. A matching clause: pattern, patterns, pattern-either or pattern-regex; or, for a taint rule, "
           "mode: taint with pattern-sources and pattern-sinks\n")
PIPE_LINE = "    - Use |> to pipe patterns together\n"


def _expected_v2_from_v1(v1_prompt, lang, sid):
    """Apply exactly the five documented edits to the v1 prompt."""
    out = v1_prompt
    for old, new in [(L.EXAMPLE_RULES.get(lang, ""), L.EXAMPLE_RULES_RUN_V2.get(lang, "")),   # edit 1
                     (V1_REQ2, V2_REQ2),                                                      # edit 2
                     (PIPE_LINE, ""),                                                         # edit 3
                     (V1_FORMAT.format(sid=sid, lang=lang), V2_FORMAT.format(sid=sid, lang=lang))]:  # 4, 5
        if old:
            assert out.count(old) == 1, f"expected exactly one occurrence of {old[:60]!r}"
            out = out.replace(old, new)
        else:                       # v1 had no example for this language: the empty insert becomes the example
            marker = "    EXAMPLES OF HIGH-QUALITY RULES:\n    \n"
            assert out.count(marker) == 1
            out = out.replace(marker, "    EXAMPLES OF HIGH-QUALITY RULES:\n    " + new + "\n")
    return out


def test_v2_prompt_is_v1_plus_documented_edits_for_every_eligible_case():
    v1_client, cfg = _client(v2=False)
    v2_client, _ = _client(v2=True)
    assert len(ELIGIBLE) == 150
    langs = set()
    for cid in ELIGIBLE:
        pi = load_case(cid, cfg)
        lang = pi.file_changes[0].language
        langs.add(lang)
        sid = L._make_suggested_id(pi)
        for feedback in (None, "Semgrep error: example feedback"):
            v1 = v1_client._build_prompt(pi, feedback)
            v2 = v2_client._build_prompt(pi, feedback)
            assert v2 == _expected_v2_from_v1(v1, lang, sid), f"{cid}: unexpected difference"
            assert "|>" not in v2.split("PATCH CHANGES:")[0] + v2.split("SEMGREP PATTERN SYNTAX GUIDE:")[1]
    assert langs <= set(L.EXAMPLE_RULES_RUN_V2), f"languages without an example: {langs - set(L.EXAMPLE_RULES_RUN_V2)}"


def test_v2_response_template_is_valid_yaml_with_one_rule():
    block = "\n".join(line[4:] for line in V2_FORMAT.format(sid="x", lang="python").splitlines()[1:])
    data = yaml.safe_load(block)
    assert isinstance(data["rules"], list) and len(data["rules"]) == 1
    assert {"id", "pattern", "languages", "message", "severity"} <= set(data["rules"][0])


def test_system_messages():
    v1_client, _ = _client(v2=False)
    v2_client, _ = _client(v2=True)
    assert v1_client._system_message() == LEGACY_SYSTEM          # v1 unchanged
    msg = v2_client._system_message()
    for form in ("pattern,", "patterns", "pattern-either", "pattern-regex", "pattern-sources", "pattern-sinks"):
        assert form in msg


# ---------------------------------------------------------------- checker
RULES = {
    "pattern": {"pattern": "eval($X)"},
    "patterns": {"patterns": [{"pattern": "eval($X)"}, {"pattern-not": "eval('1')"}]},
    "pattern-either": {"pattern-either": [{"pattern": "eval($X)"}, {"pattern": "exec($X)"}]},
    "pattern-regex": {"pattern-regex": r"eval\("},
    "taint": {"mode": "taint", "pattern-sources": [{"pattern": "input()"}], "pattern-sinks": [{"pattern": "eval(...)"}]},
}


def _rule(extra):
    return {"id": "t-rule", "message": "m", "severity": "ERROR", "languages": ["python"], **extra}


@pytest.mark.parametrize("form", sorted(RULES))
def test_v2_checker_accepts_every_form_and_semgrep_agrees(form):
    v2_client, _ = _client(v2=True)
    ok, err = v2_client.validate_rule_schema(_rule(RULES[form]))
    assert ok, err
    code, out = _semgrep_validate(yaml.safe_dump({"rules": [_rule(RULES[form])]}))
    assert code == 0, out[-800:]


def test_v1_checker_unchanged():
    v1_client, _ = _client(v2=False)
    assert v1_client.validate_rule_schema(_rule(RULES["pattern"]))[0]
    for form in ("patterns", "pattern-either", "pattern-regex", "taint"):
        ok, err = v1_client.validate_rule_schema(_rule(RULES[form]))
        assert not ok and "pattern" in err


def test_v2_checker_rejects_incomplete_rules():
    v2_client, _ = _client(v2=True)
    assert not v2_client.validate_rule_schema(_rule({}))[0]
    assert not v2_client.validate_rule_schema(_rule({"mode": "taint", "pattern-sources": [{"pattern": "x"}]}))[0]


# ---------------------------------------------------------------- failure stages
def _parse(client, cfg, text):
    pi = load_case(ELIGIBLE[0], cfg)
    return client.parse_and_sanitize_response(text, pi)


def test_failure_stages():
    c, cfg = _client(v2=True)
    one = yaml.safe_dump({"rules": [_rule(RULES["patterns"])]})
    two = yaml.safe_dump({"rules": [_rule(RULES["pattern"]), _rule(RULES["pattern-regex"])]})
    no_match = yaml.safe_dump({"rules": [_rule({})]})
    cases = [("", "empty_response"), ("rules: [unclosed\n  - : :", "yaml_parse"),
             (two, "rule_count"), (no_match, "schema"), (one, None)]
    for text, stage in cases:
        result = _parse(c, cfg, text)
        assert c.last_failure_stage == stage, (text[:40], c.last_failure_stage, c.last_error)
        assert (result is not None) == (stage is None)


def test_api_error_vs_parse_crash():
    c, cfg = _client(v2=True)
    pi = load_case(ELIGIBLE[0], cfg)

    def boom(**kw):
        raise ConnectionError("server down")
    c.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=boom)))
    assert c.generate_rule(pi) is None and c.last_failure_stage == "api_error"

    reply = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="rules: []"))])
    c.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: reply)))
    c.parse_and_sanitize_response = lambda *a: (_ for _ in ()).throw(TypeError("bad shape"))
    assert c.generate_rule(pi) is None and c.last_failure_stage == "parse_crash"


# ---------------------------------------------------------------- v1 untouched
def test_v1_defaults_untouched_and_apply_sets_v2():
    d = Config()
    assert d.rule_schema_policy == "legacy_pattern_only"
    assert getattr(d, "prompt_variant", "autogrep_default") == "autogrep_default"
    cfg = run_v2_settings.apply(build_config("qwen2.5-coder:7b-instruct"))
    assert (cfg.rule_schema_policy, cfg.prompt_variant, cfg.construction_mode) == \
        ("semgrep_search_taint_v2", "autogrep_v2", "original_prompt")
