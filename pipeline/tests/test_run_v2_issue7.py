"""
Run v2, supervisor Issue 7 (Research_Log/Run_v2_Specification.md): Part II made fair.

What these tests establish:
- moving the typed examples to module level left every v1 typed prompt byte-identical (all 150 eligible cases);
- the run v2 typed prompt differs from v1 only by the TypeScript examples, and shows the same example rules as the
  free-form prompt; every typed example compiles and Semgrep accepts it;
- the typed parser reports failure stages like the YAML parser;
- Part II episodes run through the same episode code as Part I: typed mode, 3 attempts, no token/time limit, and
  for C/D a probe check after the visible gate (scripted fake model, real pinned Semgrep);
- Part II cases and their order come from a fixed seed and benchmark facts only, never from model results;
- probes are built from visible functions only and written outside benchmark/cases.
"""
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

os.environ.setdefault("GPTLAB_API_KEY", "not-used-offline-test")
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

import llm_client as L  # noqa: E402
import run_v2_episode as E  # noqa: E402
import run_v2_probes as P  # noqa: E402
import run_v2_settings as S  # noqa: E402
from case_loader import load_case  # noqa: E402
from gptlab_config import build_config  # noqa: E402
from typed_rule import TypedRule  # noqa: E402

ELIGIBLE = S.eligible_cases()
V1_TYPED_FINGERPRINT = "111cfa9f16053726c1b51619bc77edd1d98d47f2619c24482b18449e14e69c49"   # recorded before the refactor
SEMGREP = ROOT / ".venv" / "bin" / "semgrep"


def _client(cell=None):
    cfg = build_config("qwen2.5-coder:7b-instruct")
    if cell:
        S.apply_part2_cell(cfg, cell)
    return L.LLMClient(cfg), cfg


# ---------------------------------------------------------------- typed prompt
def test_v1_typed_prompts_unchanged():
    c, cfg = _client()
    h = hashlib.sha256()
    for cid in ELIGIBLE:
        pi = load_case(cid, cfg)
        for fb in (None, "Semgrep error: example feedback"):
            h.update(c._build_prompt_typed_json(pi, fb).encode())
            h.update(b"\0")
    h.update(c._system_message_typed_json().encode())
    assert h.hexdigest() == V1_TYPED_FINGERPRINT


def test_v2_typed_prompt_differs_only_by_typescript_examples():
    c, cfg = _client()
    langs = set()
    for cid in ELIGIBLE:
        pi = load_case(cid, cfg)
        lang = pi.file_changes[0].language
        langs.add(lang)
        v1, v2 = c._build_prompt_typed_json(pi, "fb"), c._build_prompt_typed_json_v2(pi, "fb")
        if lang != "typescript":
            assert v1 == v2, cid
        else:
            text = "\n\n".join(json.dumps(ex, indent=2) for ex in L.EXAMPLE_RULES_TYPED_JSON_RUN_V2["typescript"])
            marker = "EXAMPLES OF HIGH-QUALITY RULE SPECIFICATIONS:\n    \n"
            assert v1.count(marker) == 1
            assert v2 == v1.replace(marker, "EXAMPLES OF HIGH-QUALITY RULE SPECIFICATIONS:\n    " + text + "\n"), cid
    assert "typescript" in langs


def test_both_constructions_show_the_same_example_rules():
    for lang, typed in L.EXAMPLE_RULES_TYPED_JSON_RUN_V2.items():
        free = yaml.safe_load(L.EXAMPLE_RULES_RUN_V2[lang])["rules"]
        assert [r["id"] for r in free] == [ex["id"] for ex in typed], lang
        assert all(ex["languages"] == [lang] for ex in typed)


@pytest.mark.parametrize("lang", sorted(L.EXAMPLE_RULES_TYPED_JSON_RUN_V2))
def test_typed_examples_compile_and_semgrep_accepts_them(lang):
    rules = [TypedRule(**ex).to_dict() for ex in L.EXAMPLE_RULES_TYPED_JSON_RUN_V2[lang]]
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        yaml.safe_dump({"rules": rules}, f)
    p = subprocess.run([str(SEMGREP), "--validate", "--metrics=off", "--config", f.name],
                       capture_output=True, text=True, cwd=str(ROOT))
    os.unlink(f.name)
    assert p.returncode == 0, (p.stdout + p.stderr)[-800:]


def test_typed_parser_failure_stages():
    c, cfg = _client("B")
    pi = load_case(ELIGIBLE[0], cfg)
    ok = json.dumps({"id": "x-rule", "message": "m", "severity": "ERROR", "languages": ["python"], "pattern": "eval($X)"})
    for text, stage in [("", "empty_response"), ("{not json", "json_parse"), ("[1, 2]", "rule_count"),
                        (json.dumps({"pattern": "x", "bogus_field": 1}), "schema"), (ok, None)]:
        c._parse_typed_json_response(text, pi)
        assert c.last_failure_stage == stage, (text, c.last_failure_stage, c.last_error)


# ---------------------------------------------------------------- Part II episodes (fake model, real Semgrep)
VULN = 'import os\ndef run(x):\n    os.system("ls " + x)\n'
SAFE = 'import subprocess\ndef run(x):\n    subprocess.run(["ls", x])\n'
RANGES = {"original_vulnerable": [(3, 3)], "variant_vulnerable_1": [(3, 3)], "variant_vulnerable_2": [(3, 3)]}


@pytest.fixture()
def case_dir(tmp_path):
    for stem, text in {"vulnerable_source": VULN, "patched_source": SAFE, "variant_vulnerable_01": VULN,
                       "variant_vulnerable_02": VULN, "variant_safe_01": SAFE, "benign_lookalike": SAFE}.items():
        (tmp_path / f"{stem}.py").write_text(text)
    probes = tmp_path / "probes"
    probes.mkdir()
    (probes / "vulnerable_probe.py").write_text('def run(y):\n    os.system("ls " + y)\n')   # local renamed x -> y
    (probes / "patched_probe.py").write_text('def run(y):\n    subprocess.run(["ls", y])\n')
    return tmp_path


class FakeAPI:
    def __init__(self, script):
        self.script, self.calls = list(script), []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.calls.append(kw)
        text = self.script.pop(0)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
                               usage=SimpleNamespace(prompt_tokens=1000, completion_tokens=9000))


def _pi():
    cfg = build_config("qwen2.5-coder:7b-instruct")
    cid = next(c for c in ELIGIBLE if json.loads((ROOT / "benchmark/cases" / c / "metadata.json").read_text())["language"] == "python")
    return load_case(cid, cfg)


def _episode(cell, case_dir, script, probe=False):
    client, _ = _client(cell)
    client.client = FakeAPI(script)
    files = (case_dir / "probes" / "vulnerable_probe.py", case_dir / "probes" / "patched_probe.py") if probe else None
    ep = E.run_episode(client, _pi(), case_dir, "python", RANGES, "run", "CASE-TEST", "fake",
                       sleep=lambda s: None, max_attempts=S.PART2_MAX_ATTEMPTS, use_iterative_budget=False,
                       probe_files=files, workflows=("single_shot", "autogrep"))
    return ep, client.client


def _typed(**kw):
    return json.dumps({"id": "t-rule", "message": "m", "severity": "ERROR", "languages": ["python"], **kw})


def test_cell_b_typed_episode(case_dir):
    ep, api = _episode("B", case_dir, ["{broken", _typed(pattern="os.system(...)")])
    assert [a.failure_stage for a in ep.attempts] == ["json_parse", None]
    assert ep.attempts[1].accepted and ep.workflows["autogrep"]["accepted_attempt"] == 2
    assert ep.workflows["single_shot"]["accepted_attempt"] is None
    sysmsg, user = api.calls[0]["messages"][0]["content"], api.calls[0]["messages"][1]["content"]
    assert "single JSON object" in sysmsg and "EXAMPLES OF HIGH-QUALITY RULE SPECIFICATIONS" in user
    assert set(ep.workflows) == {"single_shot", "autogrep"}


def test_three_attempts_and_no_token_limit(case_dir):
    # 9,000 output tokens per call would stop v1's iterative loop; Part II's 3-attempt loop has no token limit.
    bad = yaml.safe_dump({"rules": [{"id": "t", "languages": ["python"], "message": "m", "severity": "ERROR",
                                     "pattern-regex": "def run"}]})
    ep, api = _episode("A", case_dir, [bad, bad, bad])
    assert len(api.calls) == 3 and ep.stop_reason == "max_attempts"
    assert all(a.within_iterative_budget for a in ep.attempts)


def test_cell_c_probe_feedback(case_dir):
    literal = yaml.safe_dump({"rules": [{"id": "t", "languages": ["python"], "message": "m", "severity": "ERROR",
                                         "pattern": 'os.system("ls " + x)'}]})      # misses the renamed probe
    good = yaml.safe_dump({"rules": [{"id": "t", "languages": ["python"], "message": "m", "severity": "ERROR",
                                      "pattern": "os.system(...)"}]})
    ep, api = _episode("C", case_dir, [literal, good], probe=True)
    a1, a2 = ep.attempts
    assert a1.accepted_visible_only and not a1.accepted
    assert a1.probe["passed"] is False and "vulnerable_probe_correct" in a1.probe["reason"]
    assert a2.feedback_in == E.FB_PROBE.format(reason=a1.probe["reason"])
    assert a2.accepted and a2.probe["passed"] is True


def test_cell_a_ignores_probes(case_dir):
    literal = yaml.safe_dump({"rules": [{"id": "t", "languages": ["python"], "message": "m", "severity": "ERROR",
                                         "pattern": 'os.system("ls " + x)'}]})
    ep, _ = _episode("A", case_dir, [literal])
    assert ep.attempts[0].accepted and ep.attempts[0].probe is None


# ---------------------------------------------------------------- case set and order
def test_part2_cases_all_and_sample():
    assert S.part2_cases() == sorted(ELIGIBLE) and len(ELIGIBLE) == 150
    s1, s2 = S.part2_cases(48), S.part2_cases(48)
    assert s1 == s2 and len(s1) == 48 and set(s1) <= set(ELIGIBLE)
    lang = {c: json.loads((ROOT / "benchmark/cases" / c / "metadata.json").read_text())["language"] for c in ELIGIBLE}
    for L_ in set(lang.values()):
        share = sum(lang[c] == L_ for c in ELIGIBLE) / 150 * 48
        assert abs(sum(lang[c] == L_ for c in s1) - share) < 1


def test_run_order_is_one_fixed_permutation():
    o1, o2 = S.run_order(ELIGIBLE), S.run_order(list(reversed(ELIGIBLE)))
    assert o1 == o2 and sorted(o1) == sorted(ELIGIBLE) and o1 != sorted(ELIGIBLE)


# ---------------------------------------------------------------- probes
def test_probe_builder_counts():
    eligible = [c for c in ELIGIBLE if isinstance(P.build(c)[0], P.ProbeResult)]
    assert len(eligible) == 87
    old = json.loads((ROOT / "benchmark/diagnostic_20261010/selection.json").read_text())["case_ids"]
    assert sum(c in eligible for c in old) == 11            # the October hand review also found 11


def test_materialize_writes_outside_benchmark_and_never_overwrites(tmp_path):
    cid = next(c for c in ELIGIBLE if isinstance(P.build(c)[0], P.ProbeResult))
    paths, rec = P.materialize(cid, tmp_path)
    assert rec["eligible"] and all(p.exists() and tmp_path in p.parents for p in paths)
    assert hashlib.sha256(paths[0].read_bytes()).hexdigest() == rec["vulnerable_probe_sha256"]
    with pytest.raises(FileExistsError):
        P.materialize(cid, tmp_path)
