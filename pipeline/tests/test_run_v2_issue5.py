"""
Run v2, supervisor Issue 5 (Research_Log/Run_v2_Specification.md): one shared attempt chain per model and case.

A scripted fake model replaces the API (no inference); Semgrep is the real pinned binary on a small made-up case.
What these tests establish:
- the chain stops at the first rule that passes the run v2 visible gate (location included);
- each rejected attempt's reason is the next attempt's feedback, and it appears in the next prompt;
- single_shot / autogrep / iterative are read from the same chain with v1's budgets;
- the iterative token and wall-clock limits are checked before each call, as in v1's run_c2.py;
- API errors are retried and never count as a model failure; persistent ones raise InfraError;
- every rule the chain produced is scored on all six samples; the run v2 system message is used.
"""
import csv
import os
import sys
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
import run_v2_settings  # noqa: E402
from case_loader import load_case  # noqa: E402
from gptlab_config import build_config  # noqa: E402

VULN = textwrap.dedent('''\
    import os
    def run(x):
        os.system("ls " + x)
''')
SAFE = textwrap.dedent('''\
    import subprocess
    def run(x):
        subprocess.run(["ls", x])
''')
RANGES = {"original_vulnerable": [(3, 3)], "variant_vulnerable_1": [(3, 3)], "variant_vulnerable_2": [(3, 3)]}


def _rule(**body):
    return yaml.safe_dump({"rules": [{"id": "t-rule", "languages": ["python"], "message": "m",
                                      "severity": "ERROR", **body}]})


GOOD = _rule(pattern="os.system(...)")                       # vulnerable line 3 only -> accepted
BOTH = _rule(**{"pattern-regex": "def run"})                 # matches the patched file too
WRONG_PLACE = _rule(**{"pattern-regex": "^import os$"})      # vulnerable file only, but line 1
NOT_YAML = "rules: [unclosed\n  - : :"
JS_RULE = yaml.safe_dump({"rules": [{"id": "t-js", "languages": ["javascript"], "message": "m",
                                     "severity": "ERROR", "pattern": "eval(...)"}]})


@pytest.fixture()
def case_dir(tmp_path):
    for stem, text in {"vulnerable_source": VULN, "patched_source": SAFE, "variant_vulnerable_01": VULN,
                       "variant_vulnerable_02": VULN, "variant_safe_01": SAFE, "benign_lookalike": SAFE}.items():
        (tmp_path / f"{stem}.py").write_text(text)
    return tmp_path


class FakeAPI:
    """Scripted chat.completions: each item is a reply text, an Exception, or (text, in_tokens, out_tokens)."""
    def __init__(self, script):
        self.script, self.calls = list(script), []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.calls.append(kw)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        text, tin, tout = item if isinstance(item, tuple) else (item, 1000, 300)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
                               usage=SimpleNamespace(prompt_tokens=tin, completion_tokens=tout))


def _patch_info():
    cfg = build_config("qwen2.5-coder:7b-instruct")
    cid = next(r["case_id"] for r in csv.DictReader(open(ROOT / "benchmark" / "all_cases_reference.csv"))
               if r["status"].startswith("eligible-150") and r["language"] == "python")
    return load_case(cid, cfg)


def _run(case_dir, script, clock=None):
    cfg = run_v2_settings.apply(build_config("qwen2.5-coder:7b-instruct"))
    client = L.LLMClient(cfg)
    client.client = FakeAPI(script)
    slept = []
    kw = {"sleep": slept.append}
    if clock:
        kw["clock"] = clock
    ep = E.run_episode(client, _patch_info(), case_dir, "python", RANGES, "run", "CASE-TEST", "fake", **kw)
    return ep, client.client, slept


def test_first_attempt_accepted(case_dir):
    ep, api, _ = _run(case_dir, [GOOD])
    assert ep.stop_reason == "accepted" and len(ep.attempts) == 1 and len(api.calls) == 1
    for wf in E.WORKFLOWS:
        assert ep.workflows[wf]["accepted_attempt"] == 1 and ep.workflows[wf]["calls"] == 1
    assert {r["outcome"] for r in ep.samples[1]} == {"TP", "TN"} and len(ep.samples[1]) == 6


def test_feedback_chain_and_workflows(case_dir):
    ep, api, _ = _run(case_dir, [NOT_YAML, BOTH, WRONG_PLACE, GOOD])
    a = ep.attempts
    assert [x.failure_stage for x in a] == ["yaml_parse", None, None, None]
    assert a[1].feedback_in == a[0].error and "YAML" in a[0].error
    assert a[2].feedback_in == E.FB_PATCHED_DETECTED
    assert a[3].feedback_in == E.FB_WRONG_LOCATION
    for att in a[1:]:
        assert "PREVIOUS ERROR TO FIX:\n" + att.feedback_in in att.prompt
    assert a[2].accepted_visible_only is True and a[2].accepted is False     # v1's gate would have stopped here
    assert ep.workflows["single_shot"]["accepted_attempt"] is None
    assert ep.workflows["autogrep"]["accepted_attempt"] is None and ep.workflows["autogrep"]["calls"] == 3
    assert ep.workflows["iterative"]["accepted_attempt"] == 4 and ep.workflows["iterative"]["calls"] == 4
    assert ep.workflows["autogrep"]["accepted_visible_only_attempt"] == 3
    assert sorted(ep.samples) == [2, 3, 4]                                    # attempt 1 produced no rule


def test_run_v2_system_message_and_prompt(case_dir):
    ep, api, _ = _run(case_dir, [GOOD])
    msgs = api.calls[0]["messages"]
    assert msgs[0]["content"] == ep.attempts[0].system_message and "pattern-either" in msgs[0]["content"]
    assert "CONTAINING EXACTLY ONE RULE" in msgs[1]["content"]


def test_iterative_token_budget_stops_attempt_4_only(case_dir):
    # Attempt 1 uses 7,000 output tokens: v1's run_c2 would refuse any further call; Autogrep has no token limit.
    ep, api, _ = _run(case_dir, [(NOT_YAML, 1000, 7000), BOTH, WRONG_PLACE])
    assert [x.within_iterative_budget for x in ep.attempts] == [True, False, False]
    assert ep.stop_reason == "iterative_budget" and len(api.calls) == 3
    assert ep.workflows["iterative"]["calls"] == 1 and ep.workflows["autogrep"]["calls"] == 3


def test_iterative_wall_clock(case_dir):
    t = {"now": 0.0}

    def clock():
        t["now"] += 200.0          # every reading advances 200 s, so the 10-minute limit is passed quickly
        return t["now"]
    ep, _, _ = _run(case_dir, [NOT_YAML, NOT_YAML, NOT_YAML], clock=clock)
    assert ep.attempts[0].within_iterative_budget is True
    assert not all(x.within_iterative_budget for x in ep.attempts)
    assert ep.workflows["iterative"]["calls"] < ep.workflows["autogrep"]["calls"] == 3


def test_wrong_language_rule_gets_specific_feedback(case_dir):
    ep, _, _ = _run(case_dir, [JS_RULE, GOOD])
    assert ep.attempts[0].error == E.FB_NOT_SCANNED.format(language="python")
    assert ep.attempts[0].gate_scan_status == {"original_vulnerable": "not_scanned", "original_patched": "not_scanned"}
    assert ep.workflows["autogrep"]["accepted_attempt"] == 2


def test_api_errors_are_retried_not_counted(case_dir):
    ep, api, slept = _run(case_dir, [ConnectionError("down"), TimeoutError("slow"), GOOD])
    assert len(ep.attempts) == 1 and ep.attempts[0].api_retries == 2 and ep.attempts[0].accepted
    assert slept == list(E.API_BACKOFF_SECONDS[:2])


def test_persistent_api_failure_raises(case_dir):
    with pytest.raises(E.InfraError):
        _run(case_dir, [ConnectionError("down")] * (E.API_RETRIES + 1))


def test_derive_workflows_reads_only_the_chain():
    def att(i, acc, within=True):
        return SimpleNamespace(index=i, accepted=acc, accepted_visible_only=acc, within_iterative_budget=within,
                               input_tokens=10, output_tokens=5)
    wf = E.derive_workflows([att(1, False), att(2, True)])
    assert wf["single_shot"]["accepted_attempt"] is None
    assert wf["autogrep"]["accepted_attempt"] == wf["iterative"]["accepted_attempt"] == 2
    assert wf["autogrep"]["input_tokens"] == 20
