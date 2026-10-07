"""
Budget/call-sequence test for run_c3.py -- NO network to GPT-Lab, same canned-reply pattern as
run_fake_llm_final.py / run_fake_c2.py (monkeypatches llm_client.OpenAI before LLMClient
instantiates it). Runs the REAL run_c3_episode() -- real prompt building, real parsing, real
RuleValidator.validate_rule()/evaluate_case_bundle() against real curated-case files -- with only
the 5 agents' replies scripted per call position within the episode, to verify the budget
resolution (C3_Scope.md decision 2: exactly 6 calls, 1 repair round, no 2nd Semantic Review call)
fires correctly before trusting any real API run.

  CASE-0078 / accept_round0 : rule generation produces the known-good gold rule directly;
                              syntax review says NOT_A_SYNTAX_ERROR; semantic review ACCEPTS.
                              Expect: calls_used=4, accepted_at_round=0, stop_reason=accepted_round0.
  CASE-0078 / accept_round1 : rule generation produces a broken rule; semantic review rejects;
                              rule repair produces the gold rule; syntax review round1 confirms it's
                              fine (now valid via real re-execution).
                              Expect: calls_used=6, accepted_at_round=1, stop_reason=accepted_round1.
  CASE-0079 / never_accepted: every call produces a rule that never validates.
                              Expect: calls_used=6, accepted=False, stop_reason=rejected_round1.

Usage:  PATH=.venv/bin:$PATH python pipeline/tests/run_fake_c3.py
"""
import os
import sys
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("GPTLAB_API_KEY", "not-used-in-this-test")
ROOT = Path(__file__).resolve().parents[2]
GOLD = ROOT / "pipeline" / "tests" / "gold_rules_final"
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

import llm_client as llm_client_module  # noqa: E402
import run_c3 as c3  # noqa: E402

GOLD_0078 = (GOLD / "CASE-0078.yml").read_text()
NEVER_MATCHES = "rules:\n- id: nothing\n  message: m\n  severity: ERROR\n  languages: [javascript]\n  pattern: $X.__no_such_attribute_zzz__\n"
BROKEN_FIRST = "rules:\n- id: broken\n  message: m\n  severity: ERROR\n  languages: [python]\n  pattern: $X.__no_such_attribute_zzz__\n"

# Scripted replies, indexed by call position (1-based) within the episode:
# 1=Patch Analysis, 2=Rule Generation, 3=Syntax Review r0, 4=Semantic Review r0,
# 5=Rule Repair, 6=Syntax Review r1.
SCRIPTS = {
    "accept_round0": {
        "case_id": "CASE-0078",
        "replies": {
            1: "MECHANISM: m\nSOURCE: s\nSINK: k\nFIX: f",
            2: GOLD_0078,
            3: "DIAGNOSIS: NOT_A_SYNTAX_ERROR\nEXPLANATION: fine\nCORRECTED_RULE:\nNONE",
            4: "VERDICT: ACCEPTED\nDIAGNOSIS: NONE\nREPAIR_INSTRUCTIONS: NONE",
        },
    },
    "accept_round1": {
        "case_id": "CASE-0078",
        "replies": {
            1: "MECHANISM: m\nSOURCE: s\nSINK: k\nFIX: f",
            2: BROKEN_FIRST,
            3: "DIAGNOSIS: NOT_A_SYNTAX_ERROR\nEXPLANATION: fine\nCORRECTED_RULE:\nNONE",
            4: "VERDICT: NOT_ACCEPTED\nDIAGNOSIS: MISS\nREPAIR_INSTRUCTIONS: fix the pattern to match the real vulnerable code",
            5: GOLD_0078,
            6: "DIAGNOSIS: NOT_A_SYNTAX_ERROR\nEXPLANATION: fine\nCORRECTED_RULE:\nNONE",
        },
    },
    "never_accepted": {
        "case_id": "CASE-0079",
        "replies": {
            1: "MECHANISM: m\nSOURCE: s\nSINK: k\nFIX: f",
            2: NEVER_MATCHES,
            3: "DIAGNOSIS: NOT_A_SYNTAX_ERROR\nEXPLANATION: fine\nCORRECTED_RULE:\nNONE",
            4: "VERDICT: NOT_ACCEPTED\nDIAGNOSIS: MISS\nREPAIR_INSTRUCTIONS: try harder",
            5: NEVER_MATCHES,
            6: "DIAGNOSIS: NOT_A_SYNTAX_ERROR\nEXPLANATION: fine\nCORRECTED_RULE:\nNONE",
        },
    },
}
STATE = {"scenario": None, "call_count": 0}


class FakeCompletions:
    def create(self, **kwargs):
        STATE["call_count"] += 1
        reply = SCRIPTS[STATE["scenario"]]["replies"][STATE["call_count"]]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))])


class FakeOpenAI:
    def __init__(self, *a, **k):
        self.chat = SimpleNamespace(completions=FakeCompletions())


llm_client_module.OpenAI = FakeOpenAI


def run_scenario(name, expect_accepted, expect_calls, expect_round, expect_stop_reason):
    STATE["scenario"] = name
    STATE["call_count"] = 0
    case_id = SCRIPTS[name]["case_id"]

    config = c3.build_config("qwen2.5-coder:7b-instruct", temperature=0.0, prompt_variant="autogrep_default")
    llm_client = c3.LLMClient(config)
    validator = c3.RuleValidator(config)
    frozen_manifest = c3._load_frozen_manifest_index()

    episode, samples = c3.run_c3_episode(
        case_id, "qwen2.5-coder:7b-instruct", "C3-E", config, llm_client, validator,
        "test-run", frozen_manifest, max_tokens=512,
    )

    ok = (episode.accepted == expect_accepted and episode.calls_used == expect_calls
          and episode.accepted_at_round == expect_round and episode.stop_reason == expect_stop_reason)
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name} ({case_id}): accepted={episode.accepted} calls_used={episode.calls_used} "
          f"accepted_at_round={episode.accepted_at_round} stop_reason={episode.stop_reason} samples={len(samples)}")
    if not ok:
        print(f"         expected: accepted={expect_accepted} calls={expect_calls} "
              f"round={expect_round} stop_reason={expect_stop_reason}")
    return ok


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    results = [
        run_scenario("accept_round0", expect_accepted=True, expect_calls=4, expect_round=0, expect_stop_reason="accepted_round0"),
        run_scenario("accept_round1", expect_accepted=True, expect_calls=6, expect_round=1, expect_stop_reason="accepted_round1"),
        run_scenario("never_accepted", expect_accepted=False, expect_calls=6, expect_round=None, expect_stop_reason="rejected_round1"),
    ]
    print()
    if all(results):
        print(f"All {len(results)} C3 budget-and-workflow scenarios PASSED.")
        sys.exit(0)
    else:
        print(f"{results.count(False)} of {len(results)} scenarios FAILED.")
        sys.exit(1)
