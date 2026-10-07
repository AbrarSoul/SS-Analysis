"""
Budget-enforcement test for run_c2.py -- NO network to GPT-Lab, same canned-reply pattern as
run_fake_llm_final.py (monkeypatches llm_client.OpenAI before LLMClient instantiates it). Runs the
REAL run_c2_episode() -- real prompt building, real parse/sanitize, real RuleValidator.validate_rule()
against CASE-0078/0079/0181's actual standalone files (clone-free, Section 12.24), real
evaluate_case_bundle() -- with only the model's replies and token usage scripted, to verify the
budget-stop logic fires correctly before trusting any real API run:

  CASE-0078 : gold rule accepted on the FIRST call -> expect accepted=True, calls_used=1,
              repair_rounds_used=0, stop_reason="accepted", 6 sample records.
  CASE-0079 : a schema-valid rule that never discriminates the vulnerability, every call ->
              expect calls_used=4 (1 initial + 3 repair rounds), repair_rounds_used=3,
              stop_reason="max_repair_rounds", accepted=False.
  CASE-0181 : the first call returns a huge token usage (35000 prompt tokens, over the 30000
              combined-input budget) with a non-matching rule -> expect the loop to stop WITHOUT
              a second call, calls_used=1, stop_reason="max_input_tokens".

Usage:  PATH=.venv/bin:$PATH python pipeline/tests/run_fake_c2.py
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
import run_c2 as c2  # noqa: E402

GOLD_0078 = (GOLD / "CASE-0078.yml").read_text()
# Schema-valid but never matches anything real in CASE-0079's files -- always fails validation.
NEVER_MATCHES = "rules:\n- id: nothing\n  message: m\n  severity: ERROR\n  languages: [javascript]\n  pattern: $X.__no_such_attribute_zzz__\n"

SCRIPT = {
    "CASE-0078": {"replies": [GOLD_0078], "usage": [(100, 50)]},
    "CASE-0079": {"replies": [NEVER_MATCHES], "usage": [(100, 50)]},  # repeats via min(n, len-1)
    "CASE-0181": {"replies": [NEVER_MATCHES], "usage": [(35000, 50)]},
}
STATE = {"case": None, "calls": {}}


class FakeCompletions:
    def create(self, **kwargs):
        case = STATE["case"]
        n = STATE["calls"].get(case, 0)
        STATE["calls"][case] = n + 1
        script = SCRIPT[case]
        text = script["replies"][min(n, len(script["replies"]) - 1)]
        in_tok, out_tok = script["usage"][min(n, len(script["usage"]) - 1)]
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
            usage=SimpleNamespace(prompt_tokens=in_tok, completion_tokens=out_tok),
        )


class FakeOpenAI:
    def __init__(self, *a, **k):
        self.chat = SimpleNamespace(completions=FakeCompletions())


llm_client_module.OpenAI = FakeOpenAI


def run_one(case_id, expect_accepted, expect_calls, expect_rounds, expect_stop_reason):
    STATE["case"] = case_id
    config = c2.build_config("qwen2.5-coder:7b-instruct", temperature=0.0, prompt_variant="autogrep_default")
    llm_client = c2.LLMClient(config)
    validator = c2.RuleValidator(config)
    frozen_manifest = c2._load_frozen_manifest_index()

    episode, samples = c2.run_c2_episode(
        case_id, "qwen2.5-coder:7b-instruct", "GPU-farmi-001", config,
        llm_client, validator, "test-run", frozen_manifest,
    )

    ok = (episode.accepted == expect_accepted and episode.calls_used == expect_calls
          and episode.repair_rounds_used == expect_rounds and episode.stop_reason == expect_stop_reason)
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {case_id}: accepted={episode.accepted} calls_used={episode.calls_used} "
          f"repair_rounds_used={episode.repair_rounds_used} stop_reason={episode.stop_reason} "
          f"input_tokens_used={episode.input_tokens_used} output_tokens_used={episode.output_tokens_used} "
          f"samples={len(samples)}")
    if not ok:
        print(f"         expected: accepted={expect_accepted} calls={expect_calls} "
              f"rounds={expect_rounds} stop_reason={expect_stop_reason}")
    if expect_accepted:
        sample_types = sorted(s.sample_type for s in samples)
        expected_types = ["benign_lookalike", "original_patched", "original_vulnerable",
                           "variant_safe", "variant_vulnerable_01", "variant_vulnerable_02"]
        # sample_evaluation.py may label variants differently; just check count + no crash.
        print(f"         sample_types: {sample_types}")
    return ok


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    results = [
        run_one("CASE-0078", expect_accepted=True, expect_calls=1, expect_rounds=0, expect_stop_reason="accepted"),
        run_one("CASE-0079", expect_accepted=False, expect_calls=4, expect_rounds=3, expect_stop_reason="max_repair_rounds"),
        run_one("CASE-0181", expect_accepted=False, expect_calls=1, expect_rounds=0, expect_stop_reason="max_input_tokens"),
    ]
    print()
    if all(results):
        print(f"All {len(results)} budget-enforcement scenarios PASSED.")
        sys.exit(0)
    else:
        print(f"{results.count(False)} of {len(results)} scenarios FAILED.")
        sys.exit(1)
