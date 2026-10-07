"""
End-to-end pipeline test on FINAL-set cases with a FAKE model (no API key, no network to GPT-Lab).
Runs the real run_generation.run_model_on_cases() -- prompt building, raw capture, Autogrep's
retry/validation loop against the standalone extracted case files (Section 12.24: clone-free for curated
cases), and the six-sample bundle scorer -- while the model's replies are canned:

  CASE-0079, CASE-0181, CASE-0078 : a good gold rule on the first attempt
  CASE-0341                       : a match-nothing rule first, then its composite (patterns:/pattern-not-
                                     inside:) gold rule -- demonstrates the real, already-documented Autogrep
                                     schema limitation (no top-level `pattern:` key -> rejected), same as
                                     CASE-0079/0342 hit with real model output in Section 12.21
  CASE-0342                       : never-valid garbage (all attempts fail)

Usage:  PATH=.venv/bin:$PATH python pipeline/tests/run_fake_llm_final.py <results_dir>
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
import run_generation as rg  # noqa: E402

def _rule(rid, lang, pattern):
    return f"rules:\n- id: {rid}\n  message: m\n  severity: ERROR\n  languages: [{lang}]\n  pattern: {pattern}\n"


# Autogrep's schema requires a top-level `pattern:` (composite patterns:/pattern-not: rules are rejected), so the
# canned "good" answers are single-pattern rules -- exactly what a model can actually return through this pipeline.
NOTHING = _rule("nothing", "python", "$X.__no_such_attribute_zzz__")
GOLD_0341 = (GOLD / "CASE-0341.yml").read_text()
SCRIPT = {
    "CASE-0079": [_rule("buffer", "javascript", "new Buffer($X)")],
    "CASE-0181": [_rule("yaml-load", "python", "yaml.load($X)")],
    "CASE-0078": [_rule("and-return", "python", "return $X and $X == $Y")],
    # CASE-0341's own gold rule (gold_rules_final/), not the naive $D/$T/$N join pattern used earlier here:
    # os.path.join(config_states_dir, f"{timestamp}_{name}.json") appears IDENTICALLY in vulnerable_source.py
    # and patched_source.py -- the real fix sanitizes `name` beforehand, it doesn't change this call -- so a
    # rule matching just the join call can never discriminate the two. Found while re-verifying the
    # clone-free validator refactor (Section 12.24): the "failure" was this test's rule, not the refactor.
    "CASE-0341": [NOTHING, GOLD_0341],
    "CASE-0342": ["I am sorry, I cannot produce a rule for this."],
}
STATE = {"case": None, "calls": {}}


class FakeCompletions:
    def create(self, **kwargs):
        case = STATE["case"]
        n = STATE["calls"].get(case, 0)
        STATE["calls"][case] = n + 1
        replies = SCRIPT[case]
        text = replies[min(n, len(replies) - 1)]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


class FakeOpenAI:
    def __init__(self, *a, **k):
        self.chat = SimpleNamespace(completions=FakeCompletions())


llm_client_module.OpenAI = FakeOpenAI
_orig = rg.evaluate_case_from_curated


def _wrapped(autogen, case_id, *a, **k):
    STATE["case"] = case_id
    return _orig(autogen, case_id, *a, **k)


rg.evaluate_case_from_curated = _wrapped

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    results_root = Path(sys.argv[1])
    # No repo cache/clone setup needed: with the clone-free curated-case validator (Section 12.24),
    # rule_validator reads benchmark/cases/CASE-XXXX/{vulnerable_source,patched_source} directly for every
    # case here, since all 5 have patch_info.case_id set (built via case_loader.load_case()).
    rg.run_model_on_cases("qwen2.5-coder:7b-instruct", list(SCRIPT), results_root, max_retries=3,
                          temperature=0.0, prompt_variant="autogrep_default")
