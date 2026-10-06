"""
Per-role model-routing test for run_c4.py's C4-B variant -- same pattern as run_fake_c4.py (which
covers C4-A), adapted for C4-B's 2-distinct-model split (32b strong for analysis/generation/repair,
7b-instruct efficient for syntax/semantic review) instead of C4-A's 4 distinct models.

Scenario: C4-B on CASE-0078, scripted to accept at round 0. Verifies, for each of the 4 calls made,
that the `model` kwarg passed to the (faked) API matches C4-B's actual role assignment:
  call 1 (Patch Analysis)   -> qwen2.5-coder:32b
  call 2 (Rule Generation)  -> qwen2.5-coder:32b
  call 3 (Syntax Review)    -> qwen2.5-coder:7b-instruct
  call 4 (Semantic Review)  -> qwen2.5-coder:7b-instruct

Usage:  PATH=.venv/bin:$PATH python pipeline/tests/run_fake_c4b.py
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
import run_c4 as c4  # noqa: E402

GOLD_0078 = (GOLD / "CASE-0078.yml").read_text()

EXPECTED_MODEL_PER_CALL = {
    1: "qwen2.5-coder:32b",
    2: "qwen2.5-coder:32b",
    3: "qwen2.5-coder:7b-instruct",
    4: "qwen2.5-coder:7b-instruct",
}
REPLIES = {
    1: "MECHANISM: m\nSOURCE: s\nSINK: k\nFIX: f",
    2: GOLD_0078,
    3: "DIAGNOSIS: NOT_A_SYNTAX_ERROR\nEXPLANATION: fine\nCORRECTED_RULE:\nNONE",
    4: "VERDICT: ACCEPTED\nDIAGNOSIS: NONE\nREPAIR_INSTRUCTIONS: NONE",
}
STATE = {"call_count": 0, "model_mismatches": []}


class FakeCompletions:
    def create(self, **kwargs):
        STATE["call_count"] += 1
        n = STATE["call_count"]
        actual_model = kwargs.get("model")
        expected_model = EXPECTED_MODEL_PER_CALL.get(n)
        if actual_model != expected_model:
            STATE["model_mismatches"].append((n, expected_model, actual_model))
        reply = REPLIES[n]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))])


class FakeOpenAI:
    def __init__(self, *a, **k):
        self.chat = SimpleNamespace(completions=FakeCompletions())


llm_client_module.OpenAI = FakeOpenAI


def main():
    import logging
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    variant = "C4-B"
    role_models = c4.C4_CONFIGS[variant]
    unique_models = sorted(set(role_models.values()))
    configs = {m: c4.build_config(m, temperature=0.0, prompt_variant="autogrep_default") for m in unique_models}
    clients_by_model = {m: c4.LLMClient(configs[m]) for m in unique_models}
    clients = {role: clients_by_model[model_tag] for role, model_tag in role_models.items()}
    parser_client = clients["rule_generation"]
    validator = c4.RuleValidator(configs[unique_models[0]])
    frozen_manifest = c4._load_frozen_manifest_index()

    episode, samples = c4.run_c4_episode(
        "CASE-0078", variant, role_models, clients, parser_client, validator,
        "test-run", frozen_manifest, max_tokens=512,
    )

    routing_ok = len(STATE["model_mismatches"]) == 0
    workflow_ok = (episode.accepted and episode.calls_used == 4 and episode.accepted_at_round == 0
                   and episode.stop_reason == "accepted_round0" and len(samples) == 6)

    print(f"[{'PASS' if routing_ok else 'FAIL'}] per-role model routing "
          f"({STATE['call_count']} calls checked, {len(STATE['model_mismatches'])} mismatch(es))")
    for n, expected, actual in STATE["model_mismatches"]:
        print(f"         call {n}: expected model={expected!r}, got {actual!r}")

    print(f"[{'PASS' if workflow_ok else 'FAIL'}] workflow/budget (reusing C3's already-proven logic): "
          f"accepted={episode.accepted} calls_used={episode.calls_used} "
          f"accepted_at_round={episode.accepted_at_round} stop_reason={episode.stop_reason} samples={len(samples)}")

    if routing_ok and workflow_ok:
        print("\nAll C4-B routing-and-workflow checks PASSED.")
        sys.exit(0)
    else:
        print("\nSome checks FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
