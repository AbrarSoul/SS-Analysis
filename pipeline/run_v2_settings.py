"""
Run v2 settings: the single place where run v2 differs from the first run (v1).

Every value here implements a line of Research_Log/Run_v2_Specification.md. v1's own defaults in
autogrep/config.py are deliberately left unchanged, so every v1 result stays reproducible; run v2 code
calls apply() on each Config it builds instead.

Filled in issue by issue while preparing the run (phase 1 of the specification). Frozen with the rest
of the run at the freeze step.
"""

# Issue 1: accept every Semgrep matching form (pattern, patterns, pattern-either, pattern-regex, taint
# mode). Pinned Semgrep remains the authority on whether a rule is valid.
RULE_SCHEMA_POLICY = "semgrep_search_taint_v2"

# Issue 1: autogrep_default's prompt with only its visible defects corrected (valid example YAML, all
# matching forms listed, no `|>`, a valid response template, exactly one rule, a TypeScript example).
# See LLMClient._build_prompt_autogrep_v2.
PROMPT_VARIANT = "autogrep_v2"

# Issue 1: these are the failure stages LLMClient.last_failure_stage can report. Run v2 records the stage
# for every attempt, so failures are counted by stage instead of v1's single "yaml_valid" flag.
FAILURE_STAGES = ("empty_response", "no_rule_text", "yaml_parse", "rule_count", "schema",
                  "api_error", "parse_crash")


def apply(config):
    """Set run v2's values on an Autogrep Config (built by gptlab_config.build_config) and return it."""
    config.rule_schema_policy = RULE_SCHEMA_POLICY
    config.prompt_variant = PROMPT_VARIANT
    config.construction_mode = "original_prompt"
    return config


# ------------------------------------------------------------------------------------------------
# Issue 7: Part II (typed construction x probe feedback), made fair.
# ------------------------------------------------------------------------------------------------
# The four cells. Every cell uses the run v2 gate, scanner, feedback messages and the corrected examples
# (free-form: EXAMPLE_RULES_RUN_V2; typed: EXAMPLE_RULES_TYPED_JSON_RUN_V2 -- the same rules, both with a
# TypeScript entry). The only differences are the two named interventions.
PART2_CELLS = {
    "A": {"construction_mode": "original_prompt", "probe": False},
    "B": {"construction_mode": "typed_json", "probe": False},
    "C": {"construction_mode": "original_prompt", "probe": True},
    "D": {"construction_mode": "typed_json", "probe": True},
}
PART2_MAX_ATTEMPTS = 3          # v1's Part II budget, equal in every cell (typed JSON makes one call per attempt)
PART2_REPEATS = 3
CASE_ORDER_SEED = 20261125      # one fixed order for every model, cell and repeat (v1: A/B shuffled, C/D canonical)


def eligible_cases():
    import csv
    from pathlib import Path
    ref = Path(__file__).resolve().parent.parent / "benchmark" / "all_cases_reference.csv"
    return [r["case_id"] for r in csv.DictReader(open(ref)) if r["status"].startswith("eligible-150")]


def part2_cases(n=None, seed=CASE_ORDER_SEED, cases=None):
    """Part II case set, chosen WITHOUT any model result (v1 chose 24 cases from Qwen3-Coder's own outcomes).
    n=None: every case in `cases` (default: the eligible cases). Otherwise a random sample of n, stratified by
    language in proportion (largest remainder), with a fixed seed. Returned sorted by case id."""
    import json
    import random
    from collections import defaultdict
    from pathlib import Path
    cases = list(cases or eligible_cases())
    if n is None or n >= len(cases):
        return sorted(cases)
    root = Path(__file__).resolve().parent.parent / "benchmark" / "cases"
    by_lang = defaultdict(list)
    for cid in sorted(cases):
        by_lang[json.loads((root / cid / "metadata.json").read_text())["language"]].append(cid)
    quotas = {lang: n * len(ids) / len(cases) for lang, ids in by_lang.items()}
    take = {lang: int(q) for lang, q in quotas.items()}
    for lang in sorted(quotas, key=lambda l: (-(quotas[l] - take[l]), l))[: n - sum(take.values())]:
        take[lang] += 1
    rng = random.Random(seed)
    return sorted(cid for lang in sorted(by_lang) for cid in rng.sample(by_lang[lang], take[lang]))


def run_order(cases, seed=CASE_ORDER_SEED):
    """The single seeded case order used by every model, cell and repeat."""
    import random
    order = sorted(cases)
    random.Random(seed).shuffle(order)
    return order


def apply_part2_cell(config, cell):
    """Run v2 settings plus one Part II cell's construction mode."""
    apply(config)
    config.construction_mode = PART2_CELLS[cell]["construction_mode"]
    return config
