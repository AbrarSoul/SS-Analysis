# Qwen3 mechanism run v2 review

Reviewed the user-supplied terminal output against the saved environments, requests, responses and episodes. The command completed with exit 0 and all 24 cases recorded. No model calls or Semgrep scans were launched by this review.

## Observed comparison

| Metric, iterative condition | Original-prompt diagnostic (`qwen3_v3`) | Mechanism run v1 | Mechanism run v2 |
|---|---:|---:|---:|
| Complete E2E successes | 6/24 (25.0%) | 4/24 (16.7%) | 5/24 (20.8%) |
| Legacy visible acceptance | 19/24 | 11/24 | 15/24 |
| Correct-location visible acceptance | 18/24 | 10/24 | 13/24 |
| Accepted hidden-positive hits / all requested positives | 30/48 | 16/48 | 21/48 |
| Hidden false positives / evaluated accepted negatives | 8/38 | 4/22 | 4/30 |
| Total model calls | 34 | 55 | 44 |

V2 passes CASE-0063, CASE-0134, CASE-0136, CASE-0220 and CASE-0221. Relative to mechanism v1 it gains CASE-0063, CASE-0134 and CASE-0220, but loses CASE-0276 and CASE-0323: net +1 case. Relative to the original prompt it gains CASE-0063 and loses CASE-0276 and CASE-0323: net -1 case. These are descriptive differences on the selected development subset, not a full-benchmark or statistically established improvement.

All five complete successes were already present in the first attempts. Retries add visible acceptance for CASE-0222 and CASE-0239 but no complete successes. Thirteen cases used one call, two used two calls and nine used three calls. The 20 additional calls beyond one per case recovered zero E2E successes.

Reported usage totals are 59,746 input tokens and 10,460 output tokens. All 44 recorded provider finish reasons are `stop`; the v1 truncation did not recur in this run. Recorded provider-call elapsed time is approximately 147.28 seconds, excluding scans and other overhead; no monetary cost or controlled speed improvement is inferred.

## What changed

The model, temperature, 2048-token cap, three-call limit, frozen selection, schema policy and Semgrep 1.177.0 match mechanism v1. The recorded runner hash also matches v1. The LLM client hash changed from `0319a039721f75f6ec461e8b32963c630c2ae78c04dbc98c9e4c83aa7428e59f` to `438d96e05cc9cf6e69c9f40b75b3130e2243c5bf13fdac1aff93b56bc5eb1fc7`.

Actual captured requests confirm the revised prompt restores the original language-specific example section and adds guidance explaining that multiple `patterns` entries combine constraints at the same code location; separate sequential statements should use a multiline pattern. All 24 first-attempt requests differ from v1, as do all 24 response texts. This is a changed prompt, not simply a repeat of an identical prompt at temperature zero. The contributions of restoring examples, added guidance and generation variability are not separately measured.

The CLI and environment still call the prompt `diagnostic_mechanism_v1` despite its changed content. Distinguish these conditions using the output directory, captured requests and recorded source hashes; do not pool them as identical-prompt repetitions. Future prompt changes should receive distinct immutable identifiers.

## Remaining concrete problems

1. The restored example YAML is malformed. Extracting the literal example blocks from captured v2 requests, applying `textwrap.dedent`, and running `yaml.safe_load` produces `expected <block end>, but found '<block mapping start>'` at relative line 5 for Python (CASE-0134), JavaScript (CASE-0220) and Java (CASE-0221). Their indentation places fields incorrectly relative to each rule's `id`. The TypeScript example section is empty. These examples were inherited from the original prompt; this is not evidence that restoring them caused every new failure. They should be corrected and validated before another prompt experiment, including DSL validation after YAML parsing succeeds.
2. CASE-0238 still fails YAML parsing on all three attempts because an unquoted scalar contains `escapeFormulae: true`. Add explicit quoting/block-scalar guidance in a separately recorded prompt revision; preserve the failed outputs.
3. CASE-0298 still encounters syntax errors on the frozen `.ts` targets in all three attempts. The runner has not adopted the separately proposed TSX staging fix.
4. CASE-0323 fails rule parsing in every attempt; CASE-0116 has rule/schema errors across its attempts. A clean process exit is not evidence of valid rules or successful scans.
5. The legacy acceptance gate remains active. CASE-0184 and CASE-0081 count as accepted despite findings outside their original vulnerable location; neither is an E2E success. CASE-0184 also has only wrong-location findings on both hidden positives. These are not missing-location-annotation recoveries for the four previously identified helper cases.

V2's raw summary has 23 evaluations because CASE-0238 never parsed; three other raw evaluations report scan errors. Its iterative summary has only 15 evaluations, all error-free, because rejected cases have no iterative hidden scan. All 24 requested cases remain in the success denominator.

## Decision

Preserve v2 as a partial numerical recovery from mechanism v1, still below the original-prompt diagnostic. Do not promote it or rerun all models yet. First finish the versioned evaluator changes and validate every prompt example as YAML and Semgrep DSL. Replay stored artifacts where possible, then freeze an explicitly named prompt for a controlled small trial. Avoid changing several untracked instructions between runs, and keep hidden samples/outcomes unavailable to the repair loop. Any workflow selected on this subset requires fresh held-out confirmation.

## Provenance and review changes

- Run directory: `results/diagnostic_20261010/qwen3_mechanism_v2/`.
- Command log: `Research_Log/Diagnostic_20261010/commands/20261010T223535796131Z_qwen3_mechanism_v2.log`.
- Recorded runner hash: `82bcb158e3b7f13d4d10302e1be9d1e54e82e8eabe84401207f40fa91175976f`.
- Selection hash: `b473cb7b4d6737b5d2a822f8a01321e8e984f3cd314b947ee15cd29cd7e591b1`.

This review adds this document, links it from the audit README and appends an event with document and source hashes. Code, prompts, benchmark labels, model outputs and `Correction_Log.md` were not modified. Earlier artifact inventories remain snapshots of their recorded checkpoint time.
