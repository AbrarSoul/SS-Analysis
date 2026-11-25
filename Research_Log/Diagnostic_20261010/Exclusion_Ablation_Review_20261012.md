# Review of the 42-rule exclusion-composition ablation

Reviewed 2026-10-12 Europe/Helsinki. Scope: retained ablation, interpretation, serializer change and regression coverage. No implementation or historical results were edited. No model calls were made.

## Verdict

The retained complete-success result is reproducible: **0 gained, 9 lost, 33 unchanged** across 42 rule instances covering 19 cases. Eight complete-success losses follow activation of exclusions in CASE-0220/CASE-0323 instances. However, the claimed unrelated “nesting artifact” is not supported: controlled scans show activation of a previously ignored `pattern-inside` constraint. The serializer's latest workaround therefore reintroduces ignored constraints. Separately, the reported single FP improvement is a rule-parse failure incorrectly counted as FP-to-TN.

These are material issues in the new experiment's attribution and prototype, so the investigation cannot yet be described as fully closed.

## What was verified

- Reran the full two-file regression suite: **30 passed**. The new test passes, but enforces the wrong scope behavior, explained below.
- Independently read all 126 retained original/isolated/rewritten evaluations, checked six samples per arm, equal sample hashes across arms, and source hashes against the retained inventory entries and copied originals.
- All 42 original replay outcome vectors, not merely complete-success booleans, match their historical iterative evaluations.
- Recomputed 0 gained, 9 lost and 33 unchanged complete successes. The original-to-isolated step accounts for one complete-success loss; isolated-to-rewritten accounts for eight.
- Inspected all eight exclusion-loss pattern pairs. Seven are text-identical after trimming; one differs by a trailing comma. They are eight instances from two case/rule-ID families, not two byte-identical rule files (six distinct literal pattern/exclusion pairs appear in these eight instances).
- Ran seven focused scans with verified Semgrep 1.177.0 to distinguish ignored scope constraints from a nesting defect. All seven scans completed successfully.

## High: CASE-0063 reflects an activated scope constraint, not a nesting defect

Semgrep's [official rule syntax](https://docs.semgrep.dev/writing-rules/rule-syntax) specifies that `pattern-inside` must be nested under `patterns` or `pattern-either`; it restricts findings to the matching enclosing construct. A top-level sibling is not the documented composition.

The retained CASE-0063 rule asks for `function $FUNC(...) { ... }`, a named-function form. The vulnerable regex in `variant_vulnerable_01.js:633` occurs inside an **anonymous function expression** assigned around line 625. The following scans of the real file establish the difference:

| Rule form | Matched lines |
|---|---|
| Bare regex pattern, no scope clause | 633 |
| Regex plus sibling named-function `pattern-inside` | 633 |
| Regex plus sibling impossible function name `REVIEW_DOES_NOT_EXIST` | 633 |
| Nested regex plus named-function `pattern-inside` | none |
| Nested regex plus anonymous `function(...) { ... }` scope | 633 |

Thus the sibling form finds the code even when the requested enclosing function demonstrably does not exist. The nested form enforces scope; choosing a scope expression that fits the actual anonymous function restores the match. This is not evidence that nesting arbitrarily loses a valid match.

An independent Python control using the **current TypedRule serializer** confirms the general defect:

```python
def allowed():
    foo("inside")

foo("outside")
```

With `pattern='foo($X)'` and `pattern_inside='def allowed(...):\n    ...'`, the serializer matches lines **2 and 4**. Correctly nesting the same clauses matches **only line 2**. This test needs both in-scope and out-of-scope code; a positive-only fixture cannot establish that the constraint works.

Required correction: `pipeline/typed_rule.py:148–157` must compose scope constraints rather than emit ignored siblings. Replace the new test's demand that `patterns` be absent with a behavioral test of scope inclusion/exclusion. The real CASE-0063 test should distinguish named and anonymous function scopes, instead of requiring an over-restrictive named-function rule to detect the anonymous-function sample. Any repair of the generated scope text must be a separately labeled semantic intervention, not hidden inside the serializer.

Rename the ablation's original-to-isolated transition as **positive/scope-constraint activation**, with the CASE-0063 attribution supported by these probes. The third arm is useful; its causal interpretation was wrong. The single complete-success loss in that step and four hidden-positive losses remain observations, but should not be described as an unrelated Semgrep nesting bug.

## High: the apparent FP improvement comes from a failed scan

Retained artifact:
`results/diagnostic_20261010/_exclusion_ablation_20261011T225111285041Z/qwen3_v3/CASE-0184/rewritten_hidden/evaluation.json`.

The rewritten rule has `scan_ok=false`, return code 2 and a Java **Rule parse error** in its newly active exclusion. The exclusion contains three successive `File.createTempFile(...)` expressions. The original and isolated scans are clean.

The script at `pipeline/exclusion_composition_ablation.py:181–184` compares sample outcome strings without requiring valid scans. The runner's fallback FN/TN labels on the failed scan are consequently treated as two hidden TP losses and one benign FP-to-TN improvement. A failed rule did not successfully reject benign code, so this is not a specificity improvement or a demonstrated exclusion match.

Recomputed conditional behavior transitions, requiring both compared scans to be clean:

| Comparison | Evaluable instance pairs | Hidden TP losses | Hidden FP reductions |
|---|---:|---:|---:|
| Original → isolated | 42 | 4 | 0 |
| Isolated → fully rewritten | 41 | 16 | 0 |
| Original → fully rewritten | 41 | 20 | 0 |

One original-to-rewritten pair is **unevaluable because the rewritten rule fails compilation**. Keep it in the all-requested E2E denominator as a failed output, but report it separately from behavioral FN/TN transitions. CASE-0184 was already an E2E failure, so this correction does not change the 0/9/33 complete-success totals.

The defensible false-positive statement is: **among 41 pairs with successful scans on both sides, no hidden-negative outcome changed; one rewritten pair was unevaluable.** The existing “one FP improved” statement should be withdrawn. No broad absence-of-inflation conclusion follows outside this accepted-rule development sample.

## Interpretation of the remaining eight losses

The self-cancelling exclusions in CASE-0220/CASE-0323 are supported by the retained patterns and executions. They reveal that a rule may pass this benchmark while some authored constraints are ignored, and that enforcing those constraints can expose contradictory intent. This is useful evidence for the research question about whether visible acceptance establishes reliable rule semantics.

Keep two outcomes distinct: enforcing the intended DSL can improve fidelity to the authored rule, while reducing complete-success performance. A future method's lower E2E score remains a measured regression on the prespecified task metric; its explanation should be reported, not used to redefine failure after observing results. Also, these are fixed-rule rewrites, not generations under a typed prompt. A model shown a different output contract and given compiler/visible feedback may generate different clauses. This experiment cannot predict that future arm's score.

Historical scores should remain frozen as records of the literal executed outputs. The matching replay supports those measurements within the existing benchmark; it does not replace the still-pending independent review of vulnerability and transformation semantics.

## Next action

Restore scope-preserving serialization and test both sides of the scope constraint. Fix ablation tallies to separate compile failures from behavioral transitions, and revise the attribution/documentation. Those reporting corrections can use the already-retained 126 evaluations; a fresh 42-rule ablation is not needed just to correct counts. Once the serializer behavior is verified, return to the planned controlled comparison and outstanding independent review.

## Evidence and file accounting

Added this review, `exclusion_ablation_review_checks.py`, two timestamped `exclusion_review_artifacts_*` directories, and three command logs labeled `exclusion_ablation_review_checks`, `exclusion_ablation_review_regressions`, and `exclusion_ablation_review_checks_v2`. The first audit intentionally asserted clean scans, encountered the retained CASE-0184 error and stopped; the revised checker records failed scans as evidence and completes. Both command records are retained.

The completed artifact directory `exclusion_review_artifacts_20261011T232424448186Z/` contains source hashes, audited per-instance losses, all seven probe rules/outputs, findings.json, and valid_scan_transition_counts.json. The earlier stopped directory retains any version-probe logs/settings it created. README is linked to this review and events.jsonl receives an append-only milestone with exact file hashes. Eight reviewed implementation/test/user-document files remain unchanged. No benchmark, source rule, historical output, original tracking/log text or implementation was edited; imports/tests may refresh caches. Four regression scans and seven targeted scans ran outside the sandbox for certificate initialization. No model inference or fresh full ablation was launched.
