# Review of the bounded investigation changes

Reviewed 2026-10-12 Europe/Helsinki (command logs use 2026-10-11 UTC). Scope: the two modified and four added files named by the user, the generated TSX stage, and their claims against Items 1–5 of Research_Direction_20261011.md. This is a review, not an implementation fix or a new model experiment. C3/C4 remain deferred.

## Overall assessment

Useful progress, but the bounded investigation is not complete. Integrated TSX staging and additive annotations work for the saved baseline. The typed serializer has a confirmed behavioral defect, the model stopping policy remains location-blind, the failure audit omits rejected-episode causes, and the probe design's proposed semantic oracle is circular. These findings should be resolved before a controlled model comparison.

## Verified checks

- Existing regression suite: 18 passed. These tests do not exercise the new serializer, staging-cache integrity, or a disagreement between legacy and location-aware model acceptance.
- Pinned Semgrep 1.177.0: replayed 24 first-attempt and 19 accepted-final saved baseline rules through the updated evaluator, totaling 43 scans. Raw and iterative complete success both remain 6/24. Raw scan errors decrease from two to one; CASE-0116 retains its Java rule-pattern parse error.
- Both conditions report 19 legacy-accepted cases versus 18 correctly localized visible passes. Corrected accepted-hidden-negative denominator is 36 rather than 38; hidden positive hits remain 30 and false positives remain eight. This is corrected reporting, not an observed improvement in generated rules.
- The six existing CASE-0298 staged files match the frozen source bytes. All 269 benchmark/baseline input files hashed around the replay remained unchanged. Seven reviewed source/document files also retained their hashes throughout the check.
- Recomputed saved failure-category counts for all six datasets and reproduced the tracking document's iterative table. The counts are reproducible; its inference about the dominant causes of all E2E failure is not justified by those counts.
- No model calls were made. The normal sandbox prevented Semgrep certificate initialization; the approved local compiler/replay command ran outside it with metrics and version checks disabled. Compiler inputs were local files.

## Findings requiring changes

### 1. High: single-exclusion serialization silently loses the exclusion

`pipeline/typed_rule.py:86–91` emits a top-level `pattern` with a sibling `pattern-not` for the simple case. Its comment calls this composition proven safe, but executable behavior contradicts that claim.

The retained synthetic target is:

```python
foo("unsafe")
foo("safe")
```

For `pattern='foo($X)'` and `pattern_not=['foo("safe")']`, the serializer's output matches **both lines** under pinned Semgrep 1.177.0, with exit code zero and no scan errors. The control with both clauses inside a `patterns` list matches **only line one**, as intended. Successful compilation is insufficient to verify exclusion semantics.

Required change: compose even a single exclusion under `patterns`, and add an executable positive/negative behavior regression. The CASE-0238 reconstruction uses the affected simple path, so its compiler PASS cannot establish that the exclusion works. Do not project this synthetic finding onto historical outcomes without replaying the particular rule and samples.

### 2. High: corrected summary fields do not change the model acceptance gate

`pipeline/diagnostic_v2.py:195` still accepts on `evaluation['legacy_accepted']`. Adding `*_corrected` fields in `report()` only filters summary numerators/denominators; it does not keep a wrong-location rule in the repair loop.

Reproduction with a mocked visible evaluation (`legacy_accepted=True`, `visible_correct=False`) makes exactly one generation call and writes a final accepted rule. This disproves completion of a location-aware stopping policy. The legacy metric remains useful for historical comparison, but a corrected workflow needs an explicitly named acceptance policy, correct-location feedback, and a regression for this disagreement. Replaying saved final rules cannot establish the counterfactual outcome of additional repair attempts under that policy.

### 3. High: the failure audit excludes important failures and overstates the conclusion

`pipeline/audit_failure_categories.py:34–39,71–85` receives only the raw or accepted-final evaluation. Missing evaluations return `None` and contribute to no failure category. Attempts containing output parsing errors or rejected visible scans are not analyzed. The iterative condition therefore reports zero construction errors and patched-code false positives largely because such candidates do not reach it.

| Run | Requested | Accepted-final evaluations | Omitted from iterative category counts |
|---|---:|---:|---:|
| Original `qwen3_v3` | 24 | 19 | 5 |
| Mechanism v1 | 24 | 11 | 13 |
| Mechanism v2 | 24 | 15 | 9 |
| Mechanism v3 | 24 | 14 | 10 |
| Mechanism v4 | 24 | 15 | 9 |
| Mechanism v5 | 24 | 13 | 11 |

Across these runs, 57 of 144 requested episodes have no iterative evaluation. Dividing observed category counts by 24 does not recover their causes. In v5, seven first attempts have scan errors, while the accepted-final audit reports zero construction errors. These statements can both be true, but they describe different populations.

Additional gaps: all `scan_ok=False` cases are labeled construction errors, conflating invalid rules with target parsing, timeouts, missing targets and annotation problems; an original vulnerable miss without any detection has no dedicated category and can yield `none (hurdle cleared)` if no other listed category applies. A synthetic original miss returns an empty category set. Saved episodes also retain their historical evaluation protocol; this auditor does not automatically apply the newly integrated evaluator.

Required change: report all requested episodes, missing outputs/API failures, parse/envelope failures, scanner/target failures, visible original misses, wrong-location detections and patched false positives using the retained attempt records. Keep accepted-rule hidden behavior as a separate conditional analysis. Define terminal versus ever-observed attempt counts explicitly. The current evidence supports structural misses and negative false positives as important failures **among accepted rules**. It does not isolate model capability as the cause or show that prompt wording has no effect.

### 4. High for experiment validity: the proposed probe check is circular

`Bounded_Investigation_Tracking.md:161–166` proposes discarding a probe if the accepted baseline rule fails it. A baseline rule passing the original pair has not established generalization—the present research is testing exactly that limitation. This check would discard valid probes that expose baseline brittleness and favor probes the baseline already handles. It cannot independently establish probe semantics.

Required change: validate transformations independently of the evaluated rule, using appropriate behavioral tests, carefully scoped AST/binding-aware transformations, and independent semantic review. A rule can be a diagnostic signal, but should not be the sole accept/reject oracle. Plain identifier substitution can change binding, attributes, strings or reflected names; a fixed substitution table alone does not ensure semantics preservation. Separate paths and independent construction also do not justify the absolute claim that hidden-data overlap can never occur. Define the allowed information, validation, overlap policy and held-out transformation families before experiments. This is a design defect, not a claim of observed leakage.

### 5. Medium: TypedRule is a prototype, not a validated model-output contract

`pipeline/typed_rule.py:56–64` validates form exclusivity, paired taint fields and severity, but Python type annotations do not enforce runtime types. Reproductions show:

- `pattern_either='foo()'` is accepted and serialized as five character-level alternatives.
- `pattern_either=[]` is accepted; the pinned compiler accepts this example and produces zero matches on the fixture. The empty form is not rejected as an invalid generation contract.
- Taint inputs with `pattern_not` are accepted, but the exclusion is silently discarded by `to_dict()`; inside/not-inside modifiers are likewise unused in the taint branch.

Required change: validate nonempty lists, element types, required strings/languages, and supported modifier combinations; reject unsupported combinations instead of silently dropping them. State the supported grammar explicitly, including omitted nested conjunctions, regex and taint features. Restricting that grammar can be a valid experimental intervention, but it changes expressiveness and needs measurement. A model-output decoder/schema and end-to-end integration are still pending.

### 6. Medium: TSX cache trusts existing files without verifying their bytes

`pipeline/diagnostic_v2.py:100–107` only populates a staging directory if it does not exist. A stale target is reused; a partial directory is not repaired. Both behaviors were reproduced in an isolated temporary fixture. Current real copies are correct, so this is a reproducibility defect rather than evidence that the replay used wrong bytes.

Required change: verify each staged file against its frozen source and repair or reject mismatches, with safe handling of interrupted/concurrent creation. Record the staging policy and annotation-file hashes in run provenance. The source hash captures code changes, but does not capture changes to the additive annotation file, whose absence is currently accepted silently.

### 7. Medium: the integration verifier prints an expectation without checking it

`pipeline/verify_scan_integration.py:41–45` prints the measured success count and the text “expected 6” but does not assert equality or fail on disagreement. Thus exit zero is not evidence of passing that expectation. It also reuses a fixed scratch output path and does not save a versioned comparison summary.

Required change: assert the expected counts and per-case successes, include scan-error expectations, and retain versioned input hashes, engine version and summary in a fresh output directory. Keep tests of policy behavior separate from score-preserving replays.

## Items 1–5 after review

| Item | Assessment |
|---|---|
| 1: Common evaluator | TSX/range integration and corrected reporting verified; corrected model stopping policy and additional integrity checks remain incomplete. |
| 2: Failure audit | Accepted-output descriptive audit reproduced; complete episode/attempt attribution remains incomplete. |
| 3: Independent review | Partial self-review only. The caveat is appropriate; six transformation spot-checks and selected reference-rule checks do not complete independent review of the 24-case diagnostic. The status table and “done” subsection also disagree. |
| 4: Typed construction | Useful prototype; exclusion behavior and contract validation need fixes before use. |
| 5: Probe factor | Design only; replace the circular probe oracle and specify semantic/overlap safeguards before implementation. |

Recommended order: correct serializer semantics and runtime validation; explicitly version and test acceptance policy; complete episode-level failure accounting; revise the probe design; obtain independent review. Then use bounded development trials. No evidence here warrants another broad paid run yet.

## Retained evidence and file accounting

Added by this review:

- This review document.
- `bounded_review_checks.py`: reproducible temporary-fixture checks, saved-result audit and optional pinned-compiler/baseline replay.
- `bounded_review_artifacts_20261011T210859192346Z/`: offline findings and reviewed-file hashes.
- `bounded_review_artifacts_20261011T210910647882Z/`: findings, three synthetic rules and scan outputs, and all 43 replay evaluations/stdout/stderr artifacts.
- Three command logs whose labels are `bounded_review_regressions`, `bounded_review_offline_checks` and `bounded_review_compiler_replay`.

Modified by this review: audit README (link) and append-only events.jsonl (command records and review milestone). Generated Python/pytest caches may be refreshed by imports/tests. Implementation files, original tracking document, Correction_Log, benchmark inputs and historical baseline outputs were not edited. Exact review artifact hashes are retained in the appended milestone.

The user's task-specific file list is consistent with current file presence, but Git alone cannot establish its full pre/post scope: these diagnostic files are untracked relative to HEAD. `Correction_Log.md` was already modified at review start; this does not establish that the bounded-investigation task changed it. The old audit baseline predates multiple later tasks. This review does not attribute pre-existing changes to the current task.
