# Verification of corrected exclusion ablation

Reviewed 2026-10-12 Europe/Helsinki. The two implementation/measurement findings in Exclusion_Ablation_Review_20261012.md can be closed for the inspected revision. No new substantive defect was found in those fixes. This is not a certification of the whole pipeline or completion of independent benchmark review.

## Checks completed

- Reran the two regression files: **31 passed**, including the new in-scope/out-of-scope behavior test. `TypedRule.to_dict()` again nests `pattern-inside` under `patterns`, enforcing the intended scope constraint. The separate sibling-form test records the engine's ignored-constraint behavior rather than requiring the serializer to produce it.
- The ablation now compares sample outcomes only when both scans succeed. Invalid scans are separately marked unevaluable, while still contributing failures to the all-instance complete-success measure.
- Independently recomputed the latest ablation from all 84 retained original/rewritten evaluations. Verified source hashes, copied originals, equal sample hashes within pairs, and each original replay's full outcome vector against its historical episode.
- Verified the latest result: **0 complete successes gained, 9 lost, 33 unchanged** among 42 instances. Behavioral comparisons have **41 evaluable pairs**, **20 hidden-positive hits lost**, zero gained, and **zero hidden-negative FP changes**. The one unevaluable rewrite is baseline CASE-0184's Java rule-parse failure. It remains a failure in the complete-success denominator; it is not counted as a real FN/TN transition.
- The nine complete-success losses belong to three case/rule-ID families: CASE-0220 (four instances), CASE-0323 (four), CASE-0063 (one). These are repeated development instances, not nine independent vulnerabilities or three byte-identical rule files.
- All three ablation directories and their summary files remain present. Their current summary hashes are recorded in Corrected_Ablation_Verification_20261012.json. This verifies present retained evidence, not an assertion that Git alone can establish every historical file operation.
- The appended Correction_Log entry correctly withdraws the nesting-artifact explanation and FP-improvement claim, and distinguishes faithful execution of authored constraints from measured E2E performance.

## Interpretation and next step

The evidence supports a narrower and useful conclusion: some accepted rules obtained successful benchmark outcomes while their scope/exclusion clauses were ignored. Enforcing those clauses exposed self-cancelling exclusions, an incorrect scope restriction and one previously inactive malformed pattern. This explains part of the diagnostic behavior without establishing a population-wide failure rate or predicting what a model will generate under a typed contract.

Maintain separate measures for executable validity, visible-pair discrimination, held-out sample behavior, complete success and resource cost. A lower complete-success rate is still lower performance on that prespecified metric even when the implementation obeys the authored logic more faithfully.

There is no need for another full ablation rerun solely to verify these corrections. Freeze this corrected analysis as exploratory evidence. The next work is independent semantic/reference review (Item 3), and a concrete frozen protocol for the controlled comparison: output contracts, supported grammar, acceptance policy, budgets, probe eligibility, candidate selection and held-out confirmation. That work should precede new broad inference runs. C3/C4 remain deferred.

## Non-blocking wording cleanup

The latest appended Correction_Log conclusion is sound. The rewritten tracking section still retains the older “will SURFACE, not regress” and “is not evidence ... worse” wording immediately before acknowledging that lower E2E is a regression. Its following paragraph also still opens by calling the earlier correct nesting behavior a “second, independent bug,” before explaining the reversal. Remove or explicitly label those superseded assertions to leave one consistent current interpretation. They do not affect the verified code or corrected numbers.

The tracking/summary language that says failed scans are excluded from “every outcome tally” should be read more precisely as **behavioral TP/FP transition tallies**; the code correctly retains them in all-instance complete-success accounting. No denominator change is recommended.

## File accounting

Added this closure note, `verify_corrected_ablation.py`, `Corrected_Ablation_Verification_20261012.json`, and two command logs labeled `corrected_ablation_closure_tests` and `corrected_ablation_closure_artifacts`. Updated audit README with the closure link and appended command/closure events with hashes to events.jsonl. Five reviewed implementation/test/user-document files were hashed and unchanged during verification. No implementation, original tracking/Correction_Log text, source rules, benchmark data or ablation output was edited. No model calls or fresh ablation scans were launched; the test suite ran five local Semgrep scans. Python/pytest caches may be refreshed by testing.

Git status still lists the project's pre-existing modified and untracked work. Accordingly, “clean” can describe intended task scope here, but not a literally clean Git working tree. This review makes no claim to reconstruct unrelated editing activity from Git status alone.
