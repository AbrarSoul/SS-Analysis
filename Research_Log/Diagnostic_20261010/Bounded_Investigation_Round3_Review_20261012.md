# Verification of the second-round fixes and recommended next experiment

Reviewed 2026-10-12 Europe/Helsinki. This is a verification/recommendation record, not a new model experiment or implementation change. C3/C4 remain deferred.

## Verified closures

- All 29 regression tests passed again, including the executable exclusions and legacy/corrected stopping-policy checks.
- The live TSX cache guard is removed. Its remaining textual reference is a comment, exactly as the user reports. Temporary-fixture checks confirm both stale-file and deleted-file repair on later calls within the same process.
- The auditor now reads the recorded acceptance policy. A corrected-policy wrong-location rejection is tagged `never_accepted`; absent evaluable output is `original_unevaluable`, not a clean original miss. Mechanism v1 reproduces 10 clean misses plus two unevaluable cases and 19 clean raw scans versus six accepted raw rules, with distinct denominator labels in the code.
- Non-dict metadata is rejected. Tuple languages serialize to a plain list and round-trip through yaml.safe_load successfully.
- The verifier now uses `dv2.semgrep_env(out)` for its version query. Its latest retained summary, `_verify_scan_integration_20261011T221931377245Z/summary.json`, records 1.177.0, six raw and six iterative successes, the expected exact iterative case set, raw scan_errors=1, iterative scan_errors=0, and passing assertions. This review inspected that artifact; it did not repeat the full replay.

The exclusion, stopping-policy, denominator labeling, same-process staging, version-environment and specified metadata/language-container reproductions can be closed. The 29-test suite is not exhaustive coverage of every audit/design edge case.

## Remaining findings from the earlier review

### Auditor error attribution remains incomplete

`pipeline/audit_failure_categories.py:89–93` still treats every error without a `path` as `rule_construction_error`. A synthetic target parse failure accompanied by the runner's generic “Semgrep exited with status 2” message is labeled both `target_error` and `rule_construction_error`, even though the fixture contains no rule error. This was reproduced again.

Classify explicit error types, treating generic process/infrastructure/annotation messages separately. The current historical construction-error counts are not thereby proven wrong; the earlier review found explicit rule-error types in the historical episodes counted there. This remains a classification defect rather than evidence of a changed E2E score.

### Probe design is improved but not ready to implement as written

At tracking-document lines 321–328, construction still specifies identifier renaming while requiring a family different from the hidden renaming and restructuring families. Changing the later paragraph to “different family” does not make this construction a different family. Specify an actual eligible different-family transformation, or explicitly frame renaming probes as within-family development and reserve separate families for final confirmation. Within-family development is not automatically test leakage; it changes the generalization claim that can be supported.

The added reflection eligibility restriction addresses the prior locals() counterexample, but it is not a general semantic-preservation guarantee. The specification still mentions rewriting `arg` nodes. This function has none of the prohibited calls:

```python
def probe(token):
    return token
```

Calling `probe(token="unsafe")` works. Renaming the parameter and its reference to `tok`, without the caller, raises TypeError. Both function ASTs have the allowed rename-only difference and pass the stated reflection exclusion. The reproduction is retained. Restrict the first implementation to eligible local bindings, preserve externally visible signatures, and document language-specific validity checks. Independent semantic review remains pending under Item 3; a named exclusion list alone does not finish that work.

These are outstanding parts of the previous findings, not a reason to keep retesting the already-fixed serializer and cache behavior.

## Recommended next research step

Investigate the historical exclusion form offline before spending on the larger 2×2 experiment. This is a concrete mechanism already observed in 42/87 accepted rules, including all 19 accepted baseline rules. Its actual effect on false positives, lost positives and complete success is unknown. Resolving it can tell us how much of the measured gap reflects operator composition rather than a failure to identify the vulnerability.

Proposed bounded protocol, not executed by this review:

1. Freeze the inventory from `bounded_followup_artifacts_20261011T215946041546Z/historical_exclusion_inventory.json` and record all source hashes. Preserve every original rule and historical result.
2. Create a separate variant that changes only composition: combine the existing `pattern` and `pattern-not` under `patterns`, retaining the literal pattern strings and unrelated fields. Reject or separately account for any rule that does not fit the prespecified transformation; do not improvise semantic edits per case.
3. Scan each original/rewritten pair with identical pinned engine, sample bytes, TSX staging and annotations. Evaluate all six samples, preserve errors and match locations, and report gained/lost complete successes plus positive/negative outcome changes.
4. Keep the unit of analysis explicit: 42 rule instances across repeated development runs are not 42 independent cases. Report paired per-run changes, and keep all 24 requested cases in each run's E2E denominator. This accepted-rule intervention cannot estimate recovery of rejected rules or a new repair-loop policy.
5. Report the result as an exploratory deterministic composition ablation. It is not a new model generation result or proof of improvement on a fresh holdout. A loss of true positives is as important as a reduction in false positives. Zero net gain is also informative.

If this substantially changes results, the later 2×2 comparison should explicitly control the construction/normalization policy across appropriate arms and retain the historical condition separately. Otherwise a “typed representation” gain could simply reflect this operator correction. If it has little effect, that narrows the explanation and supports moving to the behavioral-feedback question. No outcome is assumed in advance.

## File accounting and evidence

Added this review, `bounded_round3_checks.py`, `bounded_round3_findings_20261011T223011269546Z.json`, and two command logs labeled `bounded_round3_regressions` and `bounded_round3_checks`. Updated the audit README and appended command/review records to events.jsonl. All eight reviewed source/test/user-document files remained unchanged; their hashes are retained in the findings JSON and checked at review completion. No implementation, historical rule, benchmark or historical result was edited. Three local regression scans were run; no model calls, historical exclusion ablation or new full baseline replay was launched.
