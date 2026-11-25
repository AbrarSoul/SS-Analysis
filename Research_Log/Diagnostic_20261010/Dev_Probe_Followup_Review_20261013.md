# Probe follow-up review — 2026-10-13

The fixes close seven of the eight retained transformation counterexamples and the three medium
findings' concrete defects. The latest coverage counts are correct. Two underlying correctness
findings remain open: incomplete scope handling, and incomplete patched-source validation. This
review does not start the separately deferred C/D gate, caching or inference work.

## Verification

- `pipeline/tests/test_dev_probe.py`: **24 passed in 0.41s**, including local Node and Java tests.
  The author reports 68/68 for the full suite; this review reran the changed test file only.
- Replayed all eight prior transformation fixtures: nested Python function, JS block, JS callee,
  spaced eval, Java declaration name and the two patched parameter/collision examples are fixed.
  Invalid patched source still returns an eligible `ProbeResult`.
- Reproduced that a scan response missing both targets now returns `scan_ok=False`. Inspected
  the four-way outcome accounting, which now includes patched FPs even with vulnerable misses.
- Verified the four tree-sitter packages are pinned, and the new run stores probe sources under
  its own `_probe_inputs/` directory with matching SHA-256 hashes. This fixes the shared-source
  overwrite issue for new runs; it does not reconstruct pre-existing overwritten inputs.
- Recounted all 104 saved scanner outputs: no errors, Semgrep 1.177.0, both targets scanned,
  outcomes equal the summary. Regenerated all 24 eligibility decisions and all 26 stored probe
  sources in memory; source bytes and hashes match.
- Of the prior audit's 581 hashed inputs, only `dev_probe.py`, `probe_coverage_check.py`,
  `test_dev_probe.py` and `autogrep/requirements.txt` changed. Historical episode/rule/probe/scan
  inputs remain unchanged. Research logs were not in that particular hash inventory.

Evidence: `Dev_Probe_Followup_Evidence_20261013.json`, produced by
`audit_dev_probe_followup_20261013.py`; successful command output is retained in
`commands/20261013T003101552518Z_dev_probe_followup_20261013.log`.

## Confirmed coverage

Namespace: `results/diagnostic_20261010/_probe_coverage_20261013T002146736021Z`.

| Model / condition | Covered accepted episodes | Pass | Miss | Patched findings |
|---|---:|---:|---:|---:|
| Qwen A | 33 | 33 | 0 | 0 |
| Qwen B | 29 | 26 | 3 | 0 |
| GPT-4o A | 21 | 18 | 3 | 0 |
| GPT-4o B | 21 | 21 | 0 | 0 |
| Total | 104 | 98 | 6 | 0 |

Eligibility is 13/24. CASE-0081 and CASE-0339 are now excluded by the conservative block-scope
filter; the 12 removed covered episodes were all passes (not merely mostly passes). All six
failing episode identities match the prior run: Qwen B CASE-0171 repeats 1–3, GPT-4o A CASE-0136
repeats 2–3, GPT-4o A CASE-0173 repeat 3. No evidence here shows those misses were transformation
artifacts. The new counterexamples below concern other inputs, not these retained outcomes.

Conditional failure rate: 6/104 = 5.77%; overall accepted-episode flag yield: 6/195 = 3.08%.
91/195 accepted episodes remain uncovered. The changed denominator explains the increased
conditional rate. The evidence remains detection potential, not demonstrated repair/E2E gains.

## Open finding 1 — high: lexical scope is still incompletely modeled

The Python exclusion lists handle nested functions/classes but not comprehension scopes or
definition-time defaults. The Java block-scope helper explicitly returns False for Java.
The audit executes three simple counterexamples:

1. Python, with global `token=10`:
   `def f(): [token for token in (1,2)]; return token`.
   The comprehension binding is treated as a local of `f`, and the independent global return
   reference is renamed too. Original returns 10; accepted probe raises `NameError`.
2. Python, with global `token=10`:
   `def f(x=token): token=1; return x+token`.
   Renaming the body local also changes the definition-time global reference in the default.
   Original returns 11; the probe raises `NameError` while defining the function.
3. Java, with enclosing field `int token=10`:
   `int f() { { int token=1; } return token; }`.
   The return reads the field, outside the inner local's scope. Original compiles and returns 10;
   accepted probe fails `javac` because the return was changed to undeclared `token_renamed`.

All transformations are accepted as `ProbeResult`. This is the same unresolved binding-identity
problem as the first review, not a requirement to support arbitrary new transformation families.
Resolve declaration/reference identity or conservatively reject the entire uncertain candidate,
including these ordinary scope constructs. Check function signatures/defaults separately from
body-local references. Add execution regressions for both Python and Java cases.

## Open finding 2 — high: patched source need not contain the selected local binding

`_rename_patched_python` now checks parameters and name collisions, but does not require the old
name to be a local declaration in the patched function. With a vulnerable local `token` and
patched `def f(): return token` reading global token=7, it still renames the global load.
The patched source returns 7; its accepted probe raises `NameError`. The reproduction and emitted
source are retained. This also demonstrates that the claim of independently rerunning the full
eligibility check set is not yet accurate.

The previous invalid-patched reproduction is unchanged: patched `def f(:` passes back unchanged
with `patched_probe_renamed=False`, but the builder returns an eligible pair. That flag merges
valid unchanged-source fallback with actual parse/validation failure.

Require a genuine eligible patched-side local before attempting to rename it; if absent, a
valid unchanged patched source can be a separately declared fallback. Parse/validation failures
must make the pair ineligible or explicitly erroneous. Apply the same contract to all languages.
Add tests of the public `build_probe` outcome, not just private helper return values.

## Documentation/test precision and next step

The JS block issue was already in the prior review and evidence; the new tracking entry calls it
self-discovered/not in that review. Its new test correctly checks ineligibility, but its purported
broken-code fixture only renames the inner declaration, leaves the outer reference unchanged and
therefore still returns 10. That part does not reproduce the original failure, which renamed both
occurrences. Fix the explanatory text and use the actual failing transformation if retaining the
behavioral demonstration. These do not change the verified coverage totals.

Close the two semantic findings and add their behavior regressions before declaring the builder
complete. Preserve the declared deferral of the combined C/D gate, deterministic caching and
inference. Passing the builder tests will not by itself implement or validate those later steps.
No new model calls, real Semgrep scans or C/D work were performed in this review.

## File accounting

Added: this review, `audit_dev_probe_followup_20261013.py`,
`Dev_Probe_Followup_Evidence_20261013.json`, and the command log named above.
Modified: `README.md`, `events.jsonl`, and append-only review entries in
`Bounded_Investigation_Tracking.md` and `Research_Log/Correction_Log.md`.
Implementation, tests, requirements, benchmark sources and historical results were not changed
by the review. Temporary compiler/mock-scan fixtures were created in a temporary directory and
automatically removed; their inputs/outcomes are retained in the evidence JSON.
