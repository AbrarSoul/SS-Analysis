# Closure of known probe findings — 2026-10-13

The two round-3 counterexamples are fixed. This closes the concrete reproductions reviewed so
far; it is not certification of all binding forms or of the still-unimplemented C/D workflow.

## Independent verification

- The changed probe test file passes **32/32 in 0.71s**, with real Python/Node/Java behavior
  checks in the suite. The author's full 76-test result was not independently rerun this turn.
- Replayed the retained Python exception-binding and JavaScript default-argument fixtures.
  Both are now ineligible. Also tested each problematic source specifically on the patched side
  with a safely renamable vulnerable input: the valid patched source stays unchanged, without
  corrupting its bindings. A typed TypeScript default-argument fixture is also ineligible.
- Read all 100 raw scanner outputs from `_probe_coverage_20261013T011301679535Z`. Each reports
  Semgrep 1.177.0, no errors and both intended targets scanned. Independent recount: **94 pass,
  6 vulnerable misses, 0 patched findings**, with exactly the previous six episode identities.
- Regenerated the 24 eligibility decisions in memory and compared all 22 saved probe sources
  byte-for-byte and against their recorded hashes. Eligibility remains **11/24**. Coverage is
  **100/195 accepted episodes**, leaving 95 uncovered. The flag rate is 6/100 conditional on
  coverage, or 6/195 across all accepted episodes; uncovered episodes are not counted as passes.
- Among the preceding review's 152 hashed inputs, only `pipeline/dev_probe.py` and
  `pipeline/tests/test_dev_probe.py` changed. Previous saved evidence remains unchanged.

Evidence: `audit_dev_probe_closure_20261013.py`, `Dev_Probe_Closure_Evidence_20261013.json`, and
`commands/20261013T012453898286Z_dev_probe_closure_20261013.log` (audit exit 0). No model calls
or real Semgrep scans were made by this verification; it inspected the user's new saved scans.

## What this establishes

The reported specific defects have reproducible fixes, and the same six saved-rule misses remain
stable across the inspected revisions. The acknowledged distinction between closing known bugs
and proving general safety is appropriate. Do not describe the builder as automatically rejecting
every unknown binding form: present rejection logic covers enumerated checks, and completeness
of that enumeration has not been demonstrated.

Stable outcomes across builder revisions are not independent new model trials. The current
probe detects a narrow literal-name weakness; it has not shown that repair improves E2E success.
The historical A/B results do not need another inference run because of these corrections.

## Recommended bounded validation step

Replace open-ended counterexample hunting with a documented admissibility audit against the
installed Python and pinned Java/JS/TS parser representations. This is a proposed next task,
not an audit already performed in this closure.

For each language, create a matrix recording: construct/node kind; declaration and reference
positions; scope boundaries; whether supported or rejected; enforcing code; and an executable
positive/negative fixture. Cover ordinary declarations and parameters, signature expressions,
nested/block/loop/handler scopes, destructuring or other non-identifier binding positions,
declaration names and member keys, reflective/name-observing operations, and replacement-name
collisions. Derive the actual inventory from the pinned grammars/AST definitions rather than
assuming this category list is exhaustive.

Acceptance criteria for that bounded task:

1. Each inventoried binding form has an explicit disposition; forms without a validated rename
   path are rejected when they can affect the candidate. State the supported syntax contract.
2. For accepted forms, tests check the declaration and every intended reference, preservation of
   unrelated names and the external signature, on both vulnerable and patched inputs. Include
   runtime behavior and independent expected spans; builder isomorphism alone is insufficient.
3. Invalid-source rejection and valid unchanged-patched fallback remain distinguishable.
4. Record the exact replaced spans and rejection reasons for the 24 current cases, then freeze
   the reviewed builder/parser/input versions and report coverage by language.
5. Any remeasurement uses a fresh immutable namespace. No model calls are needed for this audit.

This finite audit gives a reviewable boundary for the conservative implementation. It does not
claim general semantic equivalence of arbitrary programs. After it, C/D combined acceptance,
repair-budget accounting, scan-error handling and deterministic caching still require their own
implementation and offline tests. Those tasks and any inference remain deferred as requested.

## File accounting

Added: this closure note, its audit script and evidence JSON, and the command log named above.
Modified: README, events, and appended closure entries in Tracking and Correction logs.
No implementation, tests, dependency manifests, benchmark sources, existing probes or saved
result files were changed by this review. No new research finding is inferred from the unrun
admissibility-audit proposal.
