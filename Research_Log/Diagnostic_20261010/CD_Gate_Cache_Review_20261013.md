# C/D gate and cache review — 2026-10-13

The ordinary decision paths are implemented and the 20 new tests pass independently (0.12s).
This review did not rerun the author's complete 110-test suite. C/D remains a standalone
prototype: neither module is wired into `diagnostic_v2.run_model_case`, and the two episode
simulations exercise a test-local loop, not that production retry loop. No live inference or
real Semgrep execution was performed here.

Three issues need correction before these modules support the fixed-input C/D experiment.
Executable evidence is in `CD_Gate_Cache_Review_Evidence_20261013.json`, produced by
`audit_cd_gate_cache_20261013.py`. The audit uses temporary synthetic caches and executes the
existing runner with both model and scanner replaced by local functions. It does not modify any
saved probe, benchmark, historical result, implementation or permanent regression test.

## 1. High: cache hits do not verify the returned probe artifact

At `pipeline/probe_cache.py:69`, matching input/builder keys immediately deserialize the payload.
Neither probe output is hashed or compared with the reviewed immutable artifact. In a temporary
cache, I replaced the vulnerable probe's body with `return 999`, retaining the existing key.
`get_or_build_probe(..., strict=True)` returned the altered source with status `hit`.

This is an integrity/provenance defect, not a claim that saved research artifacts have actually
been corrupted. Matching source hashes establish the requested inputs; they do not establish
which transformed text is being scanned. A changed probe can change C/D's repair/accept outcome.

The preceding closure explicitly required source/builder/parser/**probe** checks against the
reviewed fixed selection. This cache also equates the current on-disk builder hash with a reviewed
version. Strict mode still builds an unseen synthetic `UNREVIEWED-CASE` on a cache miss; default
mode rebuilds changed inputs without a review boundary. Those are reasonable generic builder
operations, but they do not enforce the fixed-input experiment's admissibility requirement.

Required correction: introduce an experiment manifest containing the reviewed case selection,
language, source hashes, frozen builder/parser identities, eligibility/rejection reason and
expected probe hashes. Validate returned payloads against it before experimental use. A changed
or additional case may be built offline for review, but must not automatically inherit the old
review. Keep ordinary development cache rebuilding separate from frozen experimental loading.
A checksum stored only beside a freely changed payload is weaker than comparison against the
independently reviewed manifest.

## 2. Medium: cache identity omits language and parser versions

`pipeline/probe_cache.py:39` includes exactly three hashes: vulnerable input, patched input and
builder file. `language` selects a different parsing/renaming path but is absent from the key.
Reproduction: cache an eligible JavaScript function, request the same case/text as TypeScript in
strict mode, and receive `hit` with `result.language == "javascript"`. A fresh builder call
correctly returns `"typescript"`.

Parser/runtime changes are likewise invisible to the key, despite the prior closure freezing
Python and the four tree-sitter package versions. This latter gap is established by inspecting
the key; no parser upgrade or changed-output claim was tested here.

Required correction: include case/language identity, a cache format version and relevant parser/
runtime identities; validate payload identity as well as its text. For the pilot, compare those
identities with the frozen manifest from Finding 1. Add language-change, dependency-change and
builder-change invalidation tests; the current builder test only checks that its hash is present.

## 3. Medium: decisions cannot supply actual resource counts

`pipeline/combined_gate.py:108` counts one visible scan per decision and one probe scan per
non-null `probe_checks`. Actual `diagnostic_v2.py:208` scans only when generation produced a rule.
I executed `run_model_case` with a mocked decode failure followed by a valid, visibly passing
rule. Actual events: **two generation calls, one visible scan, one repair call**. Summarizing a
decision per attempt reports **two visible scans**. Omitting the unparsed attempt instead fixes
that count but incorrectly reports **zero repair calls**. Neither convention recovers all costs.

Additionally, `evaluate_probe_pair` explicitly permits two separate scanner invocations or a
single combined invocation. Both collapse to the same checks dictionary, so the summarizer
cannot distinguish them. Define whether a metric counts pair evaluations, targets or scanner
invocations; these are different quantities.

Required correction: record actual generation and scan events, including failures, separately
from gate decisions. Aggregate those records, with call counts preserved across any supported
resume path. Add a decode-failure trajectory through the actual runner and explicit one-scan/
two-scan accounting tests. The retained reproduction tests the first problem directly; the
second follows from the documented interface accepting both execution styles.

## Integration checks and bounded hardening

The central normal paths are sound under their documented input contracts: visible failure
short-circuits probe requirements; eligible visible/probe success accepts; failing/error probes
retry or exhaust; accepted ineligible cases are flagged; A/B ignore probe checks.

Before a C/D pilot, wire these decisions into the actual retry and feedback path and test it
offline with mocked model/scanner dependencies. Verify probe feedback reaches the next call,
hidden results remain unavailable until generation finishes, no budget reset occurs, A/B stay
unchanged, and episode/provenance records retain the real decisions and resource events.
Writing and testing this integration does **not** spend inference budget; there is no technical
need to wait for paid-run approval before making the runner reviewable. This review respects the
stated standalone scope and does not perform that integration itself.

Two API boundary observations were also reproduced, as hardening rather than demonstrated
production failures: an unknown condition string behaves like A/B, and a passing fourth attempt
is accepted with `max_attempts=3`. Validate supported condition values and legal attempt bounds.
The current real runner already uses `range(1, 4)`, so this is not evidence of an actual fourth
model call or budget overrun. The existing exhaustion test supplies a fourth *failing* attempt
and therefore does not establish rejection of an over-budget passing candidate.

Record eligibility and its reason independently of `GateDecision.is_fallback`: that field is
false for failed ineligible episodes by design. Using it alone to count eligibility/fallback
coverage would omit unsuccessful cases. No current production report consumes it yet.

## Verification and file accounting

- Independent focused suite: 20 passed; full 110-test suite not rerun in this review.
- Audit command exit 0; all reproduction assertions passed. Log:
  `commands/20261013T095417328992Z_cd_gate_cache_review_20261013.log`.
- Evidence records hashes for the gate, cache, builder, runner and new test file, plus Python
  and tree-sitter versions. The builder still matches the previously reviewed hash.
- Added: this review, the audit script, evidence JSON and command log.
- Modified: `Bounded_Investigation_Tracking.md`, `../Correction_Log.md`, `README.md` and
  `events.jsonl`. The correction log receives a new entry; older claims remain preserved.
- Zero real model calls, zero real scans; no implementation, benchmark, historical outcome,
  dependency or regression-test edits. Existing working-tree changes remain untouched.

Next step: close these cache/accounting gaps, then complete the mocked integration checks.
C/D inference remains a later, separately approved budget decision. No new E2E improvement has
been measured by this engineering work.
