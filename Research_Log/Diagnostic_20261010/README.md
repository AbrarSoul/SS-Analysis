# Diagnostic experiment and implementation record

**C/D pilot running (2026-10-14):** Credential setup succeeded and live execution has started. The [execution status](CD_Pilot_Allocation_20261014_v1/Execution_Status.json) records verified runs and the active run; older blocked/pending notices below are historical.

**C/D pilot authorized, credential blocked (2026-10-14):** [Execution status](CD_Pilot_Allocation_20261014_v1/Execution_Status.json). The first command exited before inference because GPTLAB_API_KEY is missing; 0 calls consumed, all run destinations unused. Approval persists.

**C/D pilot prepared (2026-10-14):** [Allocation, readiness and full file accounting](CD_Pilot_Allocation_20261014_v1/Readiness.md) records twelve launch commands, passing real C/D preflights, 288 matching A/B first-call prompts, and remaining case-order/time-batch caveats. No inference spent; live budget decision pending.

**Bounded C/D build complete (2026-10-13):** [Consolidation verification and handoff](CD_CLI_Build_20261013/Completion_Verification.md) verifies 86 executed passes, 156 collected tests, the unchanged 24-case manifest, and the single working C/D CLI. The concurrent-edit conflict is resolved. Infrastructure work stops at the agreed boundary; paper synthesis is next, live inference remains separately budgeted.

**C/D snapshot review (2026-10-13):** [Materialization fixes verified and two bounded follow-ups](CD_Snapshot_Review_20261013.md) verifies 73 executed passes and 143 collected tests. The three original-file/CRLF scenarios are fixed; equal basenames collide in the snapshot, and rejected integrity checks are counted as scanner calls. Carry those fixes into the pending offline manifest/CLI work. No inference, real scans or implementation edits.

**C/D materialization follow-up (2026-10-13):** [Verified fixes and one remaining scan-input boundary](CD_Materialization_Followup_Review_20261013.md) records 70 executed passes and 140 collected tests. Closes state/identity, A/B import and timeout findings; shows startup-only text verification can miss changed scan bytes and record stale hashes. Complete that boundary with the planned offline manifest/CLI work. No inference, real scans or implementation edits.

**C/D integration follow-up (2026-10-13):** [Verified fixes and remaining integration boundaries](CD_Integration_Followup_Review_20261013.md) verifies 63 focused tests and closes the earlier cache/accounting reproductions. Finds unbound scan files, unresolved-probe fallback and A/B probe imports; records a timeout/interruption gap and the remaining offline adapter/manifest work. Corrects the test increment to 23. No inference, real scans or implementation edits.

**C/D gate/cache reviewed (2026-10-13):** [Independent findings and offline integration requirements](CD_Gate_Cache_Review_20261013.md) verifies 20 new tests and reproduces unchecked cached payloads, incomplete language/parser identity, and incorrect scan accounting after decode failure. Normal gate paths pass; reviewed-artifact enforcement and real retry-loop integration remain open. No inference, real scans or implementation edits.

**Binding audit closed for fixed development inputs (2026-10-13):** [Closure and C/D integration requirements](Binding_Form_Audit_Closure_20261013.md) verifies 46 probe tests, both concrete bug fixes, all 24 edit-report rows, exact identifier spans and manual edit roles for 11 probe pairs, and unchanged 94/6/0 saved outcomes. Supports offline C/D work against these reviewed/hash-bound inputs, not a general safety claim for unreviewed syntax or authorization for inference. Corrects stale scope/test-count wording; implementation remains unchanged.

**Binding-form audit reviewed (2026-10-13):** [Verified artifacts and boundary gaps](Binding_Form_Audit_Review_20261013.md) confirms 38 probe tests pass, frozen versions match, all 24 decisions regenerate, and coverage remains 94 passes/6 misses/0 patched findings. Reproduces an unsafe destructuring form inside the claimed-safe table and an accepted decorator outside the declared boundary. The case report lacks exact edit spans and independent edit validation. Audit closure remains open; no implementation, C/D, inference or new scans.

**Known probe findings closed (2026-10-13):** [Bounded verification and next validation step](Dev_Probe_Known_Findings_Closure_20261013.md) confirms 32 probe tests pass, both latest counterexamples are handled on vulnerable/patched paths, and the newest saved coverage run remains 94 passes/6 misses/0 patched findings across 100 covered accepted episodes (11/24 eligible cases). Closes specific known reproductions without claiming exhaustive binding safety; proposes a finite supported-syntax audit. C/D, caching and inference remain deferred.

**Third probe review (2026-10-13):** [Verified corrections and remaining binding issue](Dev_Probe_Round3_Review_20261013.md) confirms 30 probe tests pass and all previous follow-up counterexamples are fixed. Recounts 94 passes/6 unchanged misses/0 patched findings among 100 covered accepted episodes (11/24 eligible cases). Two further executable examples reveal omitted Python exception bindings and JavaScript default-argument scope; binding safety remains open. No C/D work, inference or new scans.

**Probe fixes reviewed (2026-10-13):** [Follow-up verification](Dev_Probe_Followup_Review_20261013.md) confirms 24 probe tests pass, seven prior transformation counterexamples are fixed, and the new immutable coverage run yields 98 passes/6 misses/0 patched findings across 104 covered accepted episodes. Dependencies and scanner-accounting fixes are verified. Remaining scope and patched-source validation defects are reproduced with Python execution and Java compilation; C/D integration, caching and inference remain deferred.

**Probe implementation reviewed (2026-10-13):** [Verified coverage and implementation blockers](Dev_Probe_Implementation_Review_20261013.md) reproduces 110 passes/6 misses/0 patched findings from 116 saved scans, verifies 15/24 eligible cases, and runs the 18 new tests. Eight counterexamples show accepted transformations changing bindings, patched-side behavior or reflection semantics. Coverage is conditional on eligibility (116 of 195 accepted episodes). Records scanner-accounting, immutable-evidence and dependency gaps; the C/D gate is still unimplemented. No new inference, real scans or implementation changes.

**Completed A/B pilot reviewed (2026-10-13):** [Verified outcomes and research interpretation](AB_Pilot_Results_Review_20261013.md) audits 288 episodes and 486 captured calls. Qwen moves 25.00%→29.17%; GPT-4o 22.22%→23.61%, descriptively. Qwen B's extra failures are primarily embedded Semgrep pattern-parse errors, with one separate typed-schema failure. Documents corrections to GPT-4o's weighted net gain, scanner-error repeat count and interaction wording, plus concrete reasons to investigate probes. No new inference or scans.

**Condition B ready; pilot allocation proposed (2026-10-12):** [Verified fixes and concrete allocation](Condition_B_Readiness_and_Pilot_20261012.md) closes the four implementation-review findings, verifies 44 tests and both frozen hashes, and records four mocked credential routes. Prepared twelve fresh A/B batch commands for 24 cases, two models and three repeats: 288 episodes, at most 864 calls. Allocation is explicitly unapproved/unexecuted; no model inference or confirmation work occurred.

**Condition B implementation review (2026-10-12):** [Offline verification and pre-pilot findings](Condition_B_Implementation_Review_20261012.md) reproduces 44 passing tests and verifies six mocked generation/repair/capture scenarios. A's 48 rendered prompts match the snapshot despite a whitespace-only pinned-source hash failure. Before live comparison, resolve B's omitted worked examples and incorrect historical-prompt metadata; provider-specific preflight remains relevant to GPT-4o. No model inference or implementation edits by the review.

**Review closure and A/B implementation handoff (2026-10-12):** [Closure note](Protocol_Review_Closure_20261012.md) verifies the CASE-0222 qualification and explicit C/D gate are corrected in the documents. One confirmation-only bootstrap wording issue remains: resample repository groups, not independent cases. Records the typed-JSON integration and offline checks needed next; no implementation, pilot run or protocol freeze occurred.

**Corrected protocol follow-up (2026-10-12):** [Review and six recommended decisions](Controlled_2x2_Protocol_Followup_20261012.md) confirms the major draft corrections and inspects all eleven newly reviewed source diffs. A network-free reproduction qualifies CASE-0222's session/per-request TLS equivalence under environment CA overrides. C/D still needs an explicit combined visible/probe acceptance gate. Recommends three-repeat A/B development first and a construction-effect primary contrast for later factorial confirmation; no freeze, new scans or inference.

**Item 3 and protocol review (2026-10-12):** [Evidence and recommendations](Controlled_2x2_Protocol_Review_20261012.md) verifies 9/24 reference precision gaps, 72 positive detections, 12 false positives and 15/24 complete successes. Reference agreement does not finish semantic adjudication of the 11 cases without direct comparisons. The specified exact paired-test scenario requires 207 cases for 80% power, rather than the draft's 80–100. Recommends an A/B development pilot and explicit budget, selection and repeated-trial analysis rules before confirmation. No inference, new scans or protocol freeze.

**Corrected ablation verified (2026-10-12):** [Closure verification](Exclusion_Ablation_Closure_20261012.md) closes the scope-serialization and failed-scan tally findings for the inspected revision. All 31 tests pass; independent recount confirms 0 gains/9 losses/33 unchanged, 20 hidden TP losses across 41 evaluable pairs, zero FP changes and one separate compile failure. Historical summaries remain preserved. Item 3 independent review remains open.

**Exclusion ablation review (2026-10-12):** [Verified totals and corrected interpretation](Exclusion_Ablation_Review_20261012.md) reproduces 0 gains/9 losses/33 unchanged and 30 passing tests, but shows that the purported nesting artifact is an activated scope constraint. The sole apparent FP improvement is a failed Java rule scan. The new serializer workaround ignores scope and needs correction; retained evidence is sufficient to correct the ablation's reporting without new inference.

**Second-round fixes verified (2026-10-12):** [Round-three verification and next-step recommendation](Bounded_Investigation_Round3_Review_20261012.md) confirms 29 tests pass and the targeted cache/denominator/type/version fixes. Error attribution and the concrete probe-family/parameter-renaming specification remain open. It proposes a bounded offline historical-exclusion ablation before the 2×2 comparison; that experiment has not been launched.

**Follow-up review (2026-10-12):** [Review after the seven-finding fix pass](Bounded_Investigation_Followup_Review_20261012.md) confirms all 29 tests pass and the exclusion/acceptance-policy fixes work. Remaining findings concern audit populations, TSX checks after first access, AST probe validity and engine-version provenance. Saved historical exclusions are inventoried separately; no model calls or implementation edits were made.

**Bounded investigation review (2026-10-12):** [Review and reproduced findings](Bounded_Investigation_Review_20261012.md) confirms 18 regression passes and a pinned-compiler baseline replay at 6/24, but identifies an ignored serialized exclusion, an unchanged model acceptance gate, incomplete failure accounting and a circular probe-validation proposal. All checks and file accounting are retained; no model inference was launched.

**Research direction proposal (2026-10-11):** [Research direction after the prompt diagnostics](Research_Direction_20261011.md) recommends a generalization-focused contribution, a bounded construction/feedback comparison, and fresh confirmation. It records proposed questions, controls, stopping criteria, prior-art context and file accounting. This is a proposal, not a change to the original protocol; C3/C4 remain deferred.

**Latest mechanism run v5:** prompt `diagnostic_mechanism_v4` reaches 3/24 successes, down from the intervening mechanism run v4's 6/24. Seven first attempts fail Semgrep validation, including five malformed `pattern-either` alternative lists. Retries recover two successes but do not restore the prior result. See [mechanism v5 review](Qwen3_Mechanism_v5_Review.md) for the comparison, retained evidence and offline validation priorities.

**Fixed-example prompt run:** `qwen3_mechanism_v3` uses the distinct `diagnostic_mechanism_v2` prompt and parseable example YAML. E2E success remains 5/24, with two gained and two lost cases relative to the preceding run. CASE-0221 now fails the one-rule output contract on every attempt. See [mechanism v3 review](Qwen3_Mechanism_v3_Review.md) for verified changes, case-level evidence and the recommendation to validate output formatting and the evaluator offline before further broad reruns.

**Mechanism run v2:** `qwen3_mechanism_v2` achieves 5/24 successes, versus v1's 4/24 and the original prompt's 6/24. It restores examples and adds pattern-combination guidance but still uses the old prompt identifier. The captured examples contain invalid YAML indentation. See [mechanism v2 review](Qwen3_Mechanism_v2_Review.md) for the paired case changes, validation evidence and remaining evaluator issues.

**Revised-prompt run:** `qwen3_mechanism_v1` completed with 4/24 E2E successes versus 6/24 for `qwen3_v3`, losing two previously successful cases and gaining none. See [mechanism v1 review](Qwen3_Mechanism_v1_Review.md) for the paired comparison, extra calls, formatting/truncation failures and the additional prompt changes that limit causal interpretation.

**Live-run update:** the user subsequently completed `results/diagnostic_20261010/qwen3_v3/` (recorded start 2026-10-10 20:41 UTC). It achieved 6/24 complete successes in both raw and iterative conditions, matching the same six historical successes on this subset. See [Qwen3 v3 review](Qwen3_v3_Review.md) for verified results, costs, failure analysis and next steps. Credential-blocked statements below describe the earlier offline checkpoint.

This record tracks the work authorized on 2026-10-10 after the repository review: preserve the existing study, correct confirmed implementation problems, construct a small diagnostic sample and reference-rule comparison, and run a recorded model experiment where inference access permits. Historical outcomes are not rewritten. This is exploratory development work, not a new confirmatory benchmark.

## Starting state and preservation

`baseline.json` records the starting Git revision, the pre-existing dirty working tree, SHA-256 hashes of source snapshots, and 378 historical execution/configuration/dataset files. `before/` holds exact source copies made before implementation changes. The existing source scan conservatively includes vendored/cache Python and rule files (5,390 files, approximately 27 MB). These snapshots are provenance artifacts, not a second active implementation.

The following changes were already present before this task: modified `pipeline/gptlab_config.py`, `pipeline/rescore_variant_location.py`, and `pipeline/run_generation.py`; new OpenAI/follow-up analysis scripts, a 37-case OpenAI diagnostic selection, and new follow-up/OpenAI result directories. They belong to the starting state and must not be attributed to this task. The baseline preserves their exact state. No commit, reset, checkout, or publication is part of this work.

Pre-bootstrap reconnaissance was read-only: inspected Git status, ancestor/repository instruction files (none found), data-integrity principles, schema parsing, rule validation, C3/C4 orchestration, capture/scoring code, existing tests, and credential availability. No credential values were printed or stored. Neither `GPTLAB_API_KEY` nor `OPENAI_API_KEY` was available in this execution environment and no root `.env` file was present. An asynchronous question asks which environment to use for live inference; offline work proceeds meanwhile.

## Frozen diagnostic plan before selection

1. Correct composite/search/taint schema support behind an explicit versioned option. Preserve the legacy schema and prompt route for reproduction. Let pinned Semgrep validate the actual DSL rather than implementing an incomplete substitute parser.
2. Correct C3/C4 rule-text handoffs: review and repair the current candidate; after an unparseable repair, inspect that repair's raw output. Add targeted regression tests covering both failure paths.
3. Retain prompts (all roles), raw provider responses, attempt candidates, validation evidence, final rules, provider usage, timing, configuration, and code hashes in new diagnostic runs. Missing usage is reported as unavailable, never fabricated as zero.
4. Select 24 eligible-supported cases deterministically from the completed Qwen3-Coder-30B follow-up: six complete successes, six visible-validation failures (including location failures), six hidden-positive failures, and six hidden-negative failures. Seek language and repository diversity within these outcome strata. Selection uses seed 20261010, fixed before selection; document any availability-driven deviation. Keep the existing 37-case OpenAI selection untouched.
5. Inspect source, diff, transformation notes, and all six samples for each selected case. Develop transparent reference-rule candidates and retain every tested revision. These are **assistant-authored diagnostic references, not independent human-expert ground truth**. An independently reviewed expert baseline remains pending until a qualified reviewer actually verifies the rules and sample semantics. Success on six samples establishes only bundle fit.
6. Run Qwen3-Coder-30B at temperature 0 with a maximum 2048 output tokens per call: one-shot and up to three total attempts using compiler and original-pair feedback only. Both conditions share their first generation. No hidden results are used for repair or candidate selection. Hidden evaluation happens after the episode terminates. Corrected schema with the historical prompt is the primary diagnostic setting; any prompt change is a separately named condition.
7. Preserve the old acceptance criterion (any original finding and no patched finding) alongside the stricter location-aware visible result for comparison. Score all six samples using the already-adjudicated location annotations. Separate parse/scan errors from genuine non-matches; incomplete scans/bundles cannot pass.
8. Report every requested case, acceptance, correct-location patch discrimination, both hidden positives, hidden false positives, and complete success. Provide descriptive, paired case-level results; no ranking or significance claim from this outcome-stratified diagnostic subset. Any new prompt/workflow chosen from it requires fresh held-out confirmation.

## Audit mechanism and file accounting

- `events.jsonl`: append-only milestones and command start/finish records with UTC timestamps.
- `commands/`: exact stdout/stderr, command arguments, exit codes, durations, and output hashes for test and experiment commands launched through `pipeline/diagnostic_audit.py run`.
- `file_changes.json`: generated list of added/modified/deleted source and diagnostic-benchmark files, with before/after hashes.
- `diffs/`: unified diffs relative to the actual starting working tree, including pre-existing uncommitted work.
- `baseline.json` and `before/`: preserved starting evidence.

Research notes and command/diff artifacts inside this audit directory are tracked through the event log and a final artifact inventory, rather than recursively snapshotting their own growing contents. Historical-file verification reports external changes as well as agent changes; any discrepancy must be investigated rather than silently attributed.

## Progress and decisions

### Baseline and inspection

Baseline captured before edits to existing implementation files. Found that the system prompt also explicitly demands `pattern`; allowing composite schemas alone does not remove that prompt bias. The diagnostic runner will label the legacy-prompt/schema-only condition separately from any unrestricted-output prompt experiment.

No paid or remote model calls have been made at this stage. The published first-stage recommendation included an expert comparison; authorship and independence will be explicit rather than presenting assistant-written rules as human-expert validation.

## Final outcomes

Offline implementation and first-pass reference evaluation are complete. Live Qwen3 inference is blocked by the missing `GPTLAB_API_KEY`; the recorded credential preflight made **zero model calls**. An independent expert review has not occurred. The discovered annotation/parser issues make dataset adjudication the next priority before interpreting any new model comparison.

### Implementation changes and rationale

| File | Change |
|---|---|
| `autogrep/config.py` | Adds versioned `rule_schema_policy`; legacy behavior remains the default. |
| `autogrep/llm_client.py` | Opt-in `semgrep_search_taint_v2` supports `pattern`, `patterns`, `pattern-either`, `pattern-regex`, and taint envelopes; requires exactly one rule mapping. Actual DSL validity remains Semgrep's responsibility. Frozen prompt functions and generation system message are unchanged. |
| `pipeline/run_c3.py` | Syntax review's replacement becomes the actual text seen by semantic review/repair. An unparseable repair is passed forward as its own raw text. |
| `pipeline/run_c4.py` | Applies the same two candidate-handoff fixes to role-based orchestration. |
| `pipeline/raw_capture.py` | Retains full request messages, provider response, finish reason, reported token usage, timing, and failed API calls. Exclusive writes reject attempts to overwrite evidence. Missing usage remains null. |
| `pipeline/diagnostic_audit.py` (new) | Baseline snapshots, command journal, before/after diffs, file inventory and protected-file verification. |
| `pipeline/select_diagnostic_cases.py` (new) | Deterministic selection and frozen provenance. Refuses to overwrite the selection. |
| `pipeline/diagnostic_v2.py` (new) | Isolated reference/model runner; pinned Semgrep; retained attempts/scans/final rules; up to three recorded calls; original-pair feedback only; hidden scans after calls terminate. Fresh output directories required. |
| `pipeline/build_diagnostic_references.py` (new) | Freezes 24 first-pass candidates and per-case mechanism/limitation notes. Refuses to overwrite v1. |
| `pipeline/audit_diagnostic_failures.py` (new) | Case-level failure classification and byte-identical TSX suffix probe. |
| `pipeline/tests/test_diagnostic_regressions.py` (new) | 18 regression checks covering schema parsing, current-candidate handoffs, retention, hidden-feedback separation, and scan errors. |
| `benchmark/diagnostic_20261010/` (new) | Selection, 24 versioned rule YAMLs, review notes with all six sample hashes, and unapplied adjudication proposals. |
| `results/diagnostic_20261010/` (new) | Preflight successes/failures, reference execution evidence, failure audit, TSX probe, and blocked model preflight. |

The schema options follow Semgrep's [rule syntax documentation](https://docs.semgrep.dev/writing-rules/rule-syntax). This fixes an identified wrapper restriction, but the unchanged system message still asks for `pattern`; no claim is made that schema support alone solves the prompt bias. C3/C4's historical outputs have not been rerun or relabeled. Their existing call/token-budget differences are also not resolved by the handoff fix.

`file_changes.json` is the authoritative path-by-path list with before/after hashes; `diffs/` contains the exact source changes relative to the user's starting working tree. `artifact_inventory.json` hashes the audit and experiment artifacts. Tests create ignored Python/pytest caches as normal; those are not research evidence. Every subsequent checkpoint refreshes the derived inventories while `events.jsonl` remains append-only.

### Selection and interpretation

The eligible population contained 11 complete successes, 11 hidden-negative failures, 37 hidden-positive failures and 91 visible failures, using mutually exclusive, location-aware categories. The frozen selection contains six cases from each category, six per language, and 24 distinct repositories. This balances diagnosis deliberately; it does **not** estimate population passing rate. The six historically successful cases already guarantee a different composition from a random 24-case sample.

All candidate authorship is recorded as assistant-generated after bundle inspection. Several candidates are deliberately broad initial patterns, with limitations stated before evaluation in `reference_rules/v1/review_notes.json`. No reference rule was tuned after these test results, and none is certified as a general security detector. Comparing their 12/24 result to historical model performance would confound information access, authorship and selection.

### Measured reference results

Source: `results/diagnostic_20261010/references_v1/`. All 24 requested cases have retained episodes and all six sample records. Of these, 23 have error-free scans; one is invalid because of source parsing errors.

| Metric | Result |
|---|---:|
| Original vulnerable/patched discrimination, valid scans | 19/24 |
| Correct original location and patched rejection | 19/24 |
| Complete six-sample success | 12/24 |
| Hidden positive hits from accepted rules, all-requested denominator | 35/48 |
| Hidden negative false positives among accepted rules | 6/38 |
| Cases with scan errors | 1/24 |

The original `references_v1/summary.json` was preserved. `failure_audit_v1/summary.json` adds explicit scan/error/negative denominators using the retained episodes; it does not rerun or change their scores. The runner gained those reporting fields after the v1 process had already loaded its code; each run's recorded code hash distinguishes that version from the current runner.

Sample outcomes below are ordered: original vulnerable, patched, renamed vulnerable, structural vulnerable, transformed safe, benign. For CASE-0298, the printed FN/TN placeholders are **not valid detection outcomes** because parsing failed; they receive no credit.

| Case | Historical selection category | Six sample outcomes | v1 status |
|---|---|---|---|
| CASE-0323 | complete success | TP / TN / TP / TP / TN / TN | pass |
| CASE-0276 | complete success | TP / TN / TP / TP / TN / TN | pass |
| CASE-0221 | complete success | TP / TN / TP / TP / TN / TN | pass |
| CASE-0134 | complete success | TP / TN / TP / TP / TN / TN | pass |
| CASE-0136 | complete success | TP / TN / TP / TP / TN / TN | pass |
| CASE-0220 | complete success | TP / TN / TP / TP / TN / TN | pass |
| CASE-0340 | hidden negative failure | TP / TN / TP / TP / TN / TN | pass |
| CASE-0238 | hidden negative failure | TP / TN / TP / TP / FP / FP | fail |
| CASE-0193 | hidden negative failure | TP / TN / TP / TP / TN / FP | fail |
| CASE-0124 | hidden negative failure | TP / TN / TP / TP / TN / TN | pass |
| CASE-0063 | hidden negative failure | TP / TN / TP / TP / TN / FP | fail |
| CASE-0184 | hidden negative failure | TP / TN / TP / TP / TN / FP | fail |
| CASE-0173 | hidden positive failure | TP / TN / TP / FN / TN / TN | fail |
| CASE-0222 | hidden positive failure | TP / TN / TP / TP / TN / TN | pass |
| CASE-0163 | hidden positive failure | TP / TN / TP / FN / FP / TN | fail |
| CASE-0171 | hidden positive failure | TP / TN / TP / TP / TN / TN | pass |
| CASE-0046 | hidden positive failure | TP / FP / TP / TP / TN / TN | fail |
| CASE-0239 | hidden positive failure | TP / TN / TP / FN / TN / TN | fail |
| CASE-0235 | visible failure | TP / FP / TP / FN / TN / TN | fail |
| CASE-0298 | visible failure | FN / TN / FN / FN / TN / TN | scan invalid |
| CASE-0116 | visible failure | TP / FP / TP / TP / FP / TN | fail |
| CASE-0231 | visible failure | TP / TN / TP / TP / TN / TN | pass |
| CASE-0339 | visible failure | TP / FP / TP / TP / FP / TN | fail |
| CASE-0081 | visible failure | TP / TN / TP / TP / TN / TN | pass |

### New measurement issues requiring adjudication

Four structural variants have a finding on the moved security-relevant expression but outside the current accepted range:

| Case | Finding line | Accepted range | Observed source change |
|---|---:|---|---|
| CASE-0173 | 11 | 41–44 | Manifest fallback moved into `resolveKey`; caller remains annotated. |
| CASE-0163 | 50 | 26–37 | Clone argument construction moved into `cloneArgs`; caller remains annotated. |
| CASE-0239 | 38 | 40–85 | Problematic regex hoisted into `SHORTCUT_URL` before the annotated function. |
| CASE-0235 | 41 | 45–79 | Path construction moved into `resolvePath`; server callback remains annotated. |

These are candidates for accepting additional, disjoint expression ranges after semantic review. Merely widening ranges to cover unrelated code would weaken localization. CASE-0163 and CASE-0235 also have independent false positives, so accepting their helper locations would not make those candidates pass. CASE-0173 and CASE-0239 fail only on this location criterion in the recorded candidate run. Historical model impact cannot be inferred without examining their retained findings.

CASE-0298's upstream file is `component.tsx`, while the frozen bundle stores `.ts` files. Semgrep 1.177.0 emitted syntax errors for the three vulnerable files. The separate probe copied all six files byte-for-byte to `.tsx`, used the same frozen rule, and produced zero errors, findings on all three positives, and no findings on the negatives. This directly supports a suffix-related evaluation failure for this case. The probe does not alter the 12/24 recorded result or any original study result.

See `benchmark/diagnostic_20261010/adjudication_proposals.json` and `results/diagnostic_20261010/failure_audit_v1/` for exact evidence. Broad candidate false positives in CSV export, XML parsing, temporary-file permissions, mass assignment, TLS verification and ineffective escaping are retained; they are not automatically evidence of incorrect labels.

### Verification and failed attempts

- New regression suite: **18 passed**. Includes all five schema forms through the real extraction/sanitization path, legacy rejection, evidence overwrite refusal, four C3/C4 handoff combinations, hidden-feedback ordering, and three scanner failure modes.
- Existing statistics script: **10 checks passed**. Its first invocation through pytest failed with exit 3 because the file executes `sys.exit()` at import time. Rerunning it as its intended standalone script passed. Both commands and outputs are retained; the degenerate Friedman warning is recorded.
- Both frozen prompt function hashes match their pinned values.
- Pinned Semgrep: **1.177.0 verified**. Initial sandbox attempts failed with macOS certificate trust initialization errors. The first outside-sandbox attempt resolved a system `pysemgrep` and reported **1.140.0**, despite the absolute `.venv/bin/semgrep` launcher path. Prepending `.venv/bin` to PATH fixed this delegation issue. The successful preflight, 24 reference scans and TSX probe ran with approved outside-sandbox execution. No TLS verification was disabled.
- The model credential preflight exits explicitly with `GPTLAB_API_KEY unavailable`; no inference was attempted and no token/cost figures are invented.
- `file_changes.json` records the final protected-file check and any discrepancies. Pre-existing changes remain attributable to the starting state.

### Resume instructions and outstanding work

1. Independently review the candidate rules, four location proposals and the suffix probe. Decide a versioned evaluation policy before treating these as a reference baseline. Audit other JSX/TSX cases and helper-extraction annotations; do not silently rewrite the existing freeze.
2. Run any changed parser adapter/scoring policy in a new output namespace and retain paired old/new outcomes. The current runner deliberately continues to use the frozen suffixes and annotations; the known CASE-0298 parser issue will remain visible until a separately versioned change is made.
3. Make `GPTLAB_API_KEY` available in the authorized execution environment (never commit or paste it into a research record). For the already prepared legacy-prompt/schema-only model comparison, use a fresh output path:

```sh
python3 pipeline/diagnostic_audit.py run qwen3_diagnostic_v1 -- .venv/bin/python pipeline/diagnostic_v2.py model --output results/diagnostic_20261010/qwen3_v1
```

The model defaults to `qwen3-coder:30b`, temperature 0, 2048 output tokens, at most three total calls, no SDK retries, shared initial generation for raw/iterative conditions, and no hidden feedback. It may require the same approved execution environment for Semgrep as the successful reference run. Fix/adjudicate the known evaluation issues first if the aim is a corrected measurement rather than a frozen-policy diagnostic.

4. Report paired case outcomes and all-requested denominators. An unrestricted-schema prompt is a separate future condition, not an unrecorded edit to this one. A fresh holdout is needed after choosing a workflow using these cases. C3/C4 budget matching and fresh-holdout construction remain future experiments, not completed work in this pass.
5. After subsequent work, run `python3 pipeline/diagnostic_audit.py checkpoint` to refresh the change and artifact inventories. Historical results are never an output target of these scripts.
