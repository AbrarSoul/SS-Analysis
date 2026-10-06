# Correction Log

Tracks every finding and correction made in response to the 2026-10-06 methodological audit. The
baseline against which every correction below is measured is git commit `e650422`
(tag `baseline-pre-audit`) — the untouched "before" state. Every entry below states what was wrong,
what evidence established that, and exactly what changed (and in which commit), so a reader can
trace any corrected claim back through its original form.

**Rule for this log**: nothing is corrected silently. If a number, claim, or label changes anywhere
in `Paper_Draft_Notes.md` or the result tables as a consequence of this audit, there is an entry
here explaining why, and the original (pre-correction) value remains readable at the
`baseline-pre-audit` tag.

## Audit scope (7-step protocol, as instructed 2026-10-06)

- [x] **Step 1 — Preserve the current experiment.** Baseline commit `e650422` (tag
      `baseline-pre-audit`) created 2026-10-06, covering the design document, vendored Autogrep
      fork, pipeline code, the full curated dataset (40-case pilot + 300-case final), every
      reported result set (primary benchmark, 5-rep stability study, C2, C3-S/C3-E, C4-A/C4-B,
      Section 22 statistical analysis), and the paper draft, exactly as they stood before any
      audit-driven change. Excluded: `data/` (re-downloadable source dump), `.venv/`, and one
      disposable pre-experiment smoke-test run (`results/runs_final_realsmoke_*`, never part of
      any reported result — contained embedded git clones that would have complicated the commit
      without adding anything the audit needs).
- [x] **Step 2 — Audit the evaluator.** COMPLETE (reopened once, see Finding 5, while starting
      Step 3 — a real gap in the original audit, not held back deliberately). Wrapper schema
      restrictions, Semgrep errors, skipped files, finding-location checks, original vs.
      transformed samples; separated compilation success from visible-pair acceptance. Findings
      1-5 below; Finding 1 (serious) is fixed and committed.
- [x] **Step 3 — Audit questionable dataset cases.** COMPLETE except the independent second-rater
      review, which depends on action outside this session. All 11 kept-and-flagged cases documented
      with their specific concerns; benign-lookalike uncertain-negative count corrected to 4
      confirmed; bypassable-fix ground-truth concern quantified (negligible measured impact, no
      rerun needed); 2 parsing-problem cases confirmed; CASE-0166 excluded and CASE-0084 kept, both
      per the user's explicit decision (2026-10-07). Remaining open item: the independent second-rater
      review (needs
      a genuinely independent rater, not this session).
- [x] **Step 4 — Recompute all metrics consistently.** COMPLETE. All 5 required rows (compilation
      rate, acceptance coverage, conditional MCC, end-to-end hidden-positive detection rate,
      end-to-end successful rule rate) built for every condition with explicit denominators —
      `pipeline/build_step4_tables.py`, full output `results_corrected/step4_tables_report.txt`.
- [x] **Step 5 — Verify workflow comparability.** COMPLETE. See
      `Research_Log/Workflow_Comparability_C2_C3_C4.md`. Found 3 previously-unstated real
      asymmetries beyond "role separation": C3/C4's Rule Generation never sees the raw diff (only
      a Patch Analysis summary); C2 gets 3 repair rounds vs. C3/C4's 1; C3/C4's round-0 acceptance
      gate is strictly stricter (requires an agent verdict AND the deterministic check, vs. C2's
      deterministic-only gate). Also found C3/C4 never enforce the cumulative token/wall-clock
      budget dimensions C2 does (only the call-count cap is shared).
- [x] **Step 6 — Recalculate statistics.** COMPLETE. Section 22's full battery rerun on corrected
      data with repository-aware bootstrapping throughout (the case-level/repo-level inconsistency
      is now fixed). See the dedicated entry below for the full before/after comparison.
- [ ] **Step 7 — Rewrite the paper and assemble reproducibility artifacts.** Remove unsupported
      causal claims, reconcile contradictory records, provide reproduction materials. NOT STARTED.

## Findings log (chronological, newest last)

### 2026-10-06 — Pre-Step-2 scan: issues already visible without a deep code audit

Noted while setting up this log, to be formally confirmed or refuted during Step 2 rather than
acted on yet:

1. **Repo-aware bootstrap inconsistency**: `pipeline/analyze_section22_subgroups.py`'s subgroup
   analysis correctly resamples at the repository level. `pipeline/stats_section22.py`'s
   `paired_case_bootstrap()`, used for ALL 7 of Section 22.3's main comparisons, resamples at the
   CASE level, not the repository level. This is inconsistent with the audit's Step 6 instruction
   ("repository-aware uncertainty estimates" for every recalculated statistic) and with this
   study's own stated principle (cases from the same repository aren't independent) — it was
   applied only where it happened to be built first (subgroup analysis), not uniformly. To be
   fixed in Step 6.
2. **"Provably contamination-free" (Paper_Draft_Notes.md §8)**: overclaims certainty a CVE-year
   boundary can't actually provide (it bounds TRAINING cutoff, not fine-tuning data, not
   memorization from secondary sources referencing the CVE before the model's cutoff, etc.) — to
   be replaced with qualified contamination-risk language per the audit's explicit instruction.
3. **"GPU-hours" (SSRP `00_README_Overview.md`)**: conflates measured wall-clock elapsed time
   (what was actually computed, from first-to-last timestamp) with GPU-hours (which would require
   knowing concurrency and simultaneous GPU utilization, never measured) — to be corrected to
   "elapsed runtime" throughout.
4. **"Regression" terminology**: used informally in places to describe repair-round outcomes;
   needs checking against whether any ACTUAL before/after same-rule comparison exists, or whether
   it should be renamed since no such paired evidence was collected.
5. **Causal framing beyond what was tested**: "interface mismatch" (C4-A) and "self-assessment
   reliability" (C2-vs-C3 reviewer reasoning) are READINGS of observed point estimates, not
   directly tested mechanisms — already partly hedged in Paper_Draft_Notes.md's §7.7/§7.8
   amendments, but need checking throughout for any place they're still stated as established
   fact rather than explicitly labeled hypotheses.

These are preliminary; Step 2 (evaluator audit) proceeds next, since several of Step 4's required
corrections depend on first confirming whether the evaluator itself is computing outcomes
correctly.

### 2026-10-06 — Step 2 (evaluator audit): findings

Audited `pipeline/sample_evaluation.py` (the real evaluator used by every reported result since
Phase 2 — `evaluate_case_bundle()`, per its own docstring), `pipeline/result_schema.py`
(`SampleExecutionRecord._derive_outcome()`), and how `run_c3.py`/`run_c4.py` consume
`validator.validate_rule()`'s output. Checked every item against real data rather than reading code
in isolation.

**Finding 1 — CONFIRMED, SERIOUS: finding-location correctness is never checked for the hidden
held-out vulnerable variants.** Design doc Section 9.3 / this codebase's own stated intent
(`result_schema.py` line 108-110 comment) is that "a positive sample only counts as a true positive
if the finding is at the correct location, not merely somewhere in the file." In practice:
- For `original_vulnerable`: the check works correctly. Verified empirically across all 2,529
  real `detected=True` records in this sample type (primary benchmark + C2 + C3 + C4 combined):
  zero fell through to the "unknown, assume correct" default — `finding_location_correct` was
  always explicitly `True` or `False`. 205/1,433 (14.3%) of firings were correctly caught as
  wrong-location and downgraded from TP to FN.
- For `variant_vulnerable_1` and `variant_vulnerable_2` — **the two hidden, transformed samples
  VGR (the headline "generalization to hidden variants" metric) is actually computed from** —
  `finding_location_correct` is `None` for ALL 6,024 real records of this type, no exceptions.
  `evaluate_case_bundle()` (`pipeline/sample_evaluation.py` lines 201-204) only ever computes a
  location check `if sample_type == "original_vulnerable"` — it was never extended to the
  transformed variants. `result_schema.py`'s `_derive_outcome()` then treats `None` as "not
  disproven" (`finding_location_correct is not False`), so every one of these samples' TPs has been
  counted on the basis of "Semgrep matched SOMEWHERE in this file," not "Semgrep matched the actual
  (transformed) vulnerable construct." This means **every VGR number reported anywhere in this
  study** (Paper_Draft_Notes.md §7, §7.6-§7.8, every C2/C3/C4 comparison) **is, to an unquantified
  but potentially substantial degree, measuring "fires somewhere in a modified file" rather than
  "correctly re-identifies the transformed vulnerability."** Given 14.3% of the (easier, less
  transformed) `original_vulnerable` firings were wrong-location, a comparable or higher rate on
  the more heavily transformed variants is plausible, not merely theoretical.
- Root cause for why this wasn't caught at build time: the code's own docstring is explicit and
  honest about the gap ("the four new Section 9 samples... don't have an equivalent per-file
  line-range annotation yet — left None (unverified) rather than guessed") — this was a known,
  disclosed-in-code limitation that was never surfaced in `Paper_Draft_Notes.md` or flagged as a
  limitation anywhere user-facing. That is the actual process failure: an acknowledged code-level
  gap never made it into the reported results' caveats.
- **Feasibility of a retroactive fix, checked directly**: `finding_lines` (the actual line numbers
  Semgrep reported) IS already stored for every sample record — no new Semgrep execution is
  needed. What's missing is a per-variant "where is the transformed vulnerable construct"
  line-range annotation. Spot-checked one build script (`pipeline/section9_final/
  build_bundle_case0078.py`): each variant is built by a deterministic `str.replace()` of a known,
  literal source block against the original file — meaning the transformed block's exact text (and
  therefore its line range in the final constructed file) IS recoverable from each build script
  without rerunning anything, just a new extraction pass across all ~153-300 build scripts. This is
  real, scoped engineering work, not a full rerun — flagged for a decision on whether to do it
  before Step 4's metric recomputation (VGR cannot be trusted as "correctly re-identifies the
  vulnerability" until this is fixed, only as "fires somewhere in the file").

**Finding 2 — CONFIRMED: "accepted" conflates compilation success with visible-pair correctness,
exactly as suspected.** `validator.validate_rule()`'s `is_valid` boolean (used directly as
`accepted` in C2/C3/C4) is `True` only when the rule BOTH executes without a real Semgrep/schema
error AND correctly discriminates the visible vulnerable/patched pair — there was no separate
"did it even compile and run" signal anywhere in the orchestrators. Decomposed it retroactively
using the stored `validation_error` text (distinguishing real Semgrep/schema-level rejections —
"Rule parse error", "Syntax error", schema-conflict messages — from the two specific
discrimination-failure messages, "Rule failed to detect vulnerability in original version" /
"Rule incorrectly detected vulnerability in fixed version", which mean the rule ran perfectly fine
and just gave the wrong answer). Result, computed directly from the real episode logs — **a
genuinely new, previously uncomputed breakdown**:

| Condition | Compilation rate (ran without a real error) | Acceptance coverage (also correct on visible pair) | Of the gap: discrimination failures | Of the gap: real compile/schema failures |
|---|---:|---:|---:|---:|
| C3-S | 58.8% (90/153) | 22.9% (35/153) | 35.9% (55/153) | 41.2% (63/153) |
| C3-E | 69.9% (107/153) | 8.5% (13/153) | 61.4% (94/153) | 30.1% (46/153) |
| C4-A | 68.0% (104/153) | 7.2% (11/153) | 60.8% (93/153) | 32.0% (49/153) |
| C4-B | 62.7% (96/153) | 17.0% (26/153) | 45.8% (70/153) | 37.3% (57/153) |

This is a materially different picture from "coverage" alone: for every condition, MOST of the gap
between "compiles" and "accepted" is discrimination failure (the rule runs cleanly but gives the
wrong answer on the visible pair), not a syntax/schema problem — directly useful for Step 4's
required compilation-rate row, and directly contradicts any implicit reading of low "acceptance
coverage" as primarily a generation/compilation problem.

**Finding 3 — checked, NOT a live problem**: the "tolerate a missing sample file rather than
hard-failing the whole bundle" code path (`evaluate_case_bundle`, `if not target.exists(): continue`)
never actually fired across any of the 2,559 real (run-file, case) evaluation groups checked —
every bundle had all 6 expected sample types present. The defensive code exists but has not been
silently shrinking any denominator in any reported result to date.

**Finding 4 — not yet checked**: `evaluate_original_pair()` (the OTHER evaluation path, used for
the raw-`.patch`-file flow / `_check_original_pair()` during generation, as opposed to
`evaluate_case_bundle()` used for final hidden-sample scoring) has a theoretical gap where a
missing file at a given commit (`if not target.exists(): continue`) could cause a scan that never
ran to be silently recorded as `detected=False`, which for a negative-labeled sample becomes a TN —
exactly the "true-negative credit for a scan that never ran" failure mode named in the audit. Not
yet checked against real data for actual occurrence (lower priority than Findings 1-2 since this
function is used for the IN-PROCESS visible-pair check during generation, not for any of the
hidden-evaluation numbers reported in the paper — but still needs confirming before Step 4 closes).

**Finding 4 — CHECKED, NOT a live issue.** Traced every caller of `evaluate_original_pair()`
(`pipeline/run_generation.py`): it is only reachable via `evaluate_case()`, which is only called
from `run_model()`, which is only invoked by `main()`'s `--patches-dir` flag (the Phase 1
raw-`.patch`-file smoke-test flow). Every real reported result (primary benchmark, stability study,
and by extension every C2/C3/C4 run built on the same curated cases) uses `--cases final`/
`--cases stability`, which routes through `run_model_on_cases()` -> `evaluate_case_from_curated()`
-> `evaluate_case_bundle()` exclusively -- confirmed directly from `main()`'s argument-parsing
branch, not inferred. The theoretical "scan never ran, silently counted as a true negative" gap in
`evaluate_original_pair()` exists in code, but that code path has never produced any number in
`Paper_Draft_Notes.md`.

**Wrapper schema restrictions — checked.** `autogrep/llm_client.py`'s `validate_rule_schema()` (the
actual wrapper gate, run before a rule ever reaches Semgrep) only requires the 5 fields Semgrep
itself always needs (`id`, `pattern`, `message`, `severity`, `languages`), checks `severity` against
a fixed enum, and checks `id`'s character set -- it does NOT inspect `pattern`'s internal type/shape
at all. `_sanitize_rule()` (run earlier in the same pipeline) auto-fills `languages`/`severity`/
`metadata` when missing rather than rejecting the rule for their absence. This means the wrapper is
reasonably permissive and was not found to reject anything Semgrep itself would have accepted; the
genuine type/shape strictness (e.g. the 30 "X is not of type 'string'" cases from the §24
failure-taxonomy work, where a model nested a list/dict where Semgrep's own JSON-schema requires a
plain string) correctly happens at Semgrep's own validation layer, which is already counted as a
Semgrep-level rejection in every analysis in this project -- no false-rejection risk found at the
wrapper layer.

**Step 2 is now complete.** Moving to Step 6 (recalculate statistics) directly, per the user's
instruction to finish any remaining Step 2 items before rerunning Section 22's statistical battery
on the corrected data from Finding 1's fix.

### 2026-10-06 — Finding 5 (found while starting Step 3, retroactively belongs to Step 2): wrapper
### requires a literal top-level `pattern` key, rejecting valid composite-pattern rules

While beginning Step 3's dataset audit, re-read `Implementation_Log.md`'s own record of this exact
issue (Section 12.30-adjacent, "Noted, not changed" at the time): `autogrep/llm_client.py`'s
`validate_rule_schema()` hard-requires a literal `pattern` key (`required_fields = ['id', 'pattern',
'message', 'severity', 'languages']`). Re-verified directly in the current code: this means ANY
syntactically valid Semgrep rule using `patterns:` (the list combinator), `pattern-either:`, or
`pattern-not:` instead of a bare `pattern:` string is rejected by THIS WRAPPER before ever reaching
Semgrep — even though Semgrep itself accepts all of these forms. This is exactly the audit's named
concern ("wrapper schema restrictions... a valid rule rejected only during offline scoring"), except
it fires at GENERATION time, not offline scoring, for every model in the entire study, in every
condition (primary benchmark, C2, C3, C4) — `parse_and_sanitize_response()` is the single shared
code path all of them use.

**Practical significance, checked rather than assumed**: a model correctly using `pattern-not` to
exclude a benign look-alike — directly relevant to this study's own FPR metric — can never do so
successfully, no matter how good the underlying reasoning is. This is a structural ceiling on every
condition's achievable FPR, not a per-model quirk.

**Measured real-world footprint**: searched every real generation/episode log (primary benchmark,
C2, C3, C4) for this specific rejection (`"Missing required fields: pattern"` or `"...pattern,
message"`) — found 16 occurrences total, ALL concentrated in C2 (1 in `deepseek-coder:6.7b`, 15 in
`magicoder:7b` — zero in the primary benchmark's raw/autogrep conditions and zero in C3/C4).
**Cannot verify whether these 16 are genuine composite-pattern attempts wrongly rejected, or just
malformed output from `magicoder:7b`** (independently established as one of this study's weakest,
least format-consistent models) **that happened to omit `pattern` for an unrelated reason** — no raw
rule text was retained for C2 (confirmed: its episode schema has no text field for the proposed
rule), so this cannot be resolved retroactively without either recovering lost artifacts (not
available) or regenerating (a rerun, not justified by 16 out of several thousand real attempts).

**Resolution**: NOT retroactively fixable with available data, and the observed footprint (16
occurrences, concentrated in one already-weak model/condition pair) does not justify a full rerun
under "rerun only what the audit shows is necessary." This is reported as a disclosed **validity
threat / known limitation** for the manuscript (Step 7's job) rather than silently left out: the
study structurally could never evaluate any model's ability to express a vulnerability using
Semgrep's composite pattern forms, and this plausibly suppresses achievable FPR for any model whose
best rule-writing instinct would have reached for `pattern-not`. Stated honestly rather than buried,
per the audit's own "do not claim complete contamination/limitation removal" spirit.

### 2026-10-06 — Finding 1 FIXED, impact measured: this is a major correction, not a minor one

Per the user's explicit direction ("fix it now, before continuing the audit"), built and ran the
fix for Finding 1:

1. **`pipeline/compute_variant_vulnerable_lines.py`** — computes, for every case's two vulnerable
   variants, the line range where the (transformed) vulnerable construct actually sits, WITHOUT
   parsing any build script or re-executing anything. Method: variants are built by replacing one
   localized block and leaving the rest of the file byte-identical, so the known ORIGINAL file's
   `vulnerable_lines` range (always populated, 300/300) can be mapped to the variant via anchor
   text matching (lines immediately before/after the known range, located in the variant, preferring
   the occurrence nearest the expected position — a real bug in the first version, caught by testing
   on 5 diverse real cases before trusting it: a naive "first occurrence" match put CASE-0150 badly
   wrong, 144-line inferred span vs a true 42-line span; fixed and reverified clean on all 5 test
   cases before running at scale), with a diff-opcode-overlap fallback and an explicit confidence
   flag (span-ratio sanity check) so a wrong inference is never silently trusted.
   **Result: 600 variant annotations computed, 571 (95.2%) high-confidence, 29 (4.8%) flagged LOW
   for manual review rather than used.** Output: `benchmark/variant_vulnerable_lines.jsonl`.
   **Not yet covered**: the 40-case pilot set (`manifest.jsonl`) has no `vulnerable_lines` field at
   all, so this fix doesn't reach it yet — lower priority since the pilot was only used for
   prompt-template/model selection (§6), not any headline result, but flagged here rather than
   silently left out of scope.

2. **`pipeline/rescore_variant_location.py`** — applies the high-confidence annotations to every
   existing `variant_vulnerable_1/2` sample record with `detected=True` across every real result
   set (primary benchmark, all 5 stability reps, C2, C3-S/C3-E, C4-A/C4-B), recomputing
   `finding_location_correct` and `outcome` using the SAME `SampleExecutionRecord._derive_outcome()`
   logic already trusted elsewhere (reused directly, not reimplemented). Writes corrected copies to
   `results_corrected/` — every original file under `results/` is untouched (verified: a diff of any
   original against its corrected counterpart shows ONLY the rescored records' two fields changed,
   nothing else).

   **Result: of 4,063 "detected=True" hidden-variant records across the whole study, 879 (21.6%)
   were wrong-location matches, now correctly reclassified from TP to FN.** This is not a small
   correction — roughly 1 in 5 "hidden-variant detections" this entire study's VGR metric has been
   built on were matching the wrong part of the file, not the actual (transformed) vulnerability.

3. **Measured the actual downstream impact on every condition's MCC/VGR** (recomputed from
   `results_corrected/` using the same `confusion_from_samples`/`mcc`/`rate` functions used
   throughout this project, for direct comparability):

   **Primary benchmark (autogrep condition), ORIGINAL -> CORRECTED**:

   | Model | MCC | VGR |
   |---|---|---|
   | DeepHat-V1-7B | 0.581 -> 0.556 | 0.473 -> 0.429 |
   | codegemma:7b | 0.553 -> 0.493 | 0.477 -> 0.372 |
   | codellama:7b-instruct-fp16 | 0.526 -> 0.511 | 0.346 -> 0.321 |
   | deepseek-coder:6.7b | 0.609 -> 0.514 | 0.583 -> 0.417 |
   | magicoder:7b | 0.567 -> 0.432 | 0.567 -> 0.333 |
   | qwen2.5-coder:32b | 0.608 -> 0.552 | 0.622 -> 0.529 |
   | qwen2.5-coder:7b-instruct | 0.598 -> 0.508 | 0.658 -> 0.507 |
   | yi-coder:9b | 0.584 -> 0.528 | 0.537 -> 0.441 |

   **The headline model ranking changes.** Original (excluding `codellama` per its existing
   precision-confound flag): `deepseek-coder` (0.609) > `qwen32b` (0.608) > `qwen7b` (0.598) >
   `yi-coder` (0.584) > `DeepHat` (0.581) > `magicoder` (0.567) > `codegemma` (0.553). **Corrected**:
   `DeepHat` (0.556) > `qwen32b` (0.552) > `yi-coder` (0.528) > `deepseek-coder` (0.514) > `qwen7b`
   (0.508) > `codegemma` (0.493) > `magicoder` (0.432). `DeepHat` moves from 5th to 1st;
   `deepseek-coder` drops from 1st to 4th; `qwen7b` drops from 3rd to 5th. The two weakest
   format-following models (§9's own finding: `deepseek-coder` and `magicoder` had the worst
   YAML-invalid rates) also show the LARGEST corrections (-0.096 and -0.135 MCC respectively) —
   a coherent pattern (looser, less precisely-targeted rules get more undeserved credit under the
   old scoring), not noise.

   **C2 (all 8 models)** and **C3/C4 (4 multi-agent configs)** both corrected similarly (full
   tables in this commit's diff) — multi-agent conditions shift by a smaller, more uniform amount
   (-0.013 to -0.048 MCC) since C3/C4's own Semantic Review step already filters out some of the
   worst-discriminating rules before they'd ever reach this stage. One qualitative change worth
   flagging directly: the `qwen2.5-coder:7b-instruct` C2-vs-C3-E comparison (§7.6, previously
   reported as "flat," MCC 0.601 vs 0.593) becomes 0.504 vs 0.545 after correction — a sign flip
   (C3-E now reads as BETTER than C2 for this model, not flat/slightly worse). Whether this is a
   real, significant change or still noise is NOT yet known — Section 22's statistical battery
   was run entirely on the UNCORRECTED data and needs to be rerun on `results_corrected/` before
   any claim (old or new) about C2-vs-C3 or any other comparison can be trusted.

**Status**: Finding 1 is fixed at the data layer (corrected sample logs + annotations exist and are
committed). Step 4 (recompute all metrics) and Step 6 (recalculate statistics) are NOT yet done
against this corrected data — the numbers above are point estimates only, re-derived with the
project's existing pooling functions for a fast comparison, not yet run through Section 22's actual
paired/bootstrap/Holm-corrected machinery. That is the next concrete piece of work, and given the
ranking change above is substantial, it should happen before any other claim in
`Paper_Draft_Notes.md` is treated as current.

### 2026-10-06 — Step 6 (recalculate statistics): Section 22 rerun on corrected data

Per the user's direction (finish any remaining Step 2 items, then proceed to the rerun), built
`pipeline/analyze_section22_corrected.py` and `pipeline/analyze_section22_subgroups_corrected.py` —
neither modifies the original `analyze_section22.py`/`analyze_section22_subgroups.py` (which stay
reproducible against the ORIGINAL uncorrected data, per Step 1's preservation principle); both
import the same stats machinery and only swap the sample-record source to `results_corrected/`
(episode/generation logs still come from the original `results/`, since Finding 1 only affects
hidden-variant sample scoring, not the visible-pair accept/reject decision those logs record).

**Also fixed a real inconsistency flagged during the pre-Step-2 scan**: the original
`analyze_section22.py`'s 7 main comparisons used a CASE-level paired bootstrap, while
`analyze_section22_subgroups.py` correctly used a REPOSITORY-level bootstrap. Every comparison in
the corrected rerun now resamples at the repository level, closing that inconsistency per the
audit's explicit "repository-aware uncertainty estimates" instruction.

**Full corrected results**: `results_corrected/comparisons_1_7_corrected_report.txt` and
`results_corrected/subgroup_corrected_report.txt`. Headline changes versus the original run:

1. **Comparisons 1-2 (scale, security fine-tuning)**: conclusion unchanged — no statistically
   detectable difference either way, both before and after correction.
2. **Comparison 3 (family effect)**: conclusion unchanged — omnibus significant (p=0.0083,
   was 0.0140), zero pairwise comparisons survive Holm correction either before or after.
3. **Comparison 4 (raw vs autogrep)**: conclusion unchanged and the effect remains essentially the
   same large magnitude for every model. Still massively significant for all 8 models (p=0.0000
   each), still the single most robust finding in the study. **This finding is robust to the
   correction.**
4. **Comparison 5 (C1 vs C2)**: same shape, conclusion unchanged.
5. **Comparison 6 (C2 vs C3)**: `qwen2.5-coder:32b` C2-vs-C3-S — p moves from 0.0730 (case-level
   bootstrap, uncorrected data) to 0.0814 (repo-level bootstrap, corrected data) — **conclusion
   unchanged: no statistically detectable difference, both before and after.** `qwen2.5-coder:
   7b-instruct` C2-vs-C3-E — point estimate direction flips (0.601 vs 0.593, roughly flat ->
   0.504 vs 0.545, C3-E nominally ahead) but the CI is wide and crosses zero in both the original
   and corrected analysis — **conclusion unchanged: no statistically detectable difference either
   way.** Worth stating plainly: the point estimate moved, but neither the original nor the
   corrected analysis supports treating that movement as a real, detected effect.
6. **Comparison 7 (C3 vs C4)**: **the Friedman omnibus on ESR becomes significant after
   correction** (p=0.0275, was 0.0981 — a real change, not noise, given the corrected ESR values
   themselves shifted). However, of the 6 pairwise MCC repo-aware bootstraps, **none reach
   significance after Holm correction** (closest: C3-S vs C4-A, raw p=0.1010, Holm-adjusted
   0.6060) — same conclusion as before the correction: the point-estimate spread across the four
   multi-agent configurations is NOT statistically distinguishable from chance at this sample size,
   corrected data included.

**Subgroup analysis, rerun on corrected data**: all CIs remain entirely positive; the qualitative
pattern is essentially unchanged (python highest MCC, typescript lowest; patch-size shows the same
visually monotonic decline from small to large; the same 6 CWEs clear the >=10-case threshold, with
IDENTICAL point estimates for CWE-78/CWE-22/CWE-79 — those specific CWEs' cases happened not to be
affected by any TP->FN flip in this model/condition combination).

**Overall assessment of Finding 1's correction, now that the full statistical rerun is complete**:
the correction materially changes the primary benchmark's headline MODEL RANKING (a real, reportable
change — DeepHat moves from 5th to 1st) and every point estimate moves down by an uneven amount,
but it does **NOT** change which comparisons are statistically significant versus not, anywhere in
Section 22, with one exception (Comparison 7's omnibus test, which newly crosses the significance
threshold but still shows zero surviving pairwise differences after correction — not a reversal of
the qualitative story, "no detectable pairwise difference among the 4 multi-agent configs," just a
stronger omnibus signal that something differs in aggregate). The single most important practical
implication: **any claim in `Paper_Draft_Notes.md` that cites a specific MCC/VGR number or ranks
models/conditions against each other needs updating to the corrected values** before the paper is
finalized, even though the qualitative significance conclusions mostly carry over unchanged.

Not yet done: updating `Paper_Draft_Notes.md` itself to replace every affected number and the
headline ranking narrative with the corrected version — that is Step 7's job and is the next piece
of work, after Steps 3 and 5 (dataset audit, workflow-comparability table) are addressed.

### 2026-10-06 — Step 3 (dataset audit): the benign-lookalike uncertain-negative count, quantified

`Paper_Draft_Notes.md`'s own limitations section (§10, originally §8) has long stated qualitatively
that "for a small number of cases, the benign look-alike sample is syntactically identical to the
vulnerable code... Worth identifying and reporting the affected case count explicitly" — but that
count was never actually computed. Computed it now: for every one of the 300 cases, extracted the
manifest's own `vulnerable_lines` snippet from `vulnerable_source` and compared it (via a sliding-
window `difflib.SequenceMatcher` ratio, tolerant of renamed identifiers/whitespace) against every
same-length window of `benign_lookalike`.

**Result: 1 case (`CASE-0069`) is a confirmed, manually-verified near-identical match (ratio
0.983)** — `OpenNMS/opennms`'s `hasEditRights`/`hasViewRights` methods share the EXACT SAME boolean
check (`isUserInRole(ROLE_ADMIN) || isUserInRole(ROLE_REST)`), differing only in method name and an
explanatory comment; the check is a genuine vulnerability in the write-permission context and
correct in the read-permission context — textbook "no purely syntactic rule can tell these apart."
**3 further cases (`CASE-0111` 0.853, `CASE-0136` 0.820, `CASE-0067` 0.769) are moderately similar**
but not individually manually verified here (flagged for a closer look if a reviewer wants it,
rather than silently counted as confirmed or silently dropped).

This replaces "a small number of cases" with a precise, checkable number: **1 confirmed, up to 4
total if the moderate-similarity band is included**, out of 300 — a real but small effect, now
stated as a number rather than an impression.

**Correction after cross-checking against the log (see next entry)**: the log independently
documents 3 MORE cases (`CASE-0078`, `CASE-0238`, `CASE-0342`) with this exact issue, verified by
direct inspection at curation time rather than the automated similarity heuristic above. Re-checked
all 3 against my own method and found why my heuristic missed them: in each, only a SHORT, specific
construct (a single API call — `Papaparse.unparse({...})` for 0238, `new Yaml()` for 0342) is
identical between the files, not the WHOLE vulnerable snippet (my sliding-window ratio compares the
full snippet length, which washes out a short embedded match inside a much shorter/longer benign
file). **Corrected total: 4 confirmed cases (`CASE-0069`, `CASE-0078`, `CASE-0238`, `CASE-0342`),
plus the 3 unverified moderate-similarity cases from the automated check** (`CASE-0111`, `CASE-0136`,
`CASE-0067`) — combining both detection methods rather than trusting either alone.

### 2026-10-06 — Step 3 (dataset audit): the complete "kept and flagged" case review

Delegated the search (300K-character free-text log, phrasing varies) to a background research
agent, since this is a thorough-search task rather than a judgment task — the judgment (what each
finding means for the dataset's correctness claims) is done here, not by the agent. The agent
cross-checked every candidate case ID against live `metadata.json` to rule out stale/renumbered
references (case IDs were reshuffled by early exclusions before ids were pinned — a real risk the
agent correctly guarded against) and explicitly excluded every case that was EXCLUDED-and-replaced
(not relevant here) and every PILOT-range case (CASE-0001-0040, a separate concern).

**11 cases in the final 300 are explicitly KEPT with a disclosed upstream-fix/advisory concern**:

| Case | Repo / CVE | Concern |
|---|---|---|
| CASE-0107 | apache/netbeans-html4j, CVE-2020-17534 | zip-slip present in BOTH vulnerable and upstream-patched code, not the labeled CWE — disclosed, not fixed in the safe variant (explicit "observed but not acted on" decision) |
| CASE-0125 | axios, CVE-2024-57965 | disputed advisory — old/new logic identical on all 14 tested string URLs |
| CASE-0140 | dataease, CVE-2022-39312 | upstream denylist bypassable via percent-encoding (`auto%44eserialize=true` → active `autoDeserialize=true`) |
| CASE-0154 | eladmin, CVE-2025-22978 | xlsx export — the CWE-implied formula-injection risk doesn't actually manifest (strings never become formula cells) |
| CASE-0156 | DB-GPT, CVE-2024-10901 | upstream denylist bypassed via relative-path scan + `glob` |
| CASE-0166 | weixin4j, CVE-2026-24819 | upstream-patched file references an undefined constant (`MAXIMUM_CAPACITY`) and **does not compile** |
| CASE-0170 | sentry, CVE-2024-32474 | upstream fix misses a sibling log call (`validated_data`) that leaks the same sensitive data |
| CASE-0174 | transformers, CVE-2025-6051 | ReDoS fix is still quadratic (mitigated, not eliminated) |
| CASE-0194 | sidebar-link-plugin, CVE-2023-32985 | path check uses `startsWith` without a separator — classic sibling-directory bypass |
| CASE-0199 | docassemble, CVE-2024-27292 | filename gate doesn't guard against a bare `..` |
| CASE-0211 | langchain, CVE-2024-27444 | denylist-based code validator bypassed via a `getattr` string |

**A real inconsistency the agent surfaced, worth a decision rather than silent resolution**:
`CASE-0166` was KEPT despite its patched file not compiling — the exact same defect class that got
`CASE-0063` EXCLUDED earlier in the project. The log gives no stated rationale for the different
treatment. Flagged for the user rather than silently resolved either way.

**One decision explicitly left open by the log itself, not yet revisited**: `CASE-0084`
(audiobookshelf, CVE-2025-25205) was hand-curated to its real fix commit, but the log's own words
are "flagged here so it can be reversed if you would rather exclude it" — i.e., this was never
actually finalized as a considered-and-kept decision the way the other 11 were; it's an open
question.

**Parsing problems** (Semgrep failing on the case's own fixture file, not a rule defect — already
found independently during this session's §24 work, now cross-confirmed by the agent from the log):
`CASE-0055`, `CASE-0298`.

**Near-duplicate provenance** (not an open issue, included for completeness): `CASE-0276`/`CASE-0337`
are kept; their byte-identical-patch-content duplicate siblings `CASE-0277`/`CASE-0338` were
already excluded and replaced (`CASE-0341`, `CASE-0342`) — fully resolved prior to this audit.

**The methodologically important implication, per the audit's own instruction** ("distinguish
'upstream patched revision' from 'verified safe for the target weakness'. Keep partial or uncertain
fixes outside the strongest binary correctness claims"): for AT LEAST 6 of the 11 cases above
(`CASE-0140`, `CASE-0156`, `CASE-0174`, `CASE-0194`, `CASE-0199`, `CASE-0211`), the upstream "fix" is
**bypassable or incomplete, not actually safe** — meaning the dataset's `original_patched` ground-truth
label (expected TN) is questionable for these specific cases. **A model that correctly flags one of
these "patched" samples as still-vulnerable is currently scored as a false positive, when it may be
giving the MORE correct answer than the ground truth assumes.**

**Quantified the actual impact rather than leaving this as a theoretical concern**: of these 6, only
3 (`CASE-0140`, `CASE-0156`, `CASE-0194`) fall in the 153-case `supported` set used for every
multi-agent and headline comparison (the other 3 are `partially_supported`/`unsupported`, already
excluded from the primary ranking per §7.3's own convention). Checked every real `original_patched`
sample record for these 3 cases across EVERY condition in the whole study (primary benchmark x8,
C2 x8, C3-S/E, C4-A/B) — **33 total records, of which exactly 1 is an FP** (`DeepHat-V1-7B`,
`CASE-0140`, autogrep condition — notably the one model explicitly screened for security
fine-tuning, catching the one bypass another model might have missed). **A sensitivity re-analysis
excluding these 3 cases would change at most 1 sample's classification out of several thousand
pooled negative samples study-wide — a negligible effect on any reported FPR/MCC number.** Per the
audit's own "rerun only what the audit shows is necessary": this does NOT need a metrics rerun. The
methodological point (upstream-patched ≠ verified-safe) is real and worth stating in the manuscript
as a limitation, but it has not, in fact, measurably distorted any number reported so far — checked,
not assumed.

**Step 3 summary / remaining open items for the user, not resolved by this session**:
1. `CASE-0166` vs `CASE-0063` precedent inconsistency (same defect class — non-compiling patched
   file — one excluded, one kept) — needs a decision, not silently resolved either way here.
2. `CASE-0084`'s hand-curation was explicitly left reversible in the log ("flagged here so it can
   be reversed if you would rather exclude it") — never actually revisited; needs a decision.
3. The independent second-rater review — requires a genuinely independent rater per its own setup;
   not completed by this session (see above).

Everything else in Step 3 (the 11 kept-and-flagged cases' concerns, the corrected benign-lookalike
count, the 2 parsing-problem cases, the bypassable-fix sensitivity check) is now documented,
quantified, and — where checked — confirmed to have no further corrective action required.

### 2026-10-06 — Step 4 (recompute all metrics consistently): the explicit 5-row table

Built `pipeline/build_step4_tables.py` against the CORRECTED data throughout. Full output:
`results_corrected/step4_tables_report.txt`. Every row's denominator is stated explicitly; a
missing/invalid rule contributes 0 to the end-to-end detection numerator and 0 to the end-to-end
success numerator, never silently excluded from either denominator and never credited as a true
negative for a scan that never ran.

**One real limitation surfaced while building this, stated rather than hidden**: for the
`autogrep` primary-benchmark condition specifically, compilation rate and acceptance coverage come
out IDENTICAL for every model. This is not a bug — Autogrep's own retry loop only ever RETURNS a
rule once it has already passed full validation (`semgrep_valid = autogrep_rule is not None` by
construction, `run_generation.py` line 201/302), so the "compiled but failed discrimination"
distinction that IS visible for `raw`/C2/C3/C4 is structurally invisible for `autogrep` — there is
no way to recover it retroactively without re-architecting that condition's own validation loop.

**The headline result — this is the single most important corrected number in the whole study**:
end-to-end hidden-positive detection rates range **1.6%-16.3%** across every condition, and
end-to-end successful-rule rates range **0.7%-5.9%** — both dramatically lower than the "conditional"
MCC/VGR numbers (computed only among already-accepted cases, 0.36-0.67 MCC) that this project has
reported throughout. The best-performing condition by end-to-end success is `C3-S` (5.2%, 8/153)
and `DeepHat-V1-7B` under C2 (5.9%, 9/153) — meaning even the best-performing condition in this
entire study solves fewer than 1 in 16 requested cases completely end-to-end. This is exactly the
gap the audit named as "the paper's strongest current focus" — now quantified precisely, per
condition, rather than left implicit behind conditional-quality numbers that look far more
favorable in isolation.

Step 4 is now complete. Combined with Steps 1-3, 5, and 6 all complete, the only remaining work is
Step 7: rewriting `Paper_Draft_Notes.md` with the corrected numbers, the explicit 5-row tables, the
hedged causal language, and the specific manuscript-wording corrections the audit lists (contamination
language, "no statistically detectable difference" phrasing, elapsed-runtime-not-GPU-hours, etc.).

### 2026-10-07 — The 3 open Step 3 decisions: 2 resolved by the user, 1 still pending

**CASE-0166: EXCLUDED, on the user's explicit decision** ("The upstream patched revision does not
compile, so it cannot serve as a verified executable negative reference. Adding the missing
constant would create a researcher-modified fix rather than preserve the real upstream revision").
Implemented as a new row in `benchmark/exclusion_log.csv`, keyed by its original source id
(`github.com_foxinmy_weixin4j_...`), explicitly marked `post_hoc_audit_2026-10-06` to distinguish it
from the original curation-time exclusion+topup cycle — this is a provenance record, NOT a trigger
for case-ID renumbering or a replacement case (that mechanism was for ongoing curation, not a
post-hoc audit correction on an already-fully-experimented-on dataset). **Measured impact: zero.**
Confirmed directly: `CASE-0166` already carried `semgrep_representability=unsupported` (excluded
from every headline 153-case comparison already) and has 0 hits in every `sample_execution_log`
across all 300 cases × 8 models (searched directly) — every generation attempt for this case failed
before reaching Semgrep execution, so it never contributed a single sample to any pooled MCC/VGR/FPR
number. The only cosmetic change going forward: the full dataset should be described as 299 cases in
any new narrative text, not 300 — no existing reported number needs correction.

**CASE-0084: KEPT, finalized** ("Replacing an incorrectly selected introducing commit with the
verified real fixing commit corrects the dataset's provenance. It does not invent or modify the
upstream fix. This is consistent with CASE-0078."). The "flagged so it can be reversed" note from
curation time is now resolved — no further action needed, no change to any existing number (the
hand-curation was already baked into every result reported so far).

**Independent second-rater review: still pending**, genuinely requires the user's own participation
(or another independent party) — instructions already given separately. Not something this session
can resolve further; the manuscript should state its status honestly (completed with real
percent-agreement/kappa numbers, or disclosed as "prepared but not completed") once the user decides.

**Step 3 is now fully resolved** except for the second-rater item, which depends on action outside
this session. Proceeding to Step 7 (the paper rewrite) next.
