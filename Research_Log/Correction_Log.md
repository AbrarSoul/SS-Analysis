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
- [x] **Step 7 — Rewrite the paper and assemble reproducibility artifacts.** COMPLETE.
      `Paper_Draft_Notes.md` fully rewritten with corrected numbers throughout, every
      multi-agent causal claim hedged as a hypothesis, the new explicit end-to-end
      table (§7.9) added, and all manuscript-wording corrections applied (contamination
      language, "no statistically detectable difference," regression-rate renamed,
      generalization-scope clarification, elapsed-runtime framing). Reproducibility
      materials: baseline preserved at git tag `baseline-pre-audit`; every correction is
      an individually-reviewable commit on top of it; `results_corrected/` sits alongside
      the untouched `results/` originals.

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

### 2026-10-07 — The independent second-rater review: completed, real numbers, one important caveat

The user completed all 45 rows of `benchmark/second_rater/sample_blinded.csv`. Computed percent
agreement and Cohen's kappa against `answer_key_DO_NOT_OPEN_UNTIL_RATED.json` for all 3 fields
(`sklearn.metrics.cohen_kappa_score`), replacing the long-standing "prepared but not completed"
placeholder with real numbers:

| Field | Percent agreement | Cohen's kappa | Interpretation (Landis-Koch bands) |
|---|---:|---:|---|
| `pattern_or_taint` | 88.9% (40/45) | 0.737 | substantial |
| `structural_or_context_heavy` | 80.0% (36/45) | 0.531 | moderate |
| `semgrep_representability` | 64.4% (29/45) | 0.448 | moderate |

**Two honesty caveats, stated directly rather than smoothed over**:

1. **This is not a fully blinded, fully independent check**, by the rater's own disclosure in the
   `YOUR_notes` column: rating was done from the sheet's `mechanism_summary` text alone ("referenced
   diffs unavailable"), not the full diff/source the original single-rater label had access to; and
   5 of 45 cases (`CASE-0042`, `CASE-0056`, `CASE-0063`, `CASE-0078`, `CASE-0166`) had their case ID
   or some detail surface during this very audit conversation before rating. Recomputed excluding
   those 5 as a sensitivity check: `pattern_or_taint` 90.0%/κ=0.773, `structural_or_context_heavy`
   80.0%/κ=0.529, `semgrep_representability` 65.0%/κ=0.448 — essentially unchanged, so the
   contamination risk does not appear to have measurably inflated agreement, but the caveat is
   reported regardless rather than assumed away.
2. **Agreement is weakest on exactly the label this entire study's primary comparison scope depends
   on.** `semgrep_representability` -- the field that defines which 153 of 300 cases count as
   "supported" and therefore enter every headline multi-agent/primary-benchmark comparison in
   `Paper_Draft_Notes.md` -- has the LOWEST agreement of the three fields (64.4%, "moderate" per
   Landis-Koch, not "substantial" or "almost perfect"). Disagreements run in both directions (rater
   sometimes rates MORE supported than the original label, sometimes less) and concentrate heavily
   around the `partially_supported` boundary rather than confusing `supported` with `unsupported`
   outright (checked the disagreement list directly, not assumed) -- consistent with a genuine,
   hard-to-pin-down category boundary rather than a systematic labeling error in one direction.

**This is now a real, quantified limitation for the manuscript** (replacing the old "not yet
completed" placeholder in `Paper_Draft_Notes.md`'s limitations section, Step 7's job): the 153-case
"supported" scope that anchors this entire study's primary comparisons rests on a single-rater label
whose independent-agreement rate, now measured, is moderate rather than high -- stated as a genuine
validity threat to the comparison's scope, not hidden behind an unresolved TODO.

### 2026-10-07 — Step 7 (paper rewrite), in progress: a new discrepancy found while updating §7.3

While rewriting `Paper_Draft_Notes.md` with corrected numbers, re-checked §7.3's stability-experiment
claim ("the stability-run ranking mismatch with §7.1 is fully explained by case composition, not
temperature") against the Finding-1-corrected data on BOTH sides of that comparison. **It no longer
holds.** Before correction, restricting the primary run's own temp-0 results to the same 51-case
stability subset reproduced the temp-0.2 stability ranking almost exactly. After correction, the two
rankings diverge substantially -- `DeepHat-V1-7B` and `codellama:7b-instruct-fp16` in particular swap
from 3rd/6th (temp-0.2 mean) to 6th/1st (temp-0, same subset). Rather than keep the original
explanation now that it's unsupported, or silently drop the paragraph, `Paper_Draft_Notes.md` §7.3 now
states this discrepancy as OPEN/unresolved. Not investigated further in this pass -- flagged as a
genuine follow-up: a fresh look at whether this is a real temperature-sensitivity effect, a different
case-composition interaction with the location-correctness fix, or something else entirely.

### 2026-10-07 — All 7 steps complete: audit closed out

All 7 steps of the protocol are now done. Summary of what changed and what didn't:

**Changed**: the primary-benchmark headline ranking (DeepHat-V1-7B now 1st, was 5th); every
MCC/VGR/PDS/FPR number in the document (Finding 1's correction, ~0.01-0.2 MCC per condition); the
dataset size (299, not 300); the second-rater status (completed, moderate agreement on the
scope-defining label); the benign-lookalike uncertain-negative count (4 confirmed, was "a small
number"); the rule-repair "regression rate" label (renamed, no before/after evidence exists); the
contamination-risk framing (no longer "provably... free"); every multi-agent causal claim (now
explicitly hedged as a hypothesis given 3 newly-documented unmatched C2/C3/C4 variables); and one
new open question surfaced by the correction itself (§7.3's stability-ranking discrepancy).

**Did NOT change**: the single most robust finding in the whole study -- Autogrep's/C2's
feedback-driven repair producing a large, statistically significant MCC gain over one-shot
generation, for every one of the 8 models, both before and after every correction in this audit.
This is the one claim in the entire document that survived completely unscathed, and it is now
stated as such explicitly rather than left for a reader to infer.

**What this audit did NOT do, stated for completeness**: no new models, fine-tuning runs, or
direct-generation comparisons were added (none were requested); no experiment was rerun (every
correction was a reanalysis of already-collected data, consistent with "rerun only what the audit
shows is necessary" -- Finding 1's fix needed no new Semgrep/LLM calls, and no finding in this audit
produced evidence that any stored artifact was lost, corrupted, or needed regenerating); the
independent second-rater review was completed by the user, not by this session, preserving its
validity as an independent check.

**Reproducibility**: the complete, untouched original state of the project is preserved at git tag
`baseline-pre-audit` (commit `e650422`). Every correction described in this log is a separate,
individually-reviewable commit on top of it. `results_corrected/` holds every rescored sample log
alongside the untouched originals under `results/` -- diffing any pair shows exactly what changed
and why. `Paper_Draft_Notes.md` is the corrected manuscript; this file is its full audit trail.

### 2026-10-07 — Second-rater review redone with a clean, zero-overlap sample: a stronger result

The user asked to redo the second-rater review, since the first 45-case round had two disclosed
limitations (rated from summaries only, not full diffs; a handful of cases had some detail exposed
during the audit conversation before rating). Rather than reuse the same 45 cases, built a
completely fresh sample: `pipeline/build_second_rater_sheet_v2.py` draws a new stratified 45-case
sample (20 supported / 15 partial / 10 unsupported) with ZERO overlap with the first sample's case
IDs (verified: 0 shared cases) and excludes the post-hoc-excluded `CASE-0166`. Mechanism summaries
were extracted directly from each case's own Section 9 build-script docstring (real, pre-existing
documentation, not freshly written for this check) rather than hand-curated. Delivered to the user
as a self-contained folder (`~/Desktop/second_rater_redo/`) with the rubric, the blinded sheet, and
the actual `patch.diff` + vulnerable/patched source for all 45 cases, so no path had to reach back
into the project -- the answer key was deliberately NOT included in that folder, to remove any
temptation/risk of accidental exposure (this session's own copy in the repo was used for scoring).

**Result -- every field improved, confirmed by direct comparison, not assumed**:

| Field | Round 1 (summaries only, 5/45 cases exposed) | Round 2 (full evidence, zero exposure) |
|---|---:|---:|
| `pattern_or_taint` | 88.9% / κ=0.737 (substantial) | **91.1% / κ=0.802 (almost perfect)** |
| `structural_or_context_heavy` | 80.0% / κ=0.531 (moderate) | **93.3% / κ=0.860 (almost perfect)** |
| `semgrep_representability` | 64.4% / κ=0.448 (moderate) | **77.8% / κ=0.662 (substantial)** |

**This is the more trustworthy of the two rounds** -- a genuinely blind sample, real diff/source
access, zero conversation exposure -- and it should supersede Round 1 as the manuscript's reported
second-rater result, not be averaged with it or presented as a replication (the two rounds differ
in exactly the methodological respects Round 1's own caveats named, so the improvement is
interpretable, not a mystery). The scope-defining label
(`semgrep_representability`) moves from "moderate" to "substantial" agreement -- still the weakest
of the three fields, and still worth disclosing as the least-certain part of the 153-case
comparison scope, but materially less concerning than Round 1 suggested. Disagreements again
concentrate around the `partially_supported` boundary (10/45, both directions), consistent with a
genuine category-boundary difficulty rather than a systematic labeling error.

Both rounds' raw data are preserved: `benchmark/second_rater/` (round 1, now-rated) and
`benchmark/second_rater_v2/` (round 2, now-rated), neither overwritten.

### 2026-10-07 — Audit round 2: a second, deeper feedback pass (Priorities 1–8)

The user sent a second, more detailed audit-feedback table after reviewing round 1's corrections,
explicitly noting most of it "require[s] reviewing existing data and recalculating results, rather
than generating new rules." The entries below cover Priorities 1–3 and the canonical eligibility
module; Priorities 4–8 continue in later entries as they're completed.

**Priority 1 — manually resolved all 29 low-confidence variant line-range annotations.** An
automated global-alignment resolver (`difflib.SequenceMatcher` full-file bracketing-anchor search)
was tried first and failed on all 29 -- confirming the original LOW-confidence flagging was
correct, not overcautious. Each of the 29 was then resolved by direct inspection: reading the
original vulnerable construct and locating its corresponding text in the variant, following
renames/refactors to their actual definition site rather than the nearest call site. 11 of the 29
involved a refactor that extracted the vulnerable construct into a new helper function; for those,
the resolved range covers the helper's definition (where the security-relevant content sits), not
the now-trivial call site. One case (CASE-0265) caught and corrected a false lead during review: an
anchor search on a literal string match initially pointed at the call site before the actual
extracted-helper definition was found and used instead. Full reasoning for all 29:
`benchmark/variant_lines_manual_adjudication.json`. `benchmark/variant_vulnerable_lines.jsonl`
updated in place (`confidence: "manual"`); `pipeline/rescore_variant_location.py` updated to trust
`confidence in ("high", "manual")`. Rerunning the rescoring pipeline moved the TP→FN flip rate from
879/4072 (21.6%) to 897/4072 (22.0% -- corrected from an earlier arithmetic slip that said 22.1%) -- a small further correction on top of Finding 1's original
fix, now with zero unresolved annotations (571 "high" + 29 "manual" = 600/600).

**Priority 2 — ground-truth exclusion standard, applied to all 10 flagged cases.** Established one
explicit rule (confirmed with the user via two separate approvals): a case is excluded from its
representability population only if the evidence shows the SAME labeled vulnerability's upstream
fix is measurably still exploitable -- not a different, unrelated bug, and not uncertainty about the
vulnerable sample's own exploitability (a different axis). Applying this consistently across all 10
previously-flagged cases: **5 excluded** (CASE-0125, partially_supported — the "disputed advisory"
behaves identically for ordinary inputs, measured directly; CASE-0140, supported — upstream denylist
bypassable via percent-encoding, measured directly against the real mysql-connector-j 8.4.0;
CASE-0156, supported — upstream denylist bypassed via relative-path-scan + glob, measured directly;
CASE-0174, partially_supported — ReDoS fix is mitigated but still quadratic-time, same vulnerability
class remains triggerable; CASE-0194, supported — path check uses `startsWith` without a separator,
same sibling-directory-prefix-bypass class as 0140/0156) and **5 kept** (CASE-0107, CASE-0154,
CASE-0170, CASE-0199, CASE-0211 — each reviewed and found to fail the exclusion criterion for a
specific, documented reason: an unrelated co-existing bug, a different-axis exploitability question,
a sibling-location miss, or already outside every comparative population by representability label).
Full reasoning: `benchmark/ground_truth_exclusions.json`.

**Priority 3 — one canonical, versioned eligible-case module.** `pipeline/eligible_cases.py`
(`VERSION = "2026-10-07.1"`) is now the single source every analysis script imports from, rather
than each script re-deriving its own case population from the raw manifest. It encodes both
corrections in one place: the CASE-0166 post-hoc dataset exclusion (Correction_Log's earlier entry)
and the 3 ground-truth exclusions from supported (above). Verified output: 299 total cases after
CASE-0166's removal (150 supported, 97 partially_supported, 47 unsupported, plus 3
ground-truth-excluded from supported and 2 from partially_supported) -- exactly matching the user's
stated target counts. `eligible_supported_cases()` (150 cases) is now the frozen primary-comparison
population for every downstream script.

**Priority 4 + a new finding (Finding 2) — regenerated the end-to-end metric table, and found a
second, previously-missed data problem while doing it.** `pipeline/build_step4_tables.py` now
imports `eligible_cases.eligible_supported_cases()` (150, not the old 153) and prints each model's
autogrep row directly above its raw-condition counterpart for direct comparison, per the
instruction to put raw rows "beside" autogrep rows.

**Finding 2**: while regenerating this table, found that the primary benchmark's **autogrep
condition** records `validation_error: "repo not available for validation"` for 60–77% of cases, in
every one of the 8 models (verified by direct inspection of `generation_log.jsonl` across all 8
model directories). This is Autogrep's own internal repo-checkout step failing transiently inside
its 3-retry validation loop -- NOT a judgment about the generated rule. Every one of those records'
`attempt_trail` entries still shows `yaml_valid: true` for the candidate that was actually generated;
checking all 8 models' complete logs, there is not one single instance anywhere of a rule that
reached semgrep with the repo available and was then rejected for a wrong discrimination verdict --
every non-accepted autogrep-condition case resolves to either a YAML/schema parse failure (6–23
cases/model) or this repo-unavailable infra failure (90–116 cases/model). This directly contradicts
round 1's §7.9 footnote, which attributed the compile-accept gap to "discrimination failure, not a
syntax/schema problem" -- that attribution is not supported by the data for this condition. The rule
text itself was never persisted for the affected cases (`rule_path` is null, no raw-output directory
exists), so this cannot be fixed by re-running validation alone; it would require new LLM generation
for the affected ~70%. Presented this finding to the user directly (given its scale and effect on an
already-published "headline result") before proceeding; the user chose to keep the autogrep-condition
numbers in the table with an explicit, prominent caveat rather than exclude the condition or attempt
a costly rerun. `build_step4_tables.py`'s `compilation_rate` for the autogrep condition is now
recovered from `attempt_trail` (did ANY retry produce valid YAML) rather than the top-level
`yaml_valid` field, and the table reports the parse-fail/infra-fail breakdown explicitly per model.
Recovered compile rates land at 87–96% for both conditions -- close to a ceiling, consistent across
models -- a dramatically different picture from the pre-finding "compile rate = acceptance coverage"
framing. `Paper_Draft_Notes.md` §7.9 rewritten with the corrected table, the Finding 2 explanation,
and the false discrimination-failure claim removed. Full output:
`results_corrected/step4_tables_report.txt`.

**Priority 6 — statistics rerun on the frozen 150-case population, with repository-awareness
extended to the end-to-end (ESR) comparisons.** `pipeline/analyze_section22_corrected.py` now (a)
uses `eligible_cases.eligible_supported_cases()` instead of its own uncorrected 153-case
`supported_case_ids()`, and (b) runs the SAME repository-level paired bootstrap already used for
MCC on the ESR (end-to-end) metric too -- the exact McNemar test previously used for ESR assumes
discordant pairs are independent, which this project's own stated principle
(`Section22_Scope.md`) says is false for cases sharing a repository. McNemar's b/c counts are kept
printed for descriptive context only; the repo-aware bootstrap p-value is now what Holm correction
and the significance call are based on throughout. Bootstrap p-values that round to 0.0000 at
n_boot=10,000 are now printed as `p < 0.0001` (the test's resolution floor), never as an exact zero.
Full output: `results_corrected/section22_corrected_report_round2.txt`.

**This directly produces the evidence behind the user's explicit final instruction to remove the
"repair produces a large, statistically established quality improvement" claim.** Round 1's log
(above) stated this MCC gain was "the single most robust finding in the whole study... the one claim
in the entire document that survived completely unscathed" -- **that statement is retracted by this
entry.** Re-run on the same eligible population with repo-aware ESR bootstrapping:
**0/8 models show a statistically detectable raw-vs-autogrep end-to-end (ESR) difference after Holm
correction, and 0/8 show a detectable C1-vs-C2 end-to-end difference** (repo-aware bootstrap p
ranging 0.09–1.00 before correction, every one non-significant after). Meanwhile the conditional MCC
comparison for the exact same model pairs shows large, "highly significant" differences (diff
-0.40 to -0.62, p < 0.0001) in every single case. Side by side, this is direct, reproducible evidence
of the selection-effect confound the user flagged: conditional MCC for condition A vs. condition B
each draws only from that condition's OWN accepted cases -- different, self-selected populations --
so a large conditional-MCC gap is consistent with "repair changes which cases become acceptable"
rather than "repair makes the same cases' rules better," and the end-to-end metric (same 150-case
denominator for every condition) shows no detectable difference at all.

**Priority 5 — ground-truth sensitivity analysis, a real before/after table.** Recomputed
acceptance coverage, conditional MCC, end-to-end detection, and end-to-end success for all 8 models'
autogrep condition under both the 153-case (uncorrected) and 150-case (eligible) populations side by
side (`pipeline/build_step4_tables.py`). 7 of 8 models move by ≤1.3 points on every metric --
genuinely negligible, as previously claimed, but the previous claim ("only 1 sample record out of
several thousand affected") understated it: removing 3 cases removes every one of their sample
records, not one classification outcome. **Magicoder-7B is a real, disclosed exception**: its
conditional MCC moves +0.053 (0.374→0.427) because it accepts very few rules overall, so removing 3
cases' worth of samples from a small pooled confusion matrix has a proportionally larger effect. This
doesn't change any model's rank, but is model-specific, not uniformly negligible, and is now stated
as such rather than smoothed into one cross-model number.

**Manuscript propagated to match, section by section**: §1 (study overview), §7.1 (headline ranking,
now on the 150-case population, MCC/ESR recomputed directly, PDS/VGR/FPR carried over from 153 with
that caveat disclosed), §7.2 (repair-gain bullet rewritten with the selection-effect caveat and the
real end-to-end result), §7.4 (C2-vs-autogrep MCC comparison, same treatment), §7.8 (all 7 Section 22
comparisons rewritten with the repo-aware ESR bootstrap results and the retracted "most robust
finding" framing), §7.9 (already covered above), §10 (the sensitivity table above, replacing the
stale "11 cases kept, negligible impact" bullet), and the document's closing "note on what changed"
paragraph (the reader-facing summary of the whole audit history). The paper's conclusion is now the
gap between visible-validation acceptance and end-to-end hidden-test success, not a repair-
superiority claim, per the user's explicit final instruction.

**Still pending as of this entry**: Priority 7's remaining items (the C2/C3/C4 workflow-description
language was already compliant from round 1; Autogrep's compile rate is now recovered rather than
marked unavailable, per Finding 2, which is a stronger fix than the instruction asked for); Priority
8's two decisions (restricted-wrapper scope, multi-agent-causality rerun) and its reproducibility
packaging; and §7.3's stability-ranking discrepancy, still flagged open rather than resolved or
withdrawn.

### 2026-10-07 — "Finding 2" was wrong: the real root cause was already documented by the original study

While starting Priority 8's reproducibility packaging (checking `pipeline/PINNED_CONFIG.md` and
`Research_Log/Implementation_Log.md` for what to include), found Implementation_Log.md Section 12.30
("A real bug found auditing inputs before Phase 7 analysis: `reconstruct_attempt_trail()` never
updated for the clone-free refactor") — written by the original study team BEFORE any audit, and
missed when "Finding 2" was written up in this log's previous entry. **It already fully explains and
root-causes the exact same `"repo not available for validation"` pattern "Finding 2" claimed to
newly discover, and the real explanation is different from what was claimed.**

**What "Finding 2" got wrong**: it claimed this was a real, previously-undiscovered validator
infrastructure failure (a transient repo-checkout race condition), and that the candidate's true
compile rate was "recoverable" from `attempt_trail`'s per-attempt `yaml_valid` field (87-96% across
all 8 models) — attributing most of the autogrep condition's compile-accept gap to this infra issue
rather than to discrimination failure.

**What Implementation_Log.md Section 12.30 actually documents**: `reconstruct_attempt_trail()` is a
diagnostic-only re-evaluation function, independent of Autogrep's own real retry loop, that gates on
`repo_path.exists()`. Section 12.24's earlier clone-free refactor made curated cases (100% of the
primary benchmark) validate directly against each case's own stored `vulnerable_source`/
`patched_source` files, with `prepare_repo()` returning a synthetic, intentionally-non-existent
marker path — so `repo_path.exists()` is `False` BY DESIGN for every curated case, and always was,
from the moment that refactor landed. `reconstruct_attempt_trail()` was never updated to know this,
so it discards the REAL per-attempt outcome for every curated case and substitutes a generic "can't
validate" placeholder, labeled `"repo not available for validation"`. **Verified directly in that
entry: all 1,746 affected top-level records have `semgrep_valid == False` — a real rejection, never
a wrong pass.** The bug corrupts the FAILURE-REASON TEXT (and the whole `attempt_trail` diagnostic
list, confirmed "unreliable for curated cases" there), not the actual pass/fail determination.

**What this means for Round 2's own work**: `pipeline/build_step4_tables.py`'s `n_accepted` and
every other table/statistic built on the top-level `yaml_valid`/`semgrep_valid` fields (Priority 4's
tables, Priority 5's sensitivity table, Priority 6's statistics, the 0/8-significant end-to-end
result) are **unaffected and remain correct** — they were never built on `attempt_trail`. Only the
"recovered compile rate" column and its infra-failure narrative, both newly added in the "Finding 2"
entry, are wrong and are retracted. Corrected: `compilation_rate` for the autogrep condition is now
reported as unavailable/identical to acceptance coverage (matching Priority 7's actual instruction
and the pre-round-2 manuscript's original framing, now for a precisely-documented reason rather than
an invented one); `Paper_Draft_Notes.md` §7.9 updated to remove the infra-failure causal story and
cite `Implementation_Log.md` Section 12.30 directly instead.

**A process note, stated plainly**: this should have been caught before presenting "Finding 2" to
the user and writing it into the manuscript — `Implementation_Log.md` is the project's own record of
exactly this kind of implementation-level bug-and-fix, and checking it first would have surfaced
Section 12.30 immediately instead of independently (and incorrectly) re-diagnosing the same
symptom. Recorded here so the lesson is explicit: check the existing implementation/correction logs
for a documented explanation before treating a surprising data pattern as a new discovery.

### 2026-10-07 — Priority 8 complete: §7.3 resolved, two scope decisions written in, reproducibility package assembled

**§7.3's stability-ranking discrepancy**, open since round 1, investigated directly rather than left
as a blanket mystery. Three possible artifacts ruled out first: (1) the table-generating script itself
was found to still read from uncorrected `results/` in every path despite being labeled "corrected
data" — fixed (`pipeline/analyze_phase5_stability.py` now reads `results_corrected/`), and rerunning
reproduces the existing table almost exactly (confirming this wasn't the cause); (2) averaging 5
per-repeat MCCs vs. pooling all 5 repeats' samples into one confusion matrix gives essentially the
same ranking, ruling out a mean-of-ratios artifact; (3) `environment.json` diffed identical between
primary and stability runs for the most-swapped models, apart from temperature, ruling out a
config/model-version confound. With those ruled out: 6 of 8 models' single temp-0 MCC value falls
inside that model's own 5-repeat temp-0.2 range -- ordinary single-draw sampling noise among
closely-clustered MCCs (roughly 0.45-0.57) at a 51-case subset size, not a mystery. 2 of 8
(`qwen2.5-coder:32b`, `codellama:7b-instruct-fp16`) remain a genuine, same-direction exception (temp-0
scores above their ENTIRE 5-repeat range) -- carried forward as an explicit, untested hypothesis
(determinism specifically benefiting these two, one already precision-confounded), not claimed as
resolved.

**Two scope decisions**, written explicitly into `Paper_Draft_Notes.md` §10 rather than left implicit:
(a) given the wrapper-level composite-pattern restriction (§10's existing bullet), this document's
conclusions are now explicitly scoped to the tested Autogrep implementation, not to "LLM-to-Semgrep
rule generation" as a general claim; (b) a controlled rerun isolating role separation from the other
3 C2/C3/C4 confounds is stated as unnecessary under this document's actual claims (no causal
role-separation claim is made anywhere, and §7.8 finds no significant pairwise difference in most of
these comparisons regardless of cause) -- needed only if a future paper wants to make that causal
claim.

**Reproducibility package assembled**: `Research_Log/Reproducibility_Package.md`, a single index (not
a duplication) of the dataset/eligibility artifacts, the scoring-script run order, what's retained in
`results/`/`results_corrected/`, the configuration/pinning docs, and -- per Priority 8's explicit
instruction -- a stated list of missing artifacts: no generated rule YAML text survives for the
primary benchmark, stability experiment, or C2/C3/C4 (only the 40-case pilot retains it); no per-case
token/latency for the primary benchmark or C3/C4; the specific parse-vs-discrimination reason for
most autogrep-condition rejections (per the Finding-2 retraction above); the pilot's un-recomputed
numbers; and the two not-yet-run investigations (case-level flip analysis for §7.3's 2-model residual,
a controlled C2/C3/C4 rerun) tied to their respective open items above.

**This completes Priority 8 and the second audit round's explicit checklist.** Remaining open items,
carried forward rather than resolved (stated plainly, not hidden): §7.3's 2-model residual; the pilot
screening recomputation; a controlled multi-agent-causality rerun and a corrected-wrapper rerun, both
explicitly scoped as unnecessary for this document's current (non-causal, implementation-scoped)
claims but required for any future, broader claim.

### 2026-10-07 — External reviewer feedback round 3: a real pooling bug, not just a selection-effect caveat, found and fixed

The user relayed detailed external reviewer feedback on the published GitHub repository (7 numbered
items). The single highest-priority item -- an exact MCC contradiction between
`step4_tables_report.txt` (raw `qwen2.5-coder:7b-instruct` MCC = 0.626) and
`section22_corrected_report_round2.txt` (same model/condition/population, MCC = 0.101) -- led to
finding a real bug, not a selection-effect subtlety as previously assumed.

**Root cause**: `analyze_section22_corrected.py`'s three data loaders (`load_primary_corrected`,
`load_c2_corrected`, `load_multiagent_corrected`) stored `case_samples = smp_by_case.get(cid, [])`
unconditionally -- every case's sample records, regardless of whether that case's rule was actually
accepted -- then `pooled_mcc_fn` read this `"samples"` field directly with no re-check. Verified
directly: the RAW condition (unlike autogrep) records a real, scored `sample_execution_log` entry
whenever a rule's YAML parses, REGARDLESS of whether it goes on to pass `semgrep_valid` -- 215 of 269
one model's raw sample-bearing cases were NOT accepted, confirming this wasn't a one-off. The same
unconditional-pooling pattern was independently present in `analyze_phase5_primary.py`'s
`analyze_model()` (which `build_step4_tables.py`'s own `primary_table_row` was NOT affected by -- it
already correctly gated -- but this project's original, very first analysis script, used for every
pre-audit "headline ranking" claim, was never gated either, meaning the raw condition's pooled
MCC/VGR/FPR has been subject to this bug since before either audit round began).

**Fix**: added one shared helper, `gated_samples(cid, is_accepted, smp_by_case)`, to
`analyze_phase5_primary.py`, and rewired all three previously-independent call sites
(`analyze_phase5_primary.analyze_model`, `build_step4_tables.py`'s two table-row functions,
`analyze_section22_corrected.py`'s three loaders) to use it, so this exact class of bug cannot recur
silently across scripts again. Reran every affected script; `step4_tables_report.txt` and
`section22_corrected_report_round2.txt` now agree exactly (raw qwen2.5-coder:7b-instruct MCC = 0.626
in both).

**The corrected finding reverses this document's entire conditional-MCC narrative about repair,
not just adds a caveat to it.** With the bug fixed, raw's conditional MCC is numerically HIGHER than
autogrep's (and C2's) for 7 of 8 models, and the difference is statistically significant after Holm
correction for 2 of 8 models (repo-aware bootstrap) -- the opposite direction from every previous
version of this claim, including the "selection-confounded but real large gain for autogrep" framing
written earlier this same day. Combined with the already-established, unaffected end-to-end result
(0/8 models significant, any comparison), there is no remaining basis anywhere in this document for a
repair-superiority claim in either direction on either metric. `Paper_Draft_Notes.md` rewritten
throughout (§7.1, §7.2, §7.4, §7.8, §7.9's closing paragraph, §9, the document's closing note) to
reflect this.

**Also addressed from the same feedback, in the same pass**:
- **PDS/VGR/FPR recomputed for real** on the 150-case population for all 8 models × 2 conditions
  (§7.1's headline table), replacing the previous "carried over from 153, reasonable approximation"
  disclosure -- now computed directly via the same shared, gated helper.
- **§7.9's compilation-rate table was stale**, not wrong in a new way: the raw-condition compile
  rates shown (94.7%/94.0%/65.3% for DeepHat/Qwen32B/CodeLlama) predated a same-day fix (restoring
  `is_semgrep_parse_error()`) that was never re-synced into the manuscript table. Corrected to the
  verified current report values (83.3%/80.0%/70.0%).
- **Friedman omnibus tests (comparisons 3 and 7) are not repository-aware** -- `scipy.friedmanchisquare`
  assumes independent rows, false here. Rather than build an unverified repo-aware omnibus variant
  under time pressure, reported these omnibus p-values as descriptive/exploratory only; only their
  repo-aware bootstrap pairwise follow-ups carry a confirmatory significance claim. The bootstrap
  procedure itself (resampling unit, n_boot=10,000, fixed seed 42, two-sided p-value construction,
  Holm-Bonferroni as the declared multiple-testing family) is now documented precisely in §7.8, and
  degenerate (zero-sample) resamples were checked by direct simulation for this study's two
  lowest-coverage conditions (0/10,000 for both) rather than asserted away.
- **Ground-truth sensitivity analysis (Priority 5) extended to raw, C2, C3, and C4** -- previously
  autogrep-only. Same negligible pattern holds throughout (Magicoder-7B under C2 is the one other
  real exception, +0.039 MCC, same small-denominator mechanism as its autogrep exception).
- **Dataset composition table corrected to total 299**, with the 5 ground-truth exclusions shown as
  a separate annotation column rather than folded into (or confused with) the representability
  labels themselves.
- **A real arithmetic slip fixed**: 897/4072 rounds to 22.0%, not 22.1% as stated when Priority 1 was
  first logged (also not the stale pre-Priority-1 21.6% that had re-appeared in three places in
  `Paper_Draft_Notes.md`) -- all four locations corrected to 22.0%.
- **§7.4's "budget-matched baseline" language removed** -- C2's explicit budget is not enforced
  equivalently against autogrep's unmatched retry loop, so this was a real residual overclaim, not a
  caveat gap.
- **§9's causal claim retracted**: the raw condition's 57.2% semantic-failure rate was cited as "the
  strongest evidence... for why Autogrep's retry/feedback loop produces large, highly significant MCC
  gains" -- with no such gain left standing to explain, this specific causal sentence is retracted;
  the 57.2% figure itself is retained as a real, valid measurement of raw's own failure composition.
- **Reproducibility_Package.md**: added an explicit "recomputing from stored records (possible) vs.
  re-executing the historical generated rules (impossible)" section, and disclosed that
  positive-sample (vulnerable-sample) validity evidence exists but is distributed across 300
  individual per-case build scripts, not consolidated into one index file -- real evidence, not
  fabricated completeness, but real remaining work to consolidate it.

**A process note, stated plainly, again**: this is the second time in one day a causal/quantitative
claim in this document was found to rest on a coding bug rather than a genuine methodological
subtlety, and the second time an external check (first `Implementation_Log.md`, now a reviewer)
caught something this session's own re-analysis had not. The lesson from the first entry is repeated
and extended: cross-check every reported number against an independent recomputation path BEFORE
writing a causal explanation for it, not just BEFORE publishing the explanation.

### 2026-10-07 — External reviewer feedback round 4: subgroup analysis never filtered through eligible_cases.py, plus four smaller consistency fixes

**1. Subgroup analysis (§22.4) was never filtered through `eligible_cases.py`.** Caught concretely by
the reviewer: the subgroup table's "supported" bucket MCC (0.536) didn't match the primary table's
0.539 for the identical model/condition. Root cause: `analyze_section22_subgroups_corrected.py` used
`load_full_manifest()` directly, with no exclusion logic at all -- CASE-0166 and the 5 ground-truth
exclusions were still being pooled into every bucket, not just the representability one. Fixed by
filtering `all_cases` through `eligible_cases.py`'s exclusions globally (not only for the
representability bucket -- a case with untrustworthy ground truth shouldn't inform ANY subgroup
breakdown). Rerun: supported-bucket MCC now reads 0.539, matching exactly.

**Also checked, per the reviewer's explicit question: does the stability subset's "51 supported
cases" remain fully eligible?** No -- 2 of the 51 (`CASE-0140`, `CASE-0194`) are ground-truth-excluded.
`pipeline/analyze_phase5_stability.py` now filters through the same exclusions, giving **n=49**.
Pooled MCC mean/min/max (§7.3's table) are unchanged to 3 decimals (those 2 cases contributed zero
accepted autogrep samples in any of the 5 repeats, for any model), but per-case agreement figures
shift slightly, and -- more importantly -- the "same-subset temperature-0" comparison built around
this subset changes substantially: `magicoder:7b`'s temp-0 MCC moves from 0.422 (rank last) to 0.566
(rank first) at n=49 vs n=51, and `codellama` moves from 0.566 to 0.547. By coincidence of where the
new values land, the §7.3 conclusion is unchanged -- the same 6 of 8 models still fall inside their
own 5-repeat temp-0.2 range, and the same 2 (`qwen2.5-coder:32b`, `codellama`) remain the unexplained
exception -- but this was verified fresh at n=49, not assumed to carry over from n=51.

**2. Autogrep's compile column no longer duplicates the acceptance-coverage number.** The reviewer
correctly flagged that showing the same percentage in both columns (e.g. "compile=36.0%,
accept=36.0%") reads as a real, independently-recovered compile rate that happens to equal
acceptance -- it does not, it is not recovered at all. `build_step4_tables.py` now returns `None`
for autogrep's `compilation_rate` and prints the literal string `"N/A: not recoverable"`, never a
number, in both the script's own report and the manuscript table.

**3. Statistical documentation, three sub-fixes:**
- The Friedman omnibus print statements (`analyze_section22_corrected.py`, Comparisons 3 and 7) now
  print the same exploratory-only qualification the manuscript already stated, so the report and the
  manuscript say the same thing instead of the report looking more confident than the prose.
- Retracted an incorrect claim that "MCC/ESR differences are continuous-valued, not ranks" needing
  no tie-handling -- ESR is a pooled rate over binary per-case outcomes and visibly produces exact
  ties in this document's own output (`diff=+0.000` appears repeatedly). The tail-proportion p-value
  construction handles ties correctly without any special-casing, so no result changes -- the error
  was in the written justification, not the math.
- The degenerate-resample check previously covered only 2 conditions and wrongly implied the question
  was closed. Redone across all 28 conditions actually used in comparisons 4-7: 27 show zero
  degenerate resamples out of 10,000; **`magicoder:7b` (raw) -- the actual lowest-coverage condition
  in the study at 6/150 accepted cases, which the earlier check never looked at -- shows 27/10,000
  (0.27%)**. Checked this doesn't produce a false positive: a degenerate resample returns MCC=0.0, an
  extreme value relative to the observed 0.520, which widens that comparison's CI conservatively; the
  magicoder raw-vs-autogrep comparison is in fact not significant.

**4. Three remaining overbroad/contradictory summary statements corrected:**
- "0 of 8... across every one of the 7 predefined comparisons" was genuinely overbroad -- only
  comparisons 4 and 5 are structured as 8 independent per-model tests; 1/2/6 are single pairs, 3/7
  are omnibus-plus-follow-up families. Scoped the claim to comparisons 4-5 specifically.
- "Every metric reported in §7.1-7.8 is conditional" was wrong -- §7.8 includes the end-to-end ESR
  comparisons, which are explicitly NOT conditional (that's the whole point of computing them).
  Corrected to describe §7.8 as a mix, with each comparison already stating which of its own two
  reported metrics is which.
- "This completes Section 22 in full" was asserted before the subgroup analysis had actually been
  verified against final eligibility rules (fix #1 above) -- true contradiction, now resolved by
  actually completing the rerun it claimed was already done, not by softening the sentence.

**Verified before closing this entry**: a fresh `git clone` of the published GitHub repository
(https://github.com/AbrarSoul/SS-Analysis) confirms 1,212 `.py` files, 304 `.json` files, 3 `.jsonl`
files, 3,060 files total, including the full `pipeline/` scoring/analysis code and `benchmark/cases/`
source data -- directly contradicting the reviewer's "zero Python scripts, zero JSONL files, zero
JSON files" observation about "this ZIP." The two are inconsistent; flagged to the user rather than
silently re-doing already-complete work, since the most likely explanation is that a different
artifact (plausibly the `~/Desktop/SSRP/` folder, which genuinely IS reports/docs only) was reviewed
instead of the GitHub repository.

### 2026-10-07 — External reviewer feedback round 5: manuscript synced to the corrected subgroup report, execution logs published

**Manuscript sync**: §7.8's subgroup table was still the stale pre-fix version, with an explicit
"not independently rerun" disclosure that was no longer true after round 4's fix. Replaced with the
regenerated numbers (84 evaluable, supported MCC 0.539, partially-supported 0.564, 165 distinct CWEs,
CWE-22 0.845) and removed the stale disclosure. Also fixed, in the same pass: the paragraph before
§7.9's table ("reported as identical to acceptance coverage" → actually shows "N/A: not recoverable");
§7.8's opening paragraph (still cited the round-1 153-case report as current); and §7.3's stability
discussion ("not explained by ordinary sampling noise" for the 2 exception models overstated what 5
repeats can establish — softened to "unknown cause, not ruled out as sampling variability either").

**Execution logs published**: the reviewer confirmed the GitHub repo genuinely has the pipeline code
and benchmark data (resolving the round-4 "zero scripts" discrepancy — that observation was about a
different artifact, as suspected) but still needs `results/`/`results_corrected/` to actually run the
scripts. This reverses the user's original "no log files" instruction for the public repo, so this
was confirmed with the user directly before acting: **a separate GitHub Release asset, not the main
git repository**, per the user's explicit choice. Built from only the run directories any script
actually reads (`runs_phase5_primary`, `runs_phase5_stability_rep1-5`, `runs_c2_primary`, `runs_c3`,
`runs_c4`, `runs_pilot_screening`, `runs_pilot_rerun_fixed`) — excluding a 907MB leftover repo-clone
cache from an early, unreported smoke-test run (`runs_final_realsmoke_20260928_212325`, debris from
before the validator went clone-free, Section 12.24) that would otherwise have dominated the archive
size for zero benefit. The same CASE-0122 API key already redacted in `benchmark/cases/` was found
embedded, as case context, in 4 C3/C4 episode log files, and redacted identically before packaging; a
full secret scan (AWS/Google/GitHub/Slack key patterns, private-key headers) found nothing else.
Published to `https://github.com/AbrarSoul/SS-Analysis/releases/tag/reproducibility-data-v1` (3.1MB
compressed, SHA-256 `c0e1abdb20709c8f7687322e87628fc2c6fbed090aeb8117ea578ea69fe95dc3`) with the
checksum and usage instructions documented in `Reproducibility_Package.md` and the repo's `README.md`.
**Verified before publishing, and again independently by the reviewer afterward**: a completely fresh
`git clone` + release download + `python pipeline/build_step4_tables.py` reproduces the published
report byte-for-byte.

### 2026-10-07 — External reviewer feedback round 6: three final wording corrections, no new findings

All three were editing-only fixes, confirmed by the reviewer as not requiring new experiments:

1. **§7.8's subgroup-interpretation paragraph** still cited stale CIs (pre-round-4 values) and
   claimed CWE-level estimates were "identical to the uncorrected run" — no longer true (CWE-22 moved
   0.707→0.845). Replaced with current CI values; the patch-size trend is now described as descriptive
   only, with an explicit note that overlapping CIs don't establish a between-group difference either
   way (the earlier "at least suggestive since CIs only narrowly overlap" framing overstated this).
2. **§7.9 contained a logically flawed claim**: that compile rate and acceptance coverage "would be
   identical if compile rate COULD be recovered." This doesn't follow — a rule can compile (valid
   YAML) and still fail validation (wrong discrimination) in general; the two are only
   indistinguishable in this specific condition's retained records, because Autogrep's retry loop
   discards every intermediate attempt. Replaced with the reviewer's exact wording: "Attempted-
   candidate compilation rate cannot be recovered from the retained records. Acceptance coverage is
   reported separately."
3. **§7.3 still described the 6 non-exception models' ranking changes as "resolved as ordinary ...
   sampling variation"** — falling inside a 5-repeat empirical range is consistent with sampling
   variability, but does not itself establish that as the cause (no test was run to confirm that
   mechanism over any other explanation consistent with the same data). Softened throughout (the
   per-model bullet, the inline table note, and the "Net status" summary) to "consistent with sampling
   variability, does not establish the cause of ranking changes" — the reviewer's suggested wording.

### 2026-10-10 — C3/C4: two distinct rule-text handoff bugs, found during unrelated diagnostic development

Found incidentally while building an unrelated offline diagnostic (full record:
`Research_Log/Diagnostic_20261010/README.md`), not part of the 2026-10-06 audit protocol, but logged
here per this project's standing rule that nothing gets corrected silently. The single diff to
`pipeline/run_c3.py`/`pipeline/run_c4.py` (both multi-agent orchestrators) bundles two independent
fixes, kept distinct below because they trigger under different conditions and have different
observed footprints.

Two case populations are reported throughout, kept distinct rather than conflated: **612** is every
episode actually run (153 "supported"-representability cases × 4 variants: C3-E, C3-S, C4-A, C4-B);
**600** is the same run filtered down to `pipeline/eligible_cases.py`'s 150-case frozen eligible
population (3 ground-truth exclusions per variant × 4 variants = 12 fewer), i.e. the population every
other reported metric in this project is actually computed over.

**Bug A — round-N syntax reviewer shown stale round-0 text instead of the latest failed candidate.**
If the rule in hand failed to parse, the syntax reviewer was supposed to see the most recent raw
candidate text. Instead it was shown `content` — a variable that, despite its name suggesting
"current," was never reassigned after the very first rule-generation call and so always held round
0's *original* raw output. This only produces a visible difference when round 0 reaches its repair
step (semantic review rejected the rule) **and** that repair's output also fails to parse — in that
sequence, round 1's reviewer diagnosed round 0's first attempt instead of the actual just-failed
repair. Fixed by tracking the latest raw candidate in its own variable (`current_raw_content`),
updated at every point a new candidate is produced.

Quantified directly from the historical episode logs (`rule_repair.proposed_rule_parsed == False` is
exactly the trigger condition, already recorded on every episode):

- Unfiltered: 612 total, 547 reached the repair step at all (the only episodes where this *could*
  trigger), **20 actually did** (C3-E: 4, C3-S: 5, C4-A: 7, C4-B: 4).
- Eligible-filtered (150-case population): 600 total, **19 affected**.
- **All affected episodes were rejected** (`stop_reason="rejected_round1"`) in both populations —
  0 of 20 (unfiltered) / 0 of 19 (eligible-filtered) were ultimately accepted.

**Bug B — semantic review and repair shown the pre-syntax-fix candidate instead of the syntax
reviewer's actual replacement rule.** Separate from Bug A and with a much broader trigger condition.
Whenever round 0's syntax reviewer proposed any `corrected_text` that successfully reparsed, the code
already swapped `rule` to that new candidate and validated *it* with Semgrep — but `rule_text_for_review`
(the text shown to the semantic reviewer and, later, the repair agent in that same round) was never
updated to match. So the semantic reviewer was simultaneously told "here is the rule" (the stale,
pre-correction text) and given detection results (`vuln_detected`/`patched_detected`) computed against
a *different*, already-swapped rule object — and if it then rejected the rule, the repair agent was
asked to fix the stale text too, not the one Semgrep had actually just evaluated. Fixed by updating
`rule_text_for_review = _dump_rule(rule)` in the same place `rule` itself gets swapped.

Quantified by offline-reparsing each episode's stored `syntax_review_round0.proposed_fix` text through
the actual sanitize/parse function (no model calls needed — this only replays already-retained raw
text through the same deterministic parser) to determine whether the bug's trigger condition held:

- Eligible-filtered (150-case population): 600 total, **541 episodes hit the trigger condition**
  (syntax review proposed a fix that reparsed successfully) — far broader than Bug A, since this
  branch runs every round-0 episode where the reviewer offers any textual change at all, not only on
  a parse failure.
- **Of those 541, 42 were ultimately accepted** — i.e. part of the already-published C3/C4 accepted
  pool.
- This count is an upper bound on how often the inconsistency was *present*, not a measurement of how
  often it *mattered*: the local result tree does not retain the raw per-call captures (`raw/`,
  `raw_retries/` were excluded from the VM sync, consistent with every other pull in this project), so
  whether the syntax reviewer's replacement text differed *substantively* from the stale text shown —
  versus a cosmetic reformatting with identical semantic content — cannot be reconstructed from the
  retained episode logs alone.

**Overlap, not independent counts**: 13 of the 19 Bug-A-affected eligible episodes also triggered Bug
B in the same episode. Bug A and Bug B counts must not be summed — the eligible-filtered union of
episodes triggering at least one buggy branch is **547** (19 + 541 − 13), not 560. As above, triggering
a branch is not itself proof of a substantive text difference or a changed outcome.

**Net effect on already-published C3/C4 numbers: not established, in either direction — and that is
the correct way to state it.** Historical rejection does not establish that a corrected reviewer would
also have rejected; round 1's validation being deterministic only means that *specific* downstream
Semgrep check was unaffected by which text the reviewer saw, not that the reviewer's own verdict (and
anything it sets in motion — a different repair prompt, a different accept/reject call in round 0)
would have been identical with correct text. Accurate framing: **all 19–20 episodes affected by Bug A,
and all but 42 of the 541 affected by Bug B, were rejected under the historical (buggy) process;
whether the fix changes any of these outcomes is unknown pending an actual rerun. Published
`runs_c3`/`runs_c4` results remain unchanged** — this entry documents two confirmed mechanisms and
their measured historical footprint, not a correction to any reported number.

### 2026-10-11 — Two dataset/evaluation-mechanics bugs confirmed, both measured as zero-impact on existing results

Both found during the same unrelated diagnostic development (`Research_Log/Diagnostic_20261010/`).
Both are real, independently verified against actual source/data, and both are additive/versioned
fixes that never touched the frozen originals. Both were then checked against every historical run
that could possibly be affected, and both turned out to change **zero** existing numbers — logged
here for completeness and because future runs should use the versioned fixes, not because any
reported result changes.

**1. Four cases where a restructured variant moved the real vulnerable construct into a new helper
function/declaration, outside the originally-annotated line range** (`CASE-0163`, `CASE-0173`,
`CASE-0239`, `CASE-0235`, all `variant_vulnerable_2`). Each was independently re-verified against the
actual source file (exact line numbers confirmed, e.g. `CASE-0163`'s real construct moved into a new
`cloneArgs()` helper at line 50, while the original annotation (26–37) only covers the caller). Fixed
additively: `benchmark/variant_vulnerable_lines_v2_additions.jsonl` supplies a second, disjoint valid
range per case, read by the new `pipeline/rescore_variant_location_v2.py` (reads from
`results_corrected/`, Finding 1's already-corrected tree, writes to a new `results_corrected_v2/`,
touching neither). Run project-wide across all 69 historical result files (8-model primary benchmark,
5 stability reps, C2, C4, the 7-model follow-up, both OpenAI runs): **0 flips.** Across every model
ever evaluated, none ever actually produced a finding inside these 4 newly-identified correct
locations — every one of them failed to generalize to the restructured variant entirely, so the gap
is real but was never actually hit by anything that's already been reported.

**2. `CASE-0298`'s upstream file is `.tsx` (JSX) but the frozen bundle stores `.ts`**, causing a
Semgrep target-file syntax error on every scan — confirmed the dataset's only such case (checked all
300 cases' `metadata.json` against their actual stored sample-file extensions). A single-sample probe
(`results/diagnostic_20261010/failure_audit_v1/case0298_tsx_probe/`) had already shown one
assistant-authored rule scans cleanly against byte-identical `.tsx` copies. Extended this to every
model that actually touched the case: reconstructed each of the 16 headline models' (8 primary + 7
follow-up + gpt-4o) real first-attempt raw LLM response (pulled from retained VM raw-capture files,
re-parsed offline through the same sanitize/parse function — no new inference) and scanned each
resulting rule against `.tsx`-staged copies (`pipeline/replay_case0298_tsx.py`).

Result: of 16, 2 never produced a parseable rule at all (unrelated to this bug — `magicoder:7b`,
`gpt-oss:20b`, consistent with their already-known baseline). **A second, previously undiscovered
issue** affects 6 more: their rule's own *pattern* (not just the target file) contains JSX-like syntax
Semgrep's TypeScript pattern parser rejects outright (`qwen2.5-coder:7b-instruct`,
`codellama:7b-instruct-fp16`, `yi-coder:9b`, `DeepHat-V1-7B`, `opencoder:8b-instruct-q4_K_M`,
`llama3.1:8b-instruct-q4_K_M`) — the `.tsx` target-staging fix alone doesn't help these either. The
remaining 8 (`qwen2.5-coder:32b`, `deepseek-coder:6.7b`, `codegemma:7b`, `qwen3-coder:30b`,
`granite-code:8b-instruct-128k-q4_1`, `Mistral-Small-24B-Instruct-2501`, `phi4:14b-q4_K_M`, `gpt-4o`)
scanned cleanly once staged as `.tsx` — and **every one of them shows `original_vulnerable: FN`**:
none actually matched the real vulnerable construct, two (`qwen2.5-coder:32b`, `qwen3-coder:30b`)
additionally false-positive on the patched/safe samples.

**Net effect: zero.** The `.tsx` bug is confirmed real, but it was never the only thing standing
between any of these 16 models and a correct `CASE-0298` rule — fixing it doesn't flip the case to a
success for a single model; it only changes which error message explains the (unchanged) failure, and
for 6 models surfaces a second, independent bug that would need fixing too. `benchmark/cases/CASE-0298/`
and every existing result remain untouched.

**Reproducibility**: `results/diagnostic_20261010/case0298_tsx_replay_v1/` (`pipeline/replay_case0298_tsx.py`)
persists everything needed to check or redo this without trusting this log entry's word for it: each
model's raw LLM response text and its sha256, the parsed rule YAML, Semgrep's raw stdout/stderr, the
verified pinned Semgrep version (`1.177.0`), and sha256 proof that the `.tsx`-staged samples are
byte-identical to the frozen `.ts` originals (`manifest.json`'s `tsx_staging_hashes`). No new model
calls were made to produce any of it — every rule is a direct re-parse of an already-retained response.

### 2026-10-11 — Revised-prompt diagnostic trial (`diagnostic_mechanism_v1`): a real implementation bug, fixed, then a clean negative result

A new, explicitly-separate prompt condition (`autogrep/llm_client.py`'s
`_build_prompt_diagnostic_mechanism_v1`, selected only via `--prompt-variant`, never a silent edit to
`autogrep_default`) was built to test whether explicitly permitting composite/taint Semgrep forms
plus "reason about the vulnerability mechanism, not literal code shape" guidance improves end-to-end
success on the same 24-case development subset used throughout this diagnostic campaign. Two live
runs, `qwen3_mechanism_v1` then `qwen3_mechanism_v2`, both `qwen3-coder:30b`, same budget (temp 0,
3 attempts, 2048 tokens) as `qwen3_v3`.

**`qwen3_mechanism_v1` was confounded by a real bug, not just a negative result.** Its own docstring
claimed to reuse the baseline's per-language worked examples; the implementation never actually
referenced them. Confirmed directly against the run's own captured raw request text (no `pickle.loads`
reference, no examples section at all). Complete success fell to 4/24 (from baseline's 6/24),
accepted dropped from 19/24 to 11/24 — but this run cannot isolate "mechanism guidance" from
"lost examples," so it is preserved as-is (`Qwen3_Mechanism_v1_Review.md`) rather than reinterpreted.

**Fixed** (`autogrep/llm_client.py`): `EXAMPLE_RULES` extracted to module level and actually wired
into the new prompt function; added explicit guidance on `patterns:`'s real semantics (same-node
conditions, not "these statements occur near each other"), targeting a concrete failure found in v1
(below). Verified the historical `autogrep_default` prompt's output is **byte-identical**
before/after every edit (SHA-256 `161d0f8329be00faf7e17191345fb14f3e52081ff0f5a4cda40492d3bad9aea1`,
checked via `git stash`) — zero risk to anything already run under that condition. All 18 regression
tests still pass.

**`qwen3_mechanism_v2`** (examples restored): complete success 5/24 (as-reported, and confirmed
identical — **5/24** — under the full `.tsx` + merged-location-range + location-aware-acceptance
evaluator from the 2026-10-10 entry above, via `pipeline/rescore_qwen3_v3_corrected.py
qwen3_mechanism_v2`). Composition vs. baseline: lost `CASE-0323` and `CASE-0276`, gained `CASE-0063`
(net −1). Hidden-positive hits recovered substantially from v1 (16/48 → 21/48) but still below
baseline's 30/48.

**Root cause, traced for all four regressions across both runs (not just asserted) — one shared
mechanism**: every lost case was previously solved by a simple, concrete pattern that already worked;
in each case, the "reason about the mechanism, generalize past literal shape" framing led the model to
invent abstract-looking structure that doesn't match the real code:
- `CASE-0134` (v1): assumed a `re.compile(...)` wrapper the real code never uses (`re.match(r'...'
  r'...', url, re.I)` directly).
- `CASE-0220` (v1): misused `patterns:` to AND two unrelated sequential statements (verified:
  `patterns:` requires all conditions on the same matched node, not "both appear nearby").
- `CASE-0276` (v2): used top-level `pattern-either` with a sibling top-level `pattern-not`, expecting
  it to filter one alternative. **Verified with a minimal isolated test** (stripped to just these two
  fields): it does not — the rule matched both the vulnerable and the patched sample. `pattern-not`
  must be inside a `patterns:` list alongside `pattern-either` to actually compose as an exclusion —
  a second, distinct, confirmed Semgrep composition gotcha.
- `CASE-0323` (v2): invented a `$CONFIG['...']: {...}` bracket-access form; the real code is a plain
  object-literal property with a quoted string key, no bracket access anywhere.

**Verdict**: this specific prompt formulation is a net negative on this subset (5–6/24 vs. baseline's
6/24, after fixing the implementation bug) and should not be scaled to other models as-is. The
underlying idea isn't refuted — zero of the 18 historically-failing cases flipped to success either
way, so there's no evidence this framing helps the hard cases it targets, and clear evidence it hurts
easy, already-solved cases via unwarranted structural invention, including two confirmed Semgrep
composition gotchas (`patterns:` semantics; `pattern-not` + `pattern-either` composition) the prompt
didn't anticipate. Full analysis: `Research_Log/Diagnostic_20261010/Qwen3_Mechanism_v2_Review.md`.
Historical results (`qwen3_v3` and everything before it) remain unchanged; `qwen3_mechanism_v1` is
preserved unchanged as the confounded prior attempt, not deleted or overwritten.

### 2026-10-11 — A significant pre-existing finding: `autogrep_default`'s own worked examples are invalid YAML, present in every historical run

Found via an independent review of `qwen3_mechanism_v2`'s captured prompts (not by this agent) and
verified directly: `yaml.safe_load()` fails on all three per-language example blocks
(`EXAMPLE_RULES` in `autogrep/llm_client.py`) — python, javascript, and java each fail with
inconsistent block-mapping indentation (list-item fields don't align to the item's own key column).

**This is not a new bug, and not something introduced by this diagnostic campaign.** Confirmed by
directly testing the ORIGINAL, historical local copy inside `_build_prompt_autogrep_default` (same
content, since the module-level `EXAMPLE_RULES` added earlier this session was a verified
byte-identical extraction) — it fails identically. This defect is inherited from the vendored
upstream Autogrep tool itself (`lambdasec/autogrep`, commit `ace3c87a`) and has been present in the
"EXAMPLES OF HIGH-QUALITY RULES" section of every prompt sent under `autogrep_default` since Phase 1
— the full pilot screening, the 8-model primary benchmark, all 5 stability reps, C2/C3/C4, the
7-model follow-up campaign, and the `gpt-4o` campaign. Every headline result in this study was
produced under this prompt.

**Scope of actual effect: not established, and this entry does not claim otherwise.** The examples
are illustrative text shown to the model inside a larger natural-language prompt — this pipeline
never parses them itself, so the defect does not corrupt any existing metric computation directly.
The only plausible effect is behavioral: a model partially imitating the shown (broken) indentation
when writing its own rule could be a contributing factor to some of the YAML-parse failures observed
scattered across this study (e.g. `CASE-0238`'s persistent malformed-YAML failures in both mechanism
runs). This is a hypothesis, not something measured here — no claim is made about how much, if any,
of the study's observed parse-failure rate this explains.

**Deliberately not fixed in `autogrep_default` or in `EXAMPLE_RULES` itself.** That prompt's entire
methodological role is to represent the unmodified upstream tool exactly as pinned (its hash is
recorded in `pipeline/PINNED_CONFIG.md` and re-verified by SHA-256 multiple times this session,
`161d0f8329be00faf7e17191345fb14f3e52081ff0f5a4cda40492d3bad9aea1`, unchanged by any edit below) —
silently correcting it would mean the "baseline" no longer represents what every existing published
result actually measured. Fixed only in a new copy, `EXAMPLE_RULES_V2` (valid YAML, confirmed via
`yaml.safe_load()` on all three languages), used only by a new, distinctly-named condition,
`diagnostic_mechanism_v2`.

**Naming-hygiene correction, also from the same review**: the two already-run trials
(`qwen3_mechanism_v1` then `qwen3_mechanism_v2` — unfortunately named the same as this new prompt
variant's run directories, a coincidence worth flagging so it isn't misread) were both launched under
the CLI string `--prompt-variant diagnostic_mechanism_v1`, even though the underlying prompt content
changed between them (examples added, `patterns:` guidance added) — the variant *identifier* didn't
change to track that, relying only on each run's own recorded code hash to distinguish them rather
than the name itself. Fair critique: going forward, `diagnostic_mechanism_v1` is now frozen to mean
exactly what it already meant for those two completed runs (including the inherited broken-YAML
examples) and is never edited again; any further change gets a new identifier. The YAML-indentation
fix above is `diagnostic_mechanism_v2` (the prompt-variant string) for exactly this reason — not a
third silent edit to `v1`. (Note the naming collision: `diagnostic_mechanism_v2` as a *prompt variant
string* is unrelated to `qwen3_mechanism_v2` as a *run directory name* — the latter used the `v1`
prompt string throughout, per the paragraph above.)

No live model run has been made with `diagnostic_mechanism_v2` yet — this entry documents the fix and
its verification, not a result.

### 2026-10-11 — `diagnostic_mechanism_v2` (fixed examples) live trial: same 5/24, different composition, one hypothesis falsified

Run directory `qwen3_mechanism_v3` (the first live use of the `diagnostic_mechanism_v2` prompt
string, i.e. valid-YAML examples + mechanism guidance + `patterns:` guidance). Same budget as every
prior trial (temp 0, 3 attempts, 2048 tokens, same 24 cases).

**Result: 5/24, confirmed under the fully corrected evaluator (`pipeline/rescore_qwen3_v3_corrected.py
qwen3_mechanism_v3`) too — identical headline number to `qwen3_mechanism_v2`'s broken-examples trial,
but a different composition.** Lost `CASE-0221` (stable across baseline and the prior mechanism trial
until now); did not regain `CASE-0063` (the one case the broken-examples trial had newly solved).
Net: baseline's 6 minus `CASE-0221`, nothing else changed.

**One specific hypothesis is now falsified, not just untested**: `CASE-0238` fails with the exact same
error, byte-for-byte, across all three attempts, identical to every prior trial
(`Papaparse.unparse(..., { escapeFormulae: true })`, same line/column). Fixing the broken example
indentation did not change this case's own malformed-YAML failure at all — whatever is wrong with
this case's generation is unrelated to the examples bug.

**`CASE-0221`'s new failure mode, traced concretely**: the model emitted *two* separate rules under
`rules:` on all 3 attempts (confirmed directly in the raw captured response -- 
`micronaut-netty-http-headers-default-constructor` and a second
`micronaut-netty-http-headers-untrusted-input` rule), tripping the schema policy's "expected exactly
one rule mapping" check. A plausible mechanism, not proven: `EXAMPLE_RULES_V2` shows exactly two
worked examples per language, and the model may have imitated that *count*, not just the
style/content, now that the examples are legible enough to absorb a structural pattern from. This
specific case previously succeeded cleanly under every earlier condition — this is a new failure mode
this exact fix introduced, trading a historically-reliable case for an unrelated structural mistake.

**Overall assessment across three live trials now completed under this prompt-engineering direction
(`qwen3_v3` baseline 6/24, `qwen3_mechanism_v1` [broken examples] 4/24, `qwen3_mechanism_v2`-string
[fixed examples] 5/24)**: none has matched or exceeded the original `autogrep_default` baseline, and
each trial's composition has shifted in a different, individually-traceable way rather than
converging toward a stable improvement. On a 24-case subset, this is consistent with the project's
own standing caution that any workflow chosen from this development subset needs fresh held-out
confirmation before being trusted — the signal at this sample size does not yet support concluding
either that composite/taint support helps or that it doesn't. No further live trial under this
direction is planned without a larger or repeated-trial design to distinguish real effect from the
sampling noise these three trials demonstrate is substantial. Historical results remain unaffected;
all three mechanism trials are preserved as-is.

### 2026-10-11 — `diagnostic_mechanism_v3`: offline fix for the two problems traced in v3's own live trial, no new run launched

An independent review of `qwen3_mechanism_v3`'s captured prompts/episodes found two further,
concrete, traceable problems and recommended pausing further live reruns until they're fixed and
validated offline. Followed that recommendation: both fixed, verified, **no live run launched**.

**1. `CASE-0221`'s new failure (two rules emitted, confirmed in its raw response) traced to
`EXAMPLE_RULES_V2` showing two worked examples per language.** Reduced to one rule per language in a
new `EXAMPLE_RULES_V3` (kept the first of each previous pair; dropped the second rather than editing
either in place).

**2. A gap noticed independently while fixing #1**: `EXAMPLE_RULES`/`EXAMPLE_RULES_V2` only ever had
`python`/`javascript`/`java` keys — no `typescript` entry, an upstream gap inherited unchanged from
`autogrep_default`. Confirmed 6/24 (25%) of the dev subset is TypeScript (`benchmark/
diagnostic_20261010/selection.json`), meaning every TypeScript case got zero worked examples under
every condition tried so far, including the historical baseline. Added a `typescript` entry to
`EXAMPLE_RULES_V3`, deliberately written to demonstrate the colon-quoting fix below in practice
(its `pattern-not` value contains `{ escapeFormulae: true }`, correctly single-quoted).

**3. `CASE-0238`'s persistent failure** (confirmed identical across all three prior trials, unrelated
to the indentation fix) is an unquoted pattern/message value containing its own embedded
`"key: value"`, which breaks YAML's block-mapping parser — confirmed by tracing the exact raw
response. Added explicit colon-quoting guidance to the prompt body (only for `diagnostic_mechanism_v3`,
via a new `quoting_guidance` parameter), plus an explicit "exactly one rule, never two" restatement
right next to it. **Caught a self-inflicted instance of the exact same bug while testing**: the first
draft of the new typescript example's own `message:` field had an unquoted `{ escapeFormulae: true }`
and failed `yaml.safe_load()` — fixed before it was ever used anywhere.

**Verified before considering this done**: all four `EXAMPLE_RULES_V3` languages parse via
`yaml.safe_load()`; a real prompt build for one case per language (python/javascript/java/typescript)
confirms the new variant's examples, quoting guidance, and one-rule guidance are all actually present
in what would be sent; `diagnostic_mechanism_v1` is completely unaffected (still produces exactly
what `qwen3_mechanism_v1`/`v2` already used); `autogrep_default`'s hash is unchanged yet again
(`161d0f8329be00faf7e17191345fb14f3e52081ff0f5a4cda40492d3bad9aea1`). All 18 regression tests pass.

**No live model run has been made with `diagnostic_mechanism_v3` yet.** This entry documents the
offline fix and its verification, per the explicit recommendation to validate offline before spending
on another 24-case trial.

### 2026-10-11 — `diagnostic_mechanism_v3` live trial: first mechanism-prompt run to reach parity with baseline (6/24), one remaining issue traced and fixed offline as `diagnostic_mechanism_v4`

Run directory `qwen3_mechanism_v4`, launched with `--prompt-variant diagnostic_mechanism_v3` (the
already-built, examples-fixed-plus-one-rule-plus-quoting-guidance prompt from the entry above). Same
budget as every prior trial.

**Result: 6/24, confirmed under the fully corrected evaluator (`pipeline/rescore_qwen3_v3_corrected.py
qwen3_mechanism_v4`) too.** First mechanism-prompt trial to match `autogrep_default`'s own headline
number. Composition: lost `CASE-0276`, gained `CASE-0063` — a net-neutral swap versus baseline, not
simply "the same 6 cases as before."

**`CASE-0221`'s fix (single-rule examples) is confirmed working exactly as intended**: the model's
rule is now a simple, single `pattern:`/`pattern-not:` form — no more multi-rule output, no more
"Expected exactly one rule mapping."

**`CASE-0276`'s new failure is the identical `pattern-either` + sibling `pattern-not` composition
gotcha already confirmed via an isolated test in the `qwen3_mechanism_v2` entry above** — recurring
in a case that hadn't hit it before, confirming this is a real, repeatable model tendency rather than
a one-off. This was a documented-but-not-yet-prompted-against gap: the gotcha had been found and
proven, but no guidance about it had been added to any prompt variant yet.

**Fixed offline, as a new, distinctly-named condition** (`diagnostic_mechanism_v4` -- NOT a further
edit to `v3`, which must stay frozen exactly as it is: it's what actually produced this real 6/24
result). Added explicit guidance: `pattern-either` with a sibling top-level `pattern-not` does not
compose as an exclusion; both must be inside one `patterns:` list together
(`patterns: [{pattern-either: [...]}, {pattern-not: ...}]`) to actually work. `diagnostic_mechanism_v4`
is otherwise identical to `v3` (same examples, same quoting guidance, same one-rule guidance).

**Verified**: all 18 regression tests pass; `v4`'s built prompt for `CASE-0276` (the case that
triggered this) contains the new composition guidance plus everything `v3` already had;
`diagnostic_mechanism_v3` is completely unaffected (confirmed no composition guidance present,
confirmed it's what the real `qwen3_mechanism_v4` run actually used); `autogrep_default`'s hash is
unchanged yet again (`161d0f8329be00faf7e17191345fb14f3e52081ff0f5a4cda40492d3bad9aea1`, same test
case as every prior check).

**No live model run has been made with `diagnostic_mechanism_v4` yet.** Given this is the first trial
in this whole line of investigation to reach baseline parity, with a remaining regression that's both
concretely traced and now directly addressed, this is a reasonable candidate for one more live test
before deciding whether this direction has converged on something durable or is still within sampling
noise.

### 2026-10-11 — `diagnostic_mechanism_v4` live trial: a self-inflicted regression, root-caused precisely, worst result of the five trials (3/24)

Run directory `qwen3_mechanism_v5`, `--prompt-variant diagnostic_mechanism_v4`. Same budget as every
prior trial.

**Result: 3/24, confirmed under the fully corrected evaluator (`pipeline/rescore_qwen3_v3_corrected.py
qwen3_mechanism_v5`) too.** The worst of all five trials run so far (`qwen3_v3` baseline 6/24, `v1`
4/24, `v2`-string 5/24, `v3` 6/24, now `v4` 3/24).

**Root cause, traced precisely, not merely suspected: the new `composition_guidance` text added this
same day is the direct cause.** That guidance illustrated the correct `pattern-either`+`pattern-not`
composition as `patterns: [{pattern-either: [...]}, {pattern-not: ...}]` — the `[...]` was meant as
shorthand for "pattern-either's own existing list content," but written that compactly, without ever
showing a fully-expanded example, the model generalized it into "`pattern-either` takes a list of
bare values" instead of a list of `{pattern: ...}` mappings (the actual, required Semgrep schema).

**Confirmed systematic, not a one-off**: checked every case's raw captured response directly for this
exact malformed shape — at least 5 of 24 (`CASE-0134`, `CASE-0136`, `CASE-0220`, `CASE-0221`,
`CASE-0276`) show `pattern-either:` followed by bare strings/block-scalars instead of `- pattern: ...`
items, each rejected by Semgrep's own schema validator (`InvalidRuleSchemaError`). Notably,
`CASE-0134` doesn't even use the `pattern-not`-exclusion pattern the guidance was about — it just
used the malformed `pattern-either` list shape on its own, showing the bad shorthand propagated
beyond the specific construct it was meant to illustrate.

**This is the second time in this line of investigation that guidance added for one specific case
introduced a new, broader regression elsewhere** (the first: `EXAMPLE_RULES_V2`'s two-rules-per-
language count teaching the model to emit two rules, `qwen3_mechanism_v3`'s entry above). Worth
naming as a pattern, not treating each instance as independent: compact/abbreviated example syntax
in a prompt is a real risk the model can over-generalize from, and this project's "add guidance, test
again" loop has now produced an unintended regression on two separate occasions out of five trials.

**Recommendation, not yet acted on without the user's direction**: either revert to `v3` (verified
6/24, no composition guidance, currently the best and most reliable result across all five trials) as
the practical stopping point for this line of investigation, or rewrite the composition guidance with
a fully-expanded, unambiguous example (explicit `pattern:` keys, no ellipsis) as a new `v5` and test
once more. Given two self-inflicted regressions out of five trials and no trial yet exceeding
baseline, continuing this single-variable-at-a-time iterative process is showing diminishing and
unstable returns — a reasonable point to pause and decide direction rather than automatically
proceeding to a sixth trial.

### 2026-10-12 — Bounded investigation (Research_Direction_20261011.md items 1/2/4/5): an independent review found 7 real bugs, all confirmed and fixed

Following `Research_Direction_20261011.md`'s pause-and-reflect recommendation, items 1 (common
evaluator), 2 (failure-category audit), 4 (typed rule representation), and 5 (behavioral-probe
design) were worked through offline, no new inference, documented in full in
`Research_Log/Diagnostic_20261010/Bounded_Investigation_Tracking.md`. An independent review
(`Bounded_Investigation_Review_20261012.md`) then found 7 real issues in that work, 3 high-severity.
Every one was independently reproduced before being accepted — none taken on faith — and every one
is now fixed. Full detail, exact repros, and the corrected per-dataset tables are in the tracking
document; this entry is the project-wide summary.

**High severity:**

1. **The typed-rule serializer's "simple case" silently failed to exclude anything, despite passing
   `semgrep --validate` cleanly.** A rule with top-level sibling `pattern: foo($X)` / `pattern-not:
   foo("safe")` matched BOTH `foo("unsafe")` and `foo("safe")` under real pinned-Semgrep execution.
   Reproduced directly before fixing. The historical rules I'd cited as precedent for this form
   (e.g. `CASE-0124`) all happened to use a `pattern-not` for something totally unrelated to the
   main pattern, so the exclusion mechanism itself was never actually exercised by any real
   evidence — "this rule was historically accepted" ≠ "this composition form works." Fixed: any
   `pattern_not`, even exactly one, is now always composed inside `patterns:`; no sibling shortcut
   remains. A permanent executable regression test (`pipeline/tests/test_typed_rule.py`) now runs
   real target files through real Semgrep and checks actual match behavior — the exact gap that let
   a schema-only check hide this bug in the first place.
2. **`run_model_case()`'s actual generation-loop stopping decision still gated on `legacy_accepted`**,
   unaffected by the `*_corrected` fields added to `report()` — those only ever changed aggregate
   reporting, never the loop deciding whether a wrong-location rule gets a real repair attempt.
   Reproduced with a mocked wrong-location evaluation: the loop accepted after exactly one call and
   never retried. Fixed with an explicitly-named, opt-in `--acceptance-policy` flag — `legacy`
   (default) reproduces every already-completed run byte-for-byte; `corrected` requires
   `visible_correct` and feeds back specific wrong-location repair guidance instead of silently
   banking a false win. Two new regression tests confirm both policies' exact behavior.
3. **The failure-category auditor only ever looked at the final accepted evaluation**, so any case
   without one contributed to NO category at all — 57 of 144 episodes across the 6 real datasets,
   independently recomputed and confirmed exactly. This made `mechanism_v1`'s true severity invisible:
   its real `original_miss` rate is 12/24 (half the cases never even detected the vulnerability),
   not the "4/24 structural_miss among the lucky 11" the old presentation implied. Rewritten to walk
   the retained per-attempt records, covering all 24 requested episodes with a real visible-stage
   audit (never_parsed / rule_construction_error / target_error / original_miss / wrong_location /
   patched_fp / never_accepted); the hidden-stage categories (renamed_miss/structural_miss/
   safe_benign_fp) are kept, unchanged and still correctly computed, but now explicitly labeled as
   conditional-on-acceptance rather than implied to cover all 24.

**Medium severity, also fixed:**

4. The proposed development-probe validation (Item 5) was circular — discarding a probe because the
   baseline rule fails it would discard exactly the probes that expose the baseline's own
   generalization gap. Redesigned to validate probes via AST-isomorphism against the original
   function (never any rule, baseline or candidate, as the oracle); softened the "can never leak"
   claim to what independent construction actually establishes (reduces risk, doesn't prove zero
   overlap).
5. `TypedRule.validate()` had no real runtime type checking — `pattern_either="foo()"` (a bare
   string) was silently accepted and iterated character-by-character into 5 single-character
   "alternatives"; empty lists were accepted as non-empty; a taint rule's `pattern_not` was silently
   dropped rather than rejected. All reproduced before fixing. `validate()` now checks real types/
   shapes for every field and raises instead of silently misbehaving.
6. The `.tsx` staging cache trusted an existing directory without verifying its bytes — a stale or
   interrupted-partial stage would have been served forever. Fixed: every call now re-verifies
   staged bytes against the frozen source and repairs any mismatch. Annotation-file hashes
   (`variant_vulnerable_lines.jsonl` + the v2 additions) were also added to run provenance, since the
   existing code-hash tracking couldn't catch a change to the location data itself.
7. `pipeline/verify_scan_integration.py` printed "(expected 6)" without ever asserting it — exit 0
   was not actually evidence anything held. Rewritten to assert the exact complete_success count,
   the exact set of successful case IDs (not just the count, which could hide a same-total-
   different-cases swap), and both conditions' scan-error counts, writing a versioned timestamped
   summary instead of reusing a fixed scratch path. Reran after every fix above: still passes.

**Net effect on every number reported before 2026-10-12**: none of the 5 live mechanism-prompt
trials' reported `complete_success` counts change — those were always read directly from
`report()`'s own field, which was correct throughout. What was wrong was downstream presentation
(Item 2's audit) and prototype code nobody had used in a live run yet (`typed_rule.py`, Item 5's
design) — not any already-reported headline result. All 29 regression tests pass
(18 original + 9 `typed_rule` + 2 acceptance-policy). Item 3 (independent review) remains a partial
self-review, as its own caveat always stated — the external review confirmed this status rather
than changing it.

### 2026-10-12 — Bounded investigation, round 2: a follow-up review found 5 more issues in the fixes above, all confirmed and fixed

The same day's fixes above were themselves reviewed a second time
(`Bounded_Investigation_Followup_Review_20261012.md`), on the standing project rule that a review's
own fixes get checked with the same rigor as the original work. Found 5 real issues, none caught by
me. Every one independently reproduced before being accepted; every one now fixed. Full detail in
`Bounded_Investigation_Tracking.md`'s second update section; summary here:

1. **The rewritten failure-category auditor (fix #3 above) still mixed denominators.** For
   `qwen3_mechanism_v1`'s raw hidden-stage output, 19 cases were reported under a label implying
   "accepted" when only 6 actually passed real `legacy_accepted` — reproduced exactly (19 vs 6).
   Separately, `original_miss` conflated "clean scan, genuinely never detected" (10/24) with "never
   got a clean scan to check at all" (2/24) — reproduced exactly (10+2=12). Separately, the
   acceptance gate was hardcoded to `legacy_accepted` regardless of the run's own
   `--acceptance-policy` (no live "corrected"-policy run exists yet, so no historical number was
   actually wrong, but the code wasn't forward-compatible). Fixed: `acceptance_field_for()` reads
   the run's recorded policy; raw-stage output reports `n_scanned_successfully` and
   `n_actually_accepted` as two explicit, never-conflated numbers; `original_miss` split into
   `original_miss_clean`/`original_unevaluable`.
2. **The `.tsx` staging integrity check (fix #6 above) only actually ran on the FIRST call per case
   per process** — a module-level cache guard skipped the byte-verification on every later call,
   directly contradicting both the code's own comment and the first round's summary table, which
   both claimed "verified on every call." Confirmed by re-reading the code. Fixed by deleting the
   cache dict and its guard entirely — verification is now genuinely unconditional on every call, no
   process-lifetime shortcut.
3. **Item 5's redesigned probe spec (fix #4 above) contained an internal contradiction**: one
   paragraph required the probe's transform family to be "explicitly different" from the hidden
   families, a later paragraph called it a "same-transform-FAMILY-but-different-instance signal."
   Separately, the design never addressed that AST-isomorphism alone doesn't guarantee behavior
   preservation — a rename can pass an isomorphism check at every `Name`/`arg` node while still
   breaking behavior that references the old name by string (`locals()["token"]`,
   `getattr(obj, "token")`, `eval`/`exec` containing the literal string). Fixed in the design text:
   resolved the contradiction in favor of "different family" (the version that actually serves the
   no-leakage purpose); added an explicit probe-eligibility filter excluding any candidate function
   that calls `locals`/`globals`/`getattr`/`setattr`/`vars`/`eval`/`exec`, with its exclusion rate to
   be reported as a finding if it turns out large, not silently dropped. Design-only, no code yet.
4. `pipeline/verify_scan_integration.py`'s recorded `semgrep_version` (fix #7 above) came from a
   bare `subprocess.run(["--version"])` with no `env=` override, bypassing this exact project's own
   documented fix for pysemgrep's PATH-delegation bug (the same bug class `semgrep_env()` already
   guards against at every real scan call in this script). Did not reproduce a wrong version in the
   shell this was fixed in (got `1.177.0` correctly either way), but the underlying bug class is
   real and already documented elsewhere in this project, so the defensive fix was made regardless.
   Now uses `dv2.semgrep_env(out)`; reran and got identical PASSED output.
5. Two smaller `TypedRule` gaps (fix #5 above hadn't covered these): `metadata` accepted any type
   with no check (confirmed: a bare string passed `validate()` silently); `languages` passed as a
   tuple satisfied the list-or-tuple check but produced YAML with a `!!python/tuple` tag that
   `yaml.safe_load()` cannot parse back (confirmed exactly — "could not determine a constructor for
   the tag"). Fixed: `validate()` now rejects non-dict `metadata`; `to_dict()` always emits
   `list(self.languages)` regardless of the input container type, so the serializer guarantees
   parseable output rather than relying on caller discipline.

**Net effect on every number reported before this round**: unchanged again — these are fixes to
audit/design/validation code, not to any reported `complete_success` figure. All 29 regression
tests still pass; `verify_scan_integration.py` and `typed_rule.py`'s own real-Semgrep check both
rerun clean after their fixes.

The reviewer also surfaced a new, unactioned research finding (not a bug in this investigation):
42/87 historically-accepted rules across the real diagnostic runs — including all 19 of
`qwen3_v3`'s baseline accepted rules — use the same sibling `pattern`+`pattern-not` form now
confirmed non-functional for exclusion (finding #1 of the first round above). Some unknown fraction
of those 42 "accepted" rules may never have actually excluded anything via that clause. Not
investigated — would require rewriting each and re-running through real Semgrep to see whether any
historical TP/TN/FP/FN outcome changes. This is new scope beyond the 5 bounded-investigation items
and needs an explicit decision before any work starts on it.

### 2026-10-12 — Bounded investigation, round 3: a third review verified rounds 1–2's closures and found 2 further issues, both confirmed and fixed

A third review (`Bounded_Investigation_Round3_Review_20261012.md`) independently re-verified every
fix from both earlier rounds and confirmed them closed — the exclusion-composition fix, the
stopping-policy flag, the auditor's denominator labeling, same-process TSX staging, the
`verify_scan_integration.py` environment fix, and the `metadata`/`languages` typed-rule fixes all
held up under re-check. It then found 2 further issues, both independently reproduced before being
accepted. Full detail in `Bounded_Investigation_Tracking.md`'s third update section; summary here:

1. **The failure-category auditor's error classifier was still too broad.** `_is_target_error`
   ("has a `path` key") was the ONLY classifier; everything else — including `diagnostic_v2.py`'s
   own synthetic status messages ("Semgrep exited with status N", "Semgrep did not scan every
   requested sample") — fell into `rule_construction_error` by default, even though those messages
   are process/exit-status commentary, not Semgrep's own report that a rule is malformed. Reproduced
   the double-count with a synthetic fixture. Checked every real retained episode across all 6
   datasets for the actual co-occurrence this would require (a path-error and a non-path error in
   the same scan's errors list): it never happens in retained data, so **no historical
   `rule_construction_error` or `target_error` count changes** — confirmed directly by rerunning the
   fixed auditor across all 6 datasets and diffing every count against before the fix (byte-identical
   everywhere; `unclassified_scan_error`, the new category for the never-occurring edge case, is
   0/24 on every dataset). Fixed anyway since the classifier was wrong in general, not just lucky not
   to have mattered yet: `_is_status_wrapper()` now excludes the synthetic messages from
   `rule_construction_error` by content.
2. **Item 5's "different transform family" fix from round 2 was itself incomplete.** It corrected
   the design's "What this is NOT" paragraph to say "different family," but the Construction
   paragraph — the part that actually specifies the mechanism — still described renaming, the SAME
   family reserved for the real hidden `variant_vulnerable_1`. Saying "different family" in one
   place while the only specified construction uses a reserved family doesn't make it different;
   it just relocates the contradiction. Separately, the round-2 reflection-exclusion filter doesn't
   cover every way a rename can break behavior: `def probe(token): return token` has no
   `locals`/`getattr`/`eval` call (passes the filter) and is AST-isomorphic to its renamed version,
   yet a caller invoking it as `probe(token="unsafe")` — outside the construction's visibility,
   since only the function body is available — breaks with a `TypeError` after the rename.
   Reproduced exactly. Fixed by taking the honest option over inventing an unvalidated new transform
   family under time pressure: the design now explicitly frames renaming-based probes as a
   WITHIN-family development signal (freshly constructed, independent instances — never the real
   hidden file, never compared against it), narrowing what Research Question 3 can actually claim
   from this construction; separately, probe renaming is now restricted to purely local, non-parameter
   bindings, which removes the keyword-caller failure mode directly without needing visibility into
   external callers. Design-only — no code exists yet for this item.

**Net effect on every number reported before this round**: unchanged, same as both earlier rounds —
these are a classifier-precision fix (verified not to move any historical count) and a design-text
correction (no code has run under the old wording to have produced a number). All 29 regression
tests still pass.

### 2026-10-12 — Offline composition-ablation experiment on the 42 historical sibling-exclusion rules, plus a second typed_rule.py bug found as a byproduct

With the user's explicit go-ahead, ran the round-3 review's recommended offline experiment: for all
42 historically-accepted rules (across the 6 real datasets) using the sibling `pattern`+`pattern-not`
form already confirmed non-functional for exclusion, built a separate rewrite that changes ONLY
composition (moved into `patterns:`, every other field byte-identical), scanned both the original
and rewritten rule through the identical pinned engine/TSX staging/annotations, and compared
outcomes. New script: `pipeline/exclusion_composition_ablation.py`. No historical rule or result
was modified; this is a new, exploratory analysis layered on top of existing, unmodified data.
Full detail in `Bounded_Investigation_Tracking.md`.

**A methodological complication was found and corrected before reporting any number**: a naive
"original vs. fully-rewritten" comparison would have conflated two unrelated effects. Directly
reproduced that wrapping `pattern`+`pattern-inside` in `patterns:`, with NO `pattern-not` involved
at all, already loses a match the identical pair finds as top-level siblings (CASE-0063,
qwen3_mechanism_v3/v4) — a separate Semgrep 1.177.0 composition quirk, unrelated to exclusions.
Added a third "isolated" rewrite (patterns: wrapper, exclusion keys removed) to split every
observed change into the unrelated nesting artifact vs. the exclusion genuinely becoming operative,
so nothing gets misattributed.

**Results, after that correction**: of 42 instances (19 distinct case ids — not independent, the
same handful of cases recur across runs), 0 rejected (all matched the pre-specified shape), 0
replay mismatches against the historical record. `complete_success`: 0 gained, 9 lost, 33
unchanged — 1 of the 9 losses from the unrelated nesting artifact, 8 from the exclusion actually
firing. Hidden-variant true positives: 0 gained, 22 lost (4 nesting-artifact, 18 exclusion-effect).
Hidden-negative false positives: 0 gained, 1 lost (exclusion-effect) — no evidence in this dataset
that the broken exclusion was hiding inflated false-positive counts.

**All 8 genuine exclusion-effect losses trace to only 2 distinct rules** (CASE-0220, CASE-0323,
each reused across several runs). Inspected directly: in both, the model's own `pattern-not` is
identical or near-identical to its own `pattern` — a self-cancelling exclusion that, once correctly
composed, excludes everything the pattern itself matches, including the real vulnerability. The
already-known composition bug happened to render this self-defeating clause inert, which is the
only reason these 2 rules' historical "wins" happened at all.

**This does not mean any historically-reported number was wrong.** Every historical
`complete_success`/`accepted` figure correctly, faithfully measured the model's actual, literal rule
file executed by real Semgrep — exactly what happened, exactly what was measured; nothing here
retroactively corrects a published number. What it shows is prospective: a correctly-composing
representation (e.g. `typed_rule.py`, or a future typed-representation arm in the 2x2 comparison)
will SURFACE cases like CASE-0220/CASE-0323 rather than regress them — their old "success" depended
on a model-authored logical error that the broken baseline happened to mask. A typed-representation
condition scoring lower on cases like these is not evidence the representation is worse; it may be
evidence it's surfacing a pre-existing defect the broken baseline never let through to be seen.

**A second, independent `typed_rule.py` bug was found as a direct byproduct of running this
experiment** — not from any review, from using the module's own logic as an input elsewhere.
`to_dict()` routed `pattern_inside` through the `patterns:` wrapper whenever it was set, even with
NO exclusion present at all. Reproduced directly that `TypedRule` itself reproduces CASE-0063's
exact failure (0 results where the sibling form finds 1). Fixed: `pattern_inside` now only goes
through `patterns:` when an exclusion key actually requires it; with no exclusion, `pattern`/
`pattern_inside` stay a top-level sibling pair (independently confirmed to work). A new permanent
regression test was added against the real CASE-0063 file (a minimal synthetic fixture was tried
first and did not reproduce the bug, so the test uses the real case directly). Full suite: 30/30
pass.

**Unit-of-analysis caveat, stated directly**: this is an ablation on already-ACCEPTED rules only —
it cannot estimate how many rejected rules might have been accepted under correct composition, nor
does it imply anything about a different repair-loop policy. Only 3 of the 19 distinct case ids
touched (CASE-0063, CASE-0220, CASE-0323) account for every complete_success change found; the
other 16 distinct cases' rules were entirely unaffected by the fix.

### 2026-10-12 — Correction to the entry above: the "nesting artifact" was a misdiagnosis, and the reported FP improvement was a compile failure

A follow-up review (`Exclusion_Ablation_Review_20261012.md`) found two real issues in the ablation
entry directly above, both independently reproduced before accepting. This entry does not delete
or edit that entry — it corrects it, per this log's own practice everywhere else.

**1. CASE-0063 was never an unrelated "nesting artifact" — it's the same defect category as
CASE-0220/CASE-0323, misdiagnosed.** The prior entry claimed wrapping `pattern`+`pattern-inside` in
`patterns:` (no exclusion present) was an unrelated Semgrep composition quirk, and a same-day fix to
`typed_rule.py` kept `pattern_inside` as a sibling whenever no exclusion was present specifically to
avoid triggering it. Reproduced directly that this reasoning was backwards: a sibling
`pattern-inside` naming a function that **does not exist in the target file** still matches — a
probe a positive-only check can't catch. A top-level sibling `pattern-inside` is silently IGNORED
by Semgrep, never enforced; the NESTED form is Semgrep's own required composition for
`pattern-inside` to have any effect at all, and it correctly returns 0 for CASE-0063 because the
real vulnerable code sits inside an ANONYMOUS function, not the named one the model's rule asked
for. CASE-0063 belongs in exactly the same bucket as CASE-0220/CASE-0323: a model-authored
constraint (here, a wrong scope restriction instead of a self-cancelling exclusion) that the
historical composition bug happened to render inert. The `typed_rule.py` "fix" from the prior entry
was reverted the same day — `pattern_inside` is now ALWAYS composed via `patterns:`, with no
sibling shortcut, same as any exclusion key. The backwards regression test that fix had added
(asserting the broken sibling form) was replaced with two tests using an in-scope AND an
out-of-scope example — a positive-only fixture is exactly what let both this bug and the original
`pattern-not` bug go undetected.

**2. The "one FP improved" claim is withdrawn — it was a compile failure, not a behavioral change.**
The ablation script's outcome comparison didn't check `scan_ok` on either side before diffing
sample outcomes. `scan()` still returns a `samples` record even when a scan fails (empty
`findings`, since the rule never ran) — confirmed directly that CASE-0184's rewritten rule has a
genuine Java rule-parse error (`scan_ok=False`), and its trivial FN/TN defaults were counted as 2
hidden-TP losses and 1 hidden-FP "improvement" that never behaviorally happened. Fixed: any
instance where either scan failed is now excluded from the behavioral TP/FP transition tallies
specifically (not from all-instance complete_success accounting, where it correctly stays counted
as the failure it already was) and reported separately instead (`n_unevaluable_due_to_scan_failure`).

**Corrected numbers** (re-ran the full ablation; prior summary.json left in place, not deleted):
`complete_success` unchanged at 0 gained / 9 lost / 33 unchanged (CASE-0184 was already an E2E
failure in both arms, so excluding it doesn't move this count). Hidden-variant true positives: 41
evaluable pairs, **20 lost** (not 22). Hidden-negative false positives: 41 evaluable pairs, **0
lost** (not 1) — no evidence in this dataset, in either direction, that the broken composition
hid any false-positive inflation. All 9 complete_success losses now trace to 3 distinct rule_ids
(CASE-0220, CASE-0323, CASE-0063) instead of 2 — consistent with point 1 above. Per-run
complete_success numbers are unchanged (CASE-0184 wasn't involved in any of them). `typed_rule.py`'s
regression suite: 31/31 pass.

**What this changes about the conclusion, stated directly, per the review's own framing**: enforcing
the intended DSL can improve fidelity to the authored rule while still reducing measured
complete_success — both are true at once. A future typed-representation arm scoring lower on cases
like these remains a real, measured regression on the prespecified E2E metric; explaining its
mechanism (a pre-existing model-authoring defect the broken baseline was masking) does not
retroactively redefine it as not a regression. These are fixed-rule rewrites, not generations under
a typed prompt — a model given a different output contract and compiler/visible feedback may
produce different clauses entirely, so this experiment explains a mechanism observed here; it does
not predict a future arm's actual score.

### 2026-10-12 — Item 3 (bounded investigation): expanded from a 6-of-24 manual spot-check to full, exhaustive coverage of all 24 diagnostic cases

With the user's go-ahead to do Item 3's best-effort review before drafting the frozen 2x2 protocol:
ran all 24 `benchmark/diagnostic_20261010/reference_rules/v1/*.yml` rules through real pinned
Semgrep against their own full 6-sample bundle — objective and exhaustive, not a manual read of "a
few" rules. Full detail in `Bounded_Investigation_Tracking.md`.

**Zero false negatives anywhere** — every reference rule correctly detects its case's
`original_vulnerable`, `variant_vulnerable_1`, and `variant_vulnerable_2`. **9 of 24 (37.5%) have a
demonstrated precision gap** — the rule fires on at least one sample that should be negative
(`original_patched`, `variant_safe`, or `benign_lookalike`). This is more than triple the 3 found by
the earlier manual spot-check (`CASE-0193`, `CASE-0184`, `CASE-0116`); the additional 6 — `CASE-0046`
(zero constraint tied to the actual blacklist/whitelist distinction at all), `CASE-0063` (a
syntactic regex signature that can't distinguish execution context — an expected limitation, not a
construction error), `CASE-0163` (never checks the one thing the vulnerability is actually about —
whether `$FLAG` is the `--` terminator), `CASE-0235` (an unconstrained `...` wildcard swallows the
exact argument the patch changed), `CASE-0238` (uses this session's own correct `patterns:`-nested
exclusion form, but the one exception it checks for doesn't cover every safe usage), and `CASE-0339`
(a literal-string regex match that also matches the patched code's surviving, no-longer-reached
occurrence of the same string) — were not caught by reading pattern text alone; each needed the
rule run against real negative samples to surface.

**Transformation semantics now confirmed for all 24 cases, not 6.** Directly diffed
`vulnerable_source` against `variant_vulnerable_02` for the 7 precision-gap cases not already
manually checked — all 7 confirmed genuine, vulnerability-preserving restructurings, every one
following the same helper-extraction pattern (the exact vulnerable call is moved verbatim into a
new private method, called from the original site). For the remaining 11 cases, each has a
reference rule with zero demonstrated false positives anywhere in its own bundle, making that
rule's detection of `variant_vulnerable_2` non-confounded evidence of genuine preservation rather
than an overbroad-pattern artifact. Combined with the 6 already checked earlier this session: full
coverage of the diagnostic subset, up from a 6-of-24 sample.

**This doesn't change the project's standing position** that these 24 reference rules are
"diagnostic feasibility aids, not blind expert performance or a generalization ceiling" — it
substantially deepens the evidence for that position with a complete count instead of a partial
one. The independence caveat on Item 3 still genuinely applies: this is the same agent that built
the diagnostic doing a best-effort self-check, not a genuinely independent review.

With all 5 bounded-investigation items now done, drafted (not frozen, not executed) the 2x2
controlled-comparison protocol at
`Research_Log/Diagnostic_20261010/Controlled_2x2_Protocol_Draft_20261012.md`, covering shared
infrastructure (pinned engine, the `corrected` not `legacy` acceptance policy, max attempts),
condition-specific output contracts (including `TypedRule`'s supported-grammar restriction relative
to free-form YAML, stated explicitly per Research_Direction item 4), the development-probe design
from Item 5 as finally corrected, candidate selection (development set repeatedly consulted and
therefore confirmation-ineligible; a confirmation set that does not exist yet and needs sourcing),
and outcome metrics. Five numeric/scoping decisions are explicitly flagged as drafts needing the
user's sign-off (trial count, minimum worthwhile effect size, confirmation-set size, whether to
attempt C/D before the probe mechanism is built, and confirming confirmation-set sourcing is in
scope now) rather than decided unilaterally.

### 2026-10-12 — Correction to the Item 3 entry above: "non-confounded" rule-based confirmation overclaimed for 11 of 24 cases

A review (`Controlled_2x2_Protocol_Review_20261012.md`) independently re-verified the scan
statistics from the entry above and found them exact (9/24 precision-gap rules, 12/72 FP samples,
60/72 TN, 72/72 positive detections, 15/24 reference complete successes — all reproduced exactly).
It then found the semantic-coverage characterization overclaimed: calling a clean reference rule's
detection of `variant_vulnerable_2` "non-confounded evidence of genuine preservation" for the 11
cases not directly diffed was wrong — a rule correctly rejecting three chosen negative samples does
not establish that a transformed positive retains attacker control, reachability, or the actual
security consequence; it only establishes syntactic re-matching, the same sample-level-fit
limitation the Research Direction already names for these rules. Accepted directly — this is sound
reasoning, not something the original entry had independently verified.

Completed direct source-based review for all 11 remaining cases (`CASE-0323`, `0276`, `0221`,
`0136`, `0340`, `0124`, `0222`, `0171`, `0298`, `0231`, `0081`), checking reachability and trust
boundary, not just whether a Semgrep pattern re-matches. All 11 confirmed genuine — mostly the same
helper-extraction pattern as the other 13 (the exact vulnerable call moved verbatim into a new
private method, same call site, same arguments), plus `CASE-0081`'s genuine for-loop→reduce
control-flow rewrite and `CASE-0124`'s f-string→list-join STRING-CONSTRUCTION change (not a
control-flow change at all — a follow-up review caught this entry's own imprecise grouping of the
two together; corrected below), in both of which the actual vulnerable expression/sink is still
preserved byte-for-byte and still reached identically.

**Corrected characterization**: 24/24 reference-rule behavior audited by execution; **24/24** direct
source-based semantic review (not 13/24 direct + 11/24 inferred, as previously claimed). Full detail
in `Bounded_Investigation_Tracking.md`. This does not change any reported number — it corrects what
kind of evidence backs the semantic-preservation claim for 11 specific cases, from an inference the
review correctly identified as too weak to an actual direct check.

### 2026-10-12 — Correction to the 2x2 protocol draft: confirmation-set size was off by more than 2x, plus missing operational decisions

A review (`Controlled_2x2_Protocol_Review_20261012.md`) of `Controlled_2x2_Protocol_Draft_20261012.md`
independently re-verified the Item 3 scan statistics from the entry above (9/24, 12/72, 60/72,
72/72, 15/24 — all reproduced exactly) and found one high-severity, one high-severity-statistical,
and three medium issues in the protocol draft itself.

**Highest-impact finding, independently reproduced before accepting**: the draft claimed 80-100
confirmation cases would reach 80% power for a 10-point absolute `complete_success` improvement at
25% paired discordance, using McNemar's test — a number arrived at by a hand-waved "rule of thumb,"
never actually computed. Recomputed the exact two-sided conditional McNemar power directly (summing
over every discordant-pair count and win count the exact binomial test's rejection probability) and
reproduced the review's own table precisely: 80 cases → 35.4% power, 100 → 44.0%, 200 → 78.7%, 207
→ 80.2%. **207, not 80-100, is the actual requirement for this scenario** — more than double the
original claim. This is exactly the failure mode this project's own standing practice (compute and
verify real numbers, never hand-wave a status or planning figure) exists to catch; it caught itself
here via external review rather than before the draft was written. The draft's confirmation-size
section is corrected to show the real table, flag that even 207 is a simplified i.i.d. scenario that
doesn't yet account for the actual repeated-trial estimator or repository clustering, and give a
budget-planning implication of "200+ per model," not 80-100.

**Other corrections made to the draft, same day**:
- Withdrew the "gpt-4o already shown to be in statistical parity" justification for model selection
  — a prior non-significant difference doesn't establish equivalence or rule out a model-by-
  intervention interaction. The lineage/hosting contrast alone is sufficient justification and is
  retained; every contrast must now be reported within each model, not pooled, with heterogeneity
  itself reported as a finding.
- Withdrew the "3 repeats is the minimum for a variance estimate" claim (2 already suffice); 3 is
  kept as a reasonable small pilot allocation on cost grounds, not a derived mathematical minimum.
- Added a predeclared statistical analysis plan (repeat-aggregation method, the full-factorial
  construction/feedback/interaction decomposition, a required single primary/confirmatory contrast
  designation, repository-clustering-aware uncertainty) — previously entirely missing.
- Added token/call ceilings, retry/timeout accounting, the typed-JSON prompt/decoder spec and its
  repair-feedback path, episode-level and experiment-level stopping rules, and C/D's probe
  operational specifics (count per case, per-language AST/eligibility implementation, name-collision
  checks, eligibility-failure fallback policy with required probe-coverage reporting) — all
  previously unspecified gaps the review correctly flagged as needed before any freeze.
- Added the legacy-vs-corrected-policy comparability caveat: recording both acceptance fields on a
  `corrected`-policy candidate does not reconstruct what a `legacy`-policy repair loop's actual
  attempt trajectory would have produced, since `legacy` can stop earlier on a different candidate.

**Net effect**: no implementation, historical result, or already-reported number changes — this is
a correction to a not-yet-executed draft protocol, caught before any confirmation-set sourcing or
inference spend. The open-decisions list in the draft grew from 5 to 6 items, each now carrying the
review's own recommendation alongside it rather than this session's unilateral choice.

### 2026-10-12 — Follow-up review: a real environmental qualification on CASE-0222, three description-precision fixes, and a genuine C/D stopping-rule ambiguity

A follow-up review (`Controlled_2x2_Protocol_Followup_20261012.md`) directly inspected all 11
newly-reviewed source diffs from the entry above and found two substantive issues, both
independently reproduced before accepting.

**1. CASE-0222's "same effect" claim was an overclaim — reproduced directly from Requests' own
source, not taken on faith.** The entry above called `session.verify = False; session.post(...)`
equivalent to the original `requests.post(..., verify=False)`. Traced Requests 2.34.2's actual
`Session.merge_environment_settings`/`merge_setting` source directly: the environment-variable
override (`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`) only triggers when the per-call `verify` argument
is `True` or `None` at the point `merge_environment_settings` runs. The original vulnerable call
passes `verify=False` explicitly, which never reaches that branch — unconditionally disabled,
confirmed by code inspection alone. The restructured call omits `verify=` entirely (defaulting to
`None`), which DOES reach that branch — if either environment variable is set, it overrides
`session.verify = False`. **Corrected**: CASE-0222 preserves the vulnerability only when neither
variable is set in the execution environment — conditional, not unconditional, preservation. No
complete_success/precision-gap number changes (the diagnostic's own scan environment sets neither
variable); this is a wording correction to the semantic-review claim itself, not a dataset change.

**2. Three description-precision fixes**, all independently verified by re-reading the retained
diffs: `CASE-0323` extracts only the `allowedContent` SUBOBJECT, not the entire widget config
(the surrounding `draggable`/`mask`/`dialog` fields stay inline — corrected in
`Bounded_Investigation_Tracking.md`); `CASE-0136` leaves `File.createTempFile(...)` at its ORIGINAL
call site and only wraps the return value in a new cleanup helper, rather than moving the sink
itself (the one exception to the helper-extraction generalization this group was described with);
`CASE-0124` is a pure string-construction change with no control-flow difference at all, mis-grouped
in the entry above as a "control-flow rewrite" alongside `CASE-0081`'s genuine for-loop→reduce
rewrite. None of these three change the vulnerability-preservation conclusion — they correct how
each transform is described, which matters for anyone trying to verify the claim later.

**3. The 2x2 protocol draft's C/D episode-stopping rule contradicted its own probe-repair
requirement.** Re-read the draft directly: §4 said to accept and stop on `visible_correct` alone,
with no carve-out, while §5 requires continued repair after a probe failure even once the visible
pair already passes — a literal implementation of §4 as written would make C/D collapse into A/B,
silently skipping probe evaluation. Confirmed by re-reading, not just taking the review's word.
Fixed with one explicit combined gate: A/B accept on `visible_correct`; C/D (eligible probe) accept
on `visible_correct AND vulnerable_probe_correct AND patched_probe_correct`; C/D (no eligible
probe) accept on `visible_correct` alone as a declared, recorded fallback — with a probe scan error
on an eligible case never silently treated as "no eligible probe." Also corrected: the draft's
"817 cases are a lower bound" and "budget 200+ cases" wording, which still implicitly treated the
simple single-pair McNemar scenario as a real target — now explicit that 207/817 are illustrative
sensitivity numbers only, and confirmation N stays an open decision until the real repeat-averaged
estimator (§6a) is specified. Added the followup review's refinements to §6a (descriptive B-A
during the pilot, construction-main-effect-on-qwen3 as the recommended primary contrast for
confirmation, a candidate repository-cluster bootstrap estimator) and a precision fix to §10's
interruption-handling text (a completed 3-attempt failed episode is not "missing" and does not get
a fresh budget on resume).

**Net effect**: no implementation, historical result, or already-reported number changes — all
corrections are to self-review wording (CASE-0222/0323/0136/0124's descriptions) and to a
not-yet-executed draft protocol, caught before any confirmation-set sourcing, probe implementation,
or inference spend.

### 2026-10-12 — Closure review: one remaining protocol-wording error, a mislabeled bootstrap

A closure review (`Protocol_Review_Closure_20261012.md`) confirmed the CASE-0222 qualification and
C/D combined gate from the entries above both now match the evidence, and found exactly one
remaining issue in the protocol draft: §6a called its candidate uncertainty method a
"repository-cluster bootstrap" but then described resampling at the CASE level — independently
confirmed by re-reading the draft's own text. Resampling individual cases does not preserve
within-repository dependence, so what was described was not actually a cluster bootstrap at all,
just a case-level one wearing the wrong label. Fixed: the method now describes sampling whole
repository clusters with replacement (each draw pulls an entire repository's cases together; a
repository drawn twice includes its whole group twice), with cross-repository CVE families
flagged as still needing their own explicit grouping rule before this is usable. Does not block
A/B development — this only matters for the eventual confirmation analysis.

### 2026-10-12 — Implemented Condition B (typed-JSON construction mode), offline-tested, no live inference

With the user's explicit go-ahead, built the 2x2 protocol's Condition B output-contract path
(`Controlled_2x2_Protocol_Draft_20261012.md` §4) as a separately-named, opt-in construction mode —
condition A's existing behavior is byte-unchanged by default. Full detail in
`Bounded_Investigation_Tracking.md`. No model calls were made; no pilot was run.

New `Config.construction_mode` field (`"original_prompt"` default, `"typed_json"` for B);
`LLMClient.generate_rule()` now dispatches on it first, routing to new
`_generate_rule_typed_json()`/`_build_prompt_typed_json()`/`_parse_typed_json_response()` methods
that ask the model for a single JSON object matching `TypedRule`'s fields — never YAML, never
Semgrep operator-composition syntax — then construct/validate a `TypedRule` and return its
`.to_dict()`-composed rule, the same shape condition A's parser already returns so the rest of the
pipeline (`run_model_case()`'s wrap-and-dump, the repair loop, scan/accept logic) needs no changes
to work for either condition. Wired `construction_mode` through `gptlab_config.build_config()` and
`diagnostic_v2.py`'s new `--construction-mode` flag, recorded in `environment.json`.

Added 8 new offline tests (`pipeline/tests/test_typed_json_construction.py`, no model calls) per
the review's required checks: valid JSON → executable rule; a fenced/prose-wrapped response still
recovered; invalid JSON, an unexpected field, and mutually-exclusive fields each → the same
bounded-repair-feedback shape condition A's failures already produce; and — the actual regression
this whole investigation exists to catch — a `pattern_not`-bearing response produces a rule that is
BEHAVIORALLY correct under real Semgrep execution (excludes a safe line, keeps matching an unsafe
one), not merely schema-valid. Verified end-to-end via the real CLI in `preflight` mode (no model
calls): both construction modes record correctly in `environment.json`, and `references` mode
still reproduces its known 15/24 complete_success exactly, confirming no regression to `main()`'s
broader control flow. Full `pipeline/tests/` suite (excluding the pre-existing, unrelated
`test_stats_section22.py`): 44/44 pass.

**Not yet done, stated directly**: no live `typed_json` model call, no A/B pilot episode, C/D's
combined gate and probe mechanism remain unimplemented. Next step is a fresh condition-A baseline
under `--acceptance-policy corrected`, then a real `--construction-mode typed_json` run on the
24-case development set — both still gated on the user's decision to spend inference budget.

### 2026-10-12 — Condition B implementation review: 4 real issues found and fixed, all independently reproduced

A review (`Condition_B_Implementation_Review_20261012.md`) reproduced the 44/44 test suite plus its
own 6-scenario mocked-workflow audit (real `generate_rule()`/decoder/`run_model_case()`/raw-capture,
only provider responses and scanner outcomes mocked) and found 4 real issues, every one
independently reproduced before fixing. Full detail in `Bounded_Investigation_Tracking.md`.

1. **B's prompt had no worked examples, unlike A's 2-per-language.** A real confound — any later
   A-vs-B difference would be attributable to either the construction intervention or the lost
   examples, with no way to separate them. Fixed by translating the same 6 examples into
   `TypedRule`'s JSON shape (confirmed each constructs and composes correctly) and adding them to
   B's prompt.
2. **`environment.json`'s `prompt_policy` ignored `construction_mode`** — a `typed_json` run with
   default `--prompt-variant` recorded `"historical_autogrep_default_unchanged"` despite using a
   completely different prompt. Fixed: checks `construction_mode` first, with new
   `requested_prompt_variant`/`prompt_variant_ignored` fields. Verified via real preflight runs for
   both modes.
3. **The frozen-prompt-hash tripwire failed** — a trailing-whitespace-only line before
   `_build_prompt_autogrep_default`'s `return prompt` had been replaced by a plain empty line
   before this review, confirmed whitespace-only drift (not a behavior change — A's 48
   rendered-prompt comparisons and AST-equivalence already confirmed that). Restored the exact
   original whitespace rather than updating the pinned hash to conceal it.
4. **The preflight gate unconditionally required `GPTLAB_API_KEY`**, blocking a gpt-4o-only
   (`OPENAI_API_KEY`-only) environment before the correct host-specific credential was even
   checked, even though `get_key_for_host()` already dispatches correctly. Fixed by resolving the
   host first; also fixed the HTTP-failure message and `credential_available` metadata to be
   host-aware. Verified with 3 scenarios in a credential-scrubbed environment (gpt-4o with no keys,
   gpt-4o with only a fake `OPENAI_API_KEY`, qwen3-coder with no keys) — all behave correctly, no
   regression to the historical GPT-Lab path.

Full regression suite re-run after all 4 fixes: 44/44 pass; `verify_prompt_hashes.py` passes.
Still no live model call, no A/B pilot — these remain the next step.

### 2026-10-12/13 — The A/B development pilot executed: 288/288 episodes, real model calls, descriptive results only

With the user's explicit, separate approval for live inference spend, the full 12-run allocation
(`Condition_B_Readiness_and_Pilot_20261012.md` / `AB_Pilot_Allocation_20261012_v1/`) was executed.
The user ran all 12 commands themselves in their own terminal with their own credentials (never
typed into a file or persisted by this process); each run's `environment.json` and case-directory
count were verified against the allocation's own spec before approving the next command. One
stale, empty, zero-episode leftover directory was found and removed before command #1's real run
(inspected first — zero case data at risk). All 12 then completed cleanly, in the specified
A-then-B/B-then-A alternating order. Full detail, including the complete per-run table, paired
per-case gains/losses, and resource costs, is in `Bounded_Investigation_Tracking.md`.

**Headline, stated with every caveat the protocol requires**: `complete_success` mean over 3
repeats — qwen3-coder:30b A=6.00/24, B=7.00/24; gpt-4o A=5.33/24, B=5.67/24. Both differences are
far below the draft protocol's 10-point minimum-worthwhile-effect threshold and 24×3 was never
sized for a confirmatory claim (§8's own power analysis requires 207+ cases for that). Paired
per-case: qwen3's B gained 1 case, lost 0, perfectly stable across all 3 repeats; gpt-4o's B gained
3 cases but lost 2 — real churn in both directions.

**The pilot's most substantively interesting finding is a construction-validity asymmetry between
the two models, not either model's complete_success number**: for qwen3-coder:30b, condition B's
first-attempt scan errors jump from 1/24 (A) to 6/24 (B), and more episodes never get accepted
within budget (8-9/24 vs. 6/24) — the typed-JSON contract costs this model more failed attempts
even though its eventual complete_success is higher. For gpt-4o, the direction is the OPPOSITE —
B's scan errors are lower than or equal to A's. This is a real, observed model-by-intervention
interaction, not a hypothetical one — exactly why the protocol's analysis plan requires reporting
within each model rather than pooling, and exactly why the earlier "statistical parity" argument
for model selection was correctly withdrawn by an earlier review (parity in baseline rate says
nothing about how each model responds to the construction intervention).

`visible_correct` equals the accepted count in every one of the 12 runs — the `corrected`
acceptance policy is working as intended across both conditions and models; nothing is ever
accepted at the wrong location.

**Resource cost (actual, not the 864-call ceiling)**: 486 total calls used (56% of ceiling).
qwen3's B condition cost +22% more calls than A (132 vs. 108), consistent with its worse
construction validity above. gpt-4o's B and A cost about the same (125 vs. 121 calls).

**What this does not establish**: no winner, no confirmation, no resolution of any of the
protocol's 6 open decisions (§11) — this pilot validated that the new B infrastructure works
end-to-end against real models and produced a first descriptive read, nothing more. No candidate,
case, or repeat was selected or discarded; all 3 repeats for both models/conditions are reported as
run.

### 2026-10-13 — Correction to the pilot-results entry above: an arithmetic slip, an overclaimed interaction, a wrong repeat count, and a mixed denominator

A review (`AB_Pilot_Results_Review_20261013.md`) independently recounted all 288 episodes against
the retained raw captures and found the headline numbers correct, but found 4 real issues in the
interpretation above, every one independently reproduced before accepting. Full corrected detail
in `Bounded_Investigation_Tracking.md`.

1. **Arithmetic slip**: gpt-4o's paired changes were summarized as "gained 3 cases but lost 2" —
   true as a count of cases, but summing the five changed cases' actual per-repeat deltas
   ((2/3+1/3+1) − (1+2/3)) gives **+1/3 case**, not the "+1 case" magnitude a reader could infer.
   +1/3 over 24 cases is exactly the already-correct +1.39-percentage-point headline figure —
   confirmed by direct recomputation.
2. **Overclaimed interaction**: calling gpt-4o's opposite-direction scan-error pattern "a real,
   observed model-by-intervention interaction, not a hypothetical one" overclaims what one small
   pilot can show. Corrected to: a descriptive difference in the two models' observed responses —
   real and worth reporting within-model, but not a demonstrated population-level interaction,
   confirmatory test, or lineage-based explanation.
3. **Wrong repeat count**: gpt-4o B's raw scan errors were implied to vary across repeats ("lower
   than or equal to A's" without specifying how often) — independently recomputed directly from the
   retained episodes: it's **1 in all 3 repeats**, not variable.
4. **Mixed denominator** (caught in the companion Tracking entry, carried here for completeness):
   "complete_success among accepted episodes is higher (7/24 vs. 6/24)" wrongly implies 7/24 and
   6/24 are accepted-only figures; they are already all-requested-denominator numbers with no
   separate accepted-only version computed in this write-up.

**Also added, not a correction but new verified detail**: a finer first-attempt breakdown
separating JSON-decode/`TypedRule` failures (never reached Semgrep) from genuine Semgrep
rule-parse errors shows Qwen B has only 1/72 failures at the typed-contract layer (one
`pattern_not`-as-string case, correctly rejected by `validate()`) versus 18/72 Semgrep-level
rule-parse errors — meaning most of Qwen B's extra failures are in the embedded pattern TEXT, not
the typed construction itself. Also added: among Qwen B's accepted episodes, the renamed hidden
variant is missed 11 times across 5 cases — concrete, retained motivation for the planned probe
mechanism, not a new result from it.

**Net effect**: the headline complete_success table and resource-cost table were already correct
and remain unchanged. The corrections are to interpretive wording — overclaimed/underclaimed
magnitude and certainty — not to any underlying number.

### 2026-10-13 — Pilot-results correction review closed; three wording details clarified

Checked the revised Tracking section and appended correction against the retained independent
audit. The substantive arithmetic, repeat-count, denominator and inference corrections now match
the evidence. Of the 814 files hashed by that audit, only these two research logs had changed;
all inputs hashed in the pilot allocation remained unchanged. No code, results or benchmark data
were changed, and no model calls, scans or tests were rerun in this documentation-only closure.

Three minor wording corrections were applied directly to the Tracking section: CASE-0340's
bundle has three positive samples, not four; the earlier `scan_errors` metric excluded decode/
schema failures rather than conflating them with scanner errors; and the 207-case power figure
is explicitly an illustrative single-pair scenario, not the required size for the repeated-trial
estimator. No outcome, resource count or error classification changed.

### 2026-10-13 — Item 5 (development probes) built and offline-tested; coverage measured against the pilot's own saved rules; no new model calls

Per the agreed next sequence (build the probes, validate offline, measure coverage using
already-saved rules before spending inference budget), `pipeline/dev_probe.py` now implements
Item 5 end-to-end for all 4 languages (Python via stdlib `ast`; Java/JavaScript/TypeScript via new
`tree_sitter` dependencies). Step 4 (a budgeted C/D pilot) was explicitly NOT run. Full detail in
`Bounded_Investigation_Tracking.md`.

**A real bug was found and fixed before it could produce a false result**: the first version
reconstructed renamed Python source via `ast.unparse()`, which collapses adjacent implicit
string-literal concatenation into one literal — confirmed directly against a real case
(`CASE-0134`) that Semgrep's own parser does NOT perform this collapse, so the reformatting
silently broke a real rule's match for reasons unrelated to renaming. Fixed by switching to
text-span replacement (using each `Name` node's source positions), matching the approach already
used for the tree-sitter languages. Re-verified: the fixed probe now matches the same rule at the
same line it always did.

**Two further findings, new to this module, both handled**: a JS/TS ES6 shorthand object property
(`{token}`) ties an object's key to the variable's name — renaming would silently change the key,
not just the value; excluded via tree-sitter's own distinct `shorthand_property_identifier` node
type, with correct fallthrough to another candidate when one exists (tested directly). Java's CST
does not distinguish a field-access property or method-call name from a genuine local-variable
reference by node type the way JS/TS do — handled via each grammar's own named fields
(`field_access`'s `field` child, `method_invocation`'s `name` child), confirmed directly that
`this.token` survives a `token`-rename untouched.

**18 new offline tests, no model calls.** Probe eligibility across the real 24-case development
set: 15/24 (62.5%) — the 9 ineligible split between 6 pre-existing non-self-contained
`model_context` extraction fragments (unrelated to this module) and 3 with no eligible local
binding after exclusions.

**Coverage measurement, no new model calls**: re-scanned every already-accepted final rule from
all 12 A/B pilot runs against firewalled probe files with real Semgrep. Of 116 accepted episodes
with an eligible probe: **110 pass, 6 fail, 0 false positives**. All 6 failures trace to exactly 3
distinct cases (`CASE-0171`, `CASE-0136`, `CASE-0173`), each independently inspected and confirmed
as the same root cause: the model hardcoded a specific local variable name as literal pattern text
instead of using a Semgrep metavariable there, while correctly using metavariables elsewhere in
the same rule. 5.2% (6/116) of this pilot's accepted episodes would fail this trivial,
independently-constructed probe — a concrete, now-quantified instance of exactly the weakness
Item 5 was designed to surface.

**Not established**: this measures detection potential against already-saved rules, not whether a
model would successfully repair when a probe fails (step 4, not run). No new model calls were
made. C/D's combined accept/stop gate remains unimplemented; a budgeted C/D pilot remains gated on
the user's separate approval to spend new inference budget.

### 2026-10-13 — Probe review confirms coverage but finds behavior-changing transformations

Independent review verifies the latest coverage result from all 116 raw Semgrep outputs:
110 pass, 6 vulnerable misses, 0 patched findings; each scan used 1.177.0 and scanned both targets.
Eligibility reproduces at 15/24 cases. The new 18-test file passes; the full reported 62-test suite
was not rerun by this review. Frozen A/B allocation inputs remain unchanged.

The earlier description of Item 5 as implemented end-to-end is too strong. Executable
counterexamples show scope-incorrect renames, skipped local function call references, patched
parameter/collision failures and an `eval (text)` filter bypass. A Java method name can also change;
invalid patched source can remain eligible. Isomorphism alone does not prove binding preservation.
These remain open implementation findings. Additional gaps concern scan-target verification/FP
counting, immutable input preservation, and undeclared parser dependencies. The C/D gate is still
unimplemented, as already acknowledged.

Also qualify the percentage: 6/116 (5.17%) is among accepted episodes **with eligible probes**;
195 episodes were accepted in total and 79 lack coverage. Of the eleven motivating Qwen B
hidden-renaming misses, this mechanism catches three. All six flagged episodes also miss their
restructured positive. Current saved counts remain valid; successful future feedback repair is
not established.

See `Diagnostic_20261010/Dev_Probe_Implementation_Review_20261013.md` and its retained audit script/
JSON evidence for exact reproductions, recommended fixes and file accounting. No implementation,
test, benchmark, existing probe or historical result was modified; no new inference or real scans
were made. Correct and offline-test the mechanism and combined gate before allocating C/D runs.

### 2026-10-13 — All six review findings fixed and independently reproduced before/after; coverage remeasured

Every reproduction in the review above was run directly against the pre-fix code first (confirmed
broken), then re-run against the fix (confirmed closed) — nothing was accepted on the review's word
alone. Full detail, including each counterexample and exact fix, is in
`Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/dev_probe.py`: Python candidate collection no longer crosses into nested scopes
and excludes any name touched in one (closing the global/nested-`token` counterexample); Java
declaration names (method/constructor/class) are excluded from renaming; JS/TS candidates called as
a bare function are rejected outright rather than having only the call site skipped; the JS
reflection filter is now AST-based (closing the `eval (text)` whitespace bypass) and now also
checks `window`/`globalThis`/`self` bracket access with a non-literal key; the patched-side renamer
now independently re-checks eligibility and collisions against the patched source instead of
reusing the vulnerable side's clearance. Self-discovered while fixing the above: JS/TS `let`/`const`
block scoping was unchecked entirely, and fixing it required switching tree-sitter node-identity
comparisons from `is` to `.id` (tree-sitter's Python bindings return a fresh wrapper object per
attribute access, so `is` can wrongly report `False` for the same tree position). This correctly
drops real-case eligibility from 15/24 to 13/24 — the right cost of a real safety fix.

Fixed in `pipeline/probe_coverage_check.py`: `scan_probe` now requires both targets to appear in
Semgrep's own `paths.scanned` before trusting a result; the FP aggregate is now an explicit
four-way breakdown instead of an AND-gated formula that could hide a patched-only FP; probe inputs
are now written per-run under each coverage namespace (with a SHA-256 recorded) instead of a shared,
overwritable path. `tree_sitter`/`tree_sitter_java`/`tree_sitter_javascript`/`tree_sitter_typescript`
are now pinned in `autogrep/requirements.txt`.

Added 6 behavior-executing regression tests (Python `exec()`, JavaScript via a real `node`
subprocess, Java via real `javac`+`java`), directly answering the review's central ask that
isomorphism alone does not establish correct binding preservation. Full suite now passes 68/68
(62 prior + 6 new), rerun in full.

Coverage remeasured in a new namespace (`_probe_coverage_20261013T002146736021Z`), no new model
calls: eligibility 13/24; of 195 total accepted episodes, 104 now have an eligible probe (down from
116, entirely accounted for by the two cases that lost eligibility); of those, 98 pass and the same
6 fail as before (6/104 = 5.77%; 6/195 = 3.08% of all accepted episodes). The six failing episodes
are unchanged by case/model/repeat, confirming this specific finding was never an artifact of the
mechanism bugs fixed here. The combined C/D gate and any new budgeted inference remain unimplemented
and ungated on separate approval, unchanged from before.

### 2026-10-13 — Probe follow-up review: counts verified; two semantic findings still open

Independently verified 24/24 probe tests (full 68-test suite not rerun by the reviewer), seven
corrected prior transformation fixtures, scanner target checks, four-way FP accounting, pinned
dependencies and immutable per-run probe files with matching hashes. The latest 104 raw scan
outputs reproduce 98 passes, the same 6 misses and zero patched findings, with both targets scanned
under Semgrep 1.177.0. Eligibility is 13/24; 91 of 195 accepted episodes are uncovered. All twelve
removed covered episodes were passes. Historical result/input hashes remain unchanged except for
the four implementation/test/requirements files intentionally updated by the author.

The claim that all high-priority semantic findings are fixed is premature. Executable follow-up
fixtures show unsafe Python comprehension/global and default-argument/global renames, and a Java
block-local/field rename that breaks compilation. The patched path can still rename a global
reference with no local declaration, and the previous invalid-patched-source case still returns an
eligible pair. These are two remaining root issues: binding identity and patched-pair validation.
They do not demonstrate contamination of the six retained coverage misses.

Full evidence, precise fixes and two minor test/documentation inaccuracies are recorded in
`Diagnostic_20261010/Dev_Probe_Followup_Review_20261013.md` and its audit script/JSON. This review
changed research records only and made no model calls or real scans. C/D gate integration,
deterministic caching and inference remain deferred; close the semantic gaps before declaring the
builder complete.

### 2026-10-13 — Both remaining semantic findings fixed and independently reproduced before/after; documentation precision issue fixed; coverage remeasured a third time

Every reproduction above was run directly against the pre-fix code first (confirmed broken,
matching the exact original-vs-probe values reported), then re-run against the fix (confirmed
closed). Full detail in `Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/dev_probe.py`: Python comprehensions (`ListComp`/`SetComp`/`DictComp`/
`GeneratorExp`) are now treated as scope boundaries, closing the comprehension-target/global-return
mis-rename; a new `_py_names_in_signature` excludes names in parameter defaults/annotations,
closing the default-value/global mis-rename; the Java block-scope check's unconditional
`return False` for Java -- a real bug, not an intentional design decision -- is removed and
generalized to Java's `local_variable_declaration`, closing the inner-block-local/field mis-rename
(confirmed by actually compiling and running the original method, not just structural inspection).
Both patched-side renamers now require `old_name` to be one of the PATCHED function's own
independently-eligible local candidates (reusing the exact same candidate functions the vulnerable
side already uses) rather than merely appearing as some Name/identifier node regardless of context,
closing the global-reference mis-rename; and an unparseable patched function now makes the whole
case ineligible instead of silently serving the original unparseable text as an eligible probe,
while a parseable-but-variable-absent patched function still correctly falls through to the
legitimate "doesn't need renaming" outcome.

Fixed in `pipeline/tests/test_dev_probe.py`: the JS block-scope fixture flagged by the review as
not matching its own prose (it renamed only the inner declaration, not the outer reference, so it
never actually crashed) now renames both occurrences -- faithfully replaying what the pre-fix
code actually did -- and genuinely raises `ReferenceError`, confirmed via a real `node` run.

Added 6 new tests (structural-ineligibility plus behavioral-execution confirmations for all three
scope sub-cases and both patched-side fixes). Full suite now passes **74/74** (68 prior + 6 new),
rerun in full.

Coverage remeasured a third time (`_probe_coverage_20261013T005231042394Z`), no new model calls:
eligibility 11/24 (down from 13/24 -- `CASE-0116` and `CASE-0193`, both Java, lost eligibility to
the now-correct block-scope check, having been eligible only because that check was previously a
no-op for Java); of 195 total accepted episodes, 100 now have an eligible probe (down from 104);
of those, 94 pass and the same 6 fail as every prior round (6/100 = 6.0%; 6/195 = 3.08% of all
accepted episodes; 95/195 uncovered). The six failing episodes are unchanged by case/model/repeat
across three independent rounds of mechanism correction now -- strong evidence this specific
finding reflects genuine model behavior, not a builder artifact. The combined C/D gate and any new
budgeted inference remain unimplemented and ungated on separate approval, unchanged from before.

### 2026-10-13 — Third probe review verifies prior fixes and coverage; binding safety remains open

Independent verification confirms 30 probe tests pass, the previous follow-up counterexamples are
fixed, and the corrected JS block fixture demonstrates its stated failure. The full 74-test suite
was not rerun by this review. All 100 raw scanner outputs reproduce 94 passes, the same six misses
and zero patched findings, with Semgrep 1.177.0 and both targets scanned. Eligibility is 11/24;
generated source bytes and hashes match. Historical evidence remains unchanged.

Two further accepted transformations still change behavior: Python exception-handler bindings are
not renamed with their references (ValueError(7) becomes integer 1), and a JavaScript default's
global reference is renamed with a body-local variable (11 becomes ReferenceError). These keep
the lexical-binding safety finding open; they do not invalidate the observed six saved-rule misses.
The invalid-patched-source and prior specific scope reproductions are fixed. Stability across
builder revisions is not independent model-trial replication.

See `Diagnostic_20261010/Dev_Probe_Round3_Review_20261013.md` and its executable audit/JSON evidence.
Only research records were changed; no implementation/test/result edits, new inference or real
scans. C/D gate work, caching and inference remain deferred.

### 2026-10-13 — Both round-3 binding-safety gaps fixed and independently reproduced before/after; coverage remeasured a fourth time with unchanged numbers

Both reproductions were run directly against the pre-fix code first (confirmed broken, matching
the exact values reported), then re-run against the fix (confirmed closed). Full detail in
`Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/dev_probe.py`: a new `_py_exception_bound_names` excludes any name ever used as
an `except ... as <name>:` binding from candidacy -- that binding is a plain string attribute
(`ExceptHandler.name`), not an `ast.Name` node, so it was invisible to text-span replacement by
construction, closing the exception-handler mis-rename (original `ValueError(7)` was becoming
plain `1`). A new `_ts_names_in_signature_defaults` excludes any name used in a JS/TS parameter
default value expression from candidacy on both sides (the tree-sitter languages had no equivalent
of the earlier Python signature-defaults fix at all), closing the default-argument/body-local
conflation (original `11` was becoming a `ReferenceError`).

Added 2 regression tests (one executing via Python `exec()`, one via a real `node` subprocess).
Full suite now passes **76/76**, rerun in full.

Coverage remeasured a fourth time (`_probe_coverage_20261013T011301679535Z`), no new model calls:
every number is **unchanged** from the prior round (eligibility 11/24; 100/195 accepted episodes
covered; 94 pass, the same 6 fail, 0 patched findings) -- neither of this round's two bugs is
exercised by any of the 24 real development-set cases, confirmed by rerunning rather than assumed.
The combined C/D gate and any new budgeted inference remain unimplemented and ungated on separate
approval, unchanged from before.


### 2026-10-13 — Known probe findings verified closed, with explicit limits on the closure

Independently verified the two latest fixes on vulnerable and patched paths, a typed TypeScript
default fixture, and 32 passing probe tests (full author-reported 76-test suite not rerun here).
Recounted all 100 latest saved scanner outputs: 94 passes, the same six misses, zero patched
findings; both targets scanned under Semgrep 1.177.0. Eligibility remains 11/24; source bytes and
hashes match; 100/195 accepted episodes are covered and 95 remain uncovered.

This closes the concrete known reproductions, not all possible binding forms. A finite,
grammar-derived admissibility audit is recommended next, with explicit supported/rejected forms
and independent executable fixtures. It has not been performed in this closure. C/D integration,
caching and inference remain deferred. Full detail and exact file accounting are in
`Diagnostic_20261010/Dev_Probe_Known_Findings_Closure_20261013.md` and its audit/JSON evidence.
No implementation or saved results were changed; no model calls or real scans were made.

### 2026-10-13 — Bounded binding-form audit completed; 4 further bugs found and fixed via systematic enumeration, not another external counterexample

Built the requested deliverables (supported-syntax table per language, independent tests, per-case
review, frozen versions) in `Diagnostic_20261010/Dev_Probe_Binding_Form_Audit_20261013.md`. Before
writing the table, systematically inspected the actual AST/CST node types against the current
implementation, surfacing 4 more real bugs -- each independently reproduced (broken before, fixed
after) before being accepted, this time self-discovered rather than externally supplied.

Fixed in `pipeline/dev_probe.py`: Python nested `def`/`class` statement names, import aliases, and
`match`/`case` capture patterns -- all the same root-cause class as the earlier `except...as` fix
(a declaration site that is a plain string attribute, not an `ast.Name` node, left stale while
other same-spelled references get renamed). The JS/TS equivalent (nested `function`/`class`
declaration names) was also found and fixed. Also systematically checked and confirmed SAFE, by
direct execution rather than assumption: Python tuple/list unpacking and the walrus operator; JS/TS
destructuring, `catch` parameters, and `for-of`/`for-in` loop variables; Java local classes and
`catch` parameters (ruled out by Java's type/value identifier distinction or an outright compile
failure).

Added 8 tests. Full suite now **82/82 passing**. Coverage remeasured in a fresh namespace, no new
model calls: numerically identical to the pre-audit run (11/24 eligible; 100/195 covered; 94 pass,
6 fail, 0 patched findings; the same 6 failing episodes) -- none of the 4 new bugs occurs in any of
the 24 real development cases. Frozen versions recorded: `dev_probe.py` SHA-256, Python 3.14.4,
Semgrep 1.177.0, and the four `tree_sitter*` package versions.

This is a documented, test-backed boundary, not a completeness proof -- a few rows (JS/TS
destructuring as a future candidate, Python 3.12+ generics) are analyzed but not independently
executed, stated as such rather than assumed safe. The combined C/D gate, caching, and any new
budgeted inference remain unimplemented and ungated on separate approval, to begin only after this
audit, per the user's own ordering.


### 2026-10-13 — Binding-form audit reviewed: verified evidence, unresolved acceptance-boundary gaps

Verified 38 probe tests, the frozen builder hash and versions, all 24 case decisions and all 22
probe source hashes. Recounted the latest 100 raw scans: 94 pass, same six miss, zero patched
findings; coverage stays 11/24 cases and 100/195 accepted episodes. Full 82-test suite was not
rerun by this review. Historical inputs remain unchanged except intentional builder/test edits.

Audit closure is not yet supported: a JS destructuring declaration or assignment sharing the
chosen candidate name produces an accepted 99-to-1 behavior change despite its table's safe
classification. A Python decorator explicitly outside the checked boundary is still accepted and
renamed into NameError. The per-case report lacks the requested exact edit spans/independent
binding review and overwrites a fixed output; several disposition rows have no independent tests.
Specific findings, reproductions and completion criteria are in
`Diagnostic_20261010/Binding_Form_Audit_Review_20261013.md` and its audit/JSON evidence. The actual
probe test increase is six (32 to 38), matching 76 to 82 overall.

The saved six misses remain verified; these counterexamples do not demonstrate contamination of
those results. Enforce a bounded supported-syntax policy or restrict the pilot to explicitly
reviewed immutable probes, and finish the case-edit audit before closure. This review changed
research records only; no model calls, real scans, implementation changes or C/D work occurred.

### 2026-10-13 — All three binding-form-audit review findings fixed and independently reproduced before/after; audit document and per-case artifact corrected

Both High findings were run directly against the pre-fix code first (confirmed broken, matching
exact values reported), then re-run against the fix (confirmed closed). Full detail in
`Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/dev_probe.py`: a shorthand JS/TS destructuring binding (`var {token}=obj`)
sharing a name with an outer `var` declaration was left stale while the declaration and other
references got renamed (original 99 became 1) -- fixed by extending `_ts_has_shorthand_property`
to also cover the destructuring-shorthand node type (array/renamed-key destructuring were
separately confirmed to remain safe, not touched by the fix). Python decorator expressions,
explicitly listed as out-of-scope in the audit document with no actual enforcement, were renamed
alongside a same-named body local, raising `NameError` at definition time -- fixed by extending
`_py_names_in_signature` to also walk `func.decorator_list`.

Rewrote `pipeline/probe_binding_audit_report.py` from a decision inventory (case/old_name/new_name
only) into a genuine edit audit: per-case source hashes, line-level diffs of every actual edit, a
per-raw-candidate exclusion classification for ineligible cases, and a new timestamped output file
every run (no longer overwrites one fixed path). Added 8 tests for previously-unlinked table rows
(augmented/annotated assignment, for/with targets, global/nonlocal, Java parameters, nested JS
`var`) plus the two bug reproductions. Full suite now **90/90 passing** (82 prior + 8 new).

Coverage remeasured again, no new model calls: every number is unchanged across all three runs
this session (eligibility 11/24; 100/195 covered; 94 pass, 6 fail, 0 patched findings; same 6
failing episodes). The audit document itself was corrected in place (not silently rewritten) with
an explicit note on what changed and why, including the review's central lesson stated directly:
being listed as out-of-scope is not the same as being safely ignored by the builder. The combined
C/D gate, caching, and any new budgeted inference remain unimplemented and ungated on separate
approval, unchanged from before.


### 2026-10-13 — Binding-audit findings closed for the reviewed development inputs

Verified 46 passing probe tests (full author-reported 90-test suite not rerun here), both concrete
bug fixes, all 24 timestamped edit-report rows, and input/output hashes. Independently checked
exact identifier edit spans and manually inspected both sides of all 11 eligible pairs. Saved
coverage remains 94 passes, the same six misses and zero patched findings out of 100 covered
accepted episodes; 95 of 195 accepted episodes are uncovered. All saved scans report Semgrep
1.177.0, no errors and both targets scanned.

Closure is scoped to the reviewed development inputs, not arbitrary source. The audit front
matter now describes actual enforced exclusions rather than claiming all unknown syntax is
rejected. Offline C/D integration can proceed as a separate task with hash-bound reviewed probe
artifacts and explicit acceptance, fallback, error and budget checks. New inputs require renewed
review. No C/D implementation, caching or inference was performed here.

Corrected stale Tracking prose: five missing-link tests, eight total added (not eleven); the
latest two fixes leave real-case probes unchanged, but earlier scope fixes reduced eligibility
15 to 13 to 11 and the initial formatting bug affected CASE-0134. Earlier historical entries are
preserved here. Full evidence and file accounting:
`Diagnostic_20261010/Binding_Form_Audit_Closure_20261013.md`. Only research records changed;
no implementation/test/dependency/benchmark/result edits, model calls or real scans.

### 2026-10-13 — C/D's combined acceptance gate and deterministic probe caching implemented and offline-tested, no model calls

Built `pipeline/combined_gate.py` (the corrected 4-path accept/stop logic from
`Controlled_2x2_Protocol_Draft_20261012.md` §4: A/B accept on `visible_correct`; C/D with an
eligible probe accept only when `visible_correct` AND both probe checks pass; C/D with no eligible
probe falls back to visible-only, explicitly flagged; a probe scan error is always a failed check,
never silently treated as "no eligible probe") and `pipeline/probe_cache.py` (deterministic
per-case probe caching keyed on case-input hashes AND `dev_probe.py`'s own content hash, so a
cache entry built under an older reviewed builder version can never be silently served as current
-- a mismatch rebuilds by default, or raises in `strict=True` mode).

Found and fixed one real design gap while writing the tests, not assumed from the design doc: the
gate initially required `probe_checks` whenever a case was probe-eligible, regardless of
`visible_correct` -- but the protocol only evaluates probes AFTER a rule passes the visible pair,
so an attempt that fails visible should need no probe data at all. A realistic repair-then-accept
trajectory test caught this; fixed via an explicit short-circuit.

Added 20 offline tests covering the closure's six specified scenarios (repair on visible-pass/
probe-fail, accept-and-stop on all-checks-pass, budget exhaustion, ineligible-case fallback, probe
scan-error handling, cache mismatch) plus resource accounting (visible/probe scan counts, repair
calls, correctly excluding a probe scan for any attempt that never reached the probe step) and two
full multi-attempt episode simulations. Full suite now **110/110 passing** (90 prior + 20 new). No
wiring into the live `diagnostic_v2.py` retry loop yet -- deferred until C/D inference is
separately approved, since there is no reason to touch the live model-calling path before that
budget decision. No model calls, no real Semgrep scans, no C/D inference.


### 2026-10-13 — C/D standalone gate/cache reviewed; experimental readiness remains open

The 20 new tests pass independently (full author-reported 110-test suite not rerun here). Three
reproduced gaps qualify the preceding implementation claim: strict cache hits return modified
probe payloads without comparison to reviewed artifact hashes; language is missing from cache
identity (TypeScript request returns a JavaScript hit), as are frozen parser/runtime identities;
and decision-based resource totals count a decode-failed generation as a visible scan. The last
finding was reproduced through the real runner with all model/scanner calls mocked.

A current builder hash is not proof of review: strict mode also builds unseen cases. The prior
fixed-input closure still requires a reviewed manifest and verification of source/builder/parser/
probe identity. Standalone gate simulations do not replace integration through the actual retry
and feedback loop. That integration can be built and tested offline before inference approval.

Normal gate paths pass. Unknown-condition and over-budget inputs need boundary validation; no
actual production budget overrun was demonstrated. Failed ineligible episodes also need explicit
eligibility/reason metadata beyond the helper's accepted-fallback flag.

Next: resolve cache/provenance and event-accounting gaps, then complete mocked runner integration.
No implementation or historical result changed; no model calls or real scans. Full evidence and
file accounting: `Diagnostic_20261010/CD_Gate_Cache_Review_20261013.md`. Earlier entries remain
preserved; this is a qualification of readiness, not a revision to any historical success rate.

### 2026-10-13 — All three CD gate/cache findings fixed and independently reproduced before/after; real retry-loop integration built and tested with mocked model/scanner

All three findings were run directly against the pre-fix code first (confirmed broken, matching
the review's exact reproductions), then re-run against the fix (confirmed closed). Full detail in
`Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/probe_cache.py`: cache entries now store a `payload_sha256` verified on every
read, closing the tampered-payload-served-as-hit gap (reproduced: an edited `vulnerable_probe`
string was returned as a `"hit"` even in strict mode); the cache key now includes `language` and
the four tree-sitter/Python versions, closing the wrong-language-probe-served gap (reproduced: a
TypeScript request against a JavaScript-cached entry returned the JS result). Added a separate,
stricter `build_experiment_manifest_entry()`/`load_probe_for_experiment()` tier for the fixed
24-case selection, validating against a frozen manifest rather than just internal cache
self-consistency.

Fixed in `pipeline/combined_gate.py`: resource accounting previously assumed one scan per attempt,
but a decode/parse failure never reaches `scan()` at all -- reproduced (2 calls, 1 visible scan;
the old summarizer either overcounted scans or undercounted repairs). Fixed via a new
`AttemptEvent` record distinguishing "generation failed, no scan" from "generation succeeded, a
decision was made," plus an explicit caller-supplied `probe_scanner_invocations` field instead of
inferring invocation count from `probe_checks`. Also added condition/attempt-bounds validation and
an independent `probe_eligible` field on `GateDecision`, per the review's hardening notes.

Built the real retry-loop integration the review recommended as the explicit next step: new
`diagnostic_v2.run_model_case_cd()`, a SEPARATE function from `run_model_case()` (which stays
byte-for-byte untouched -- its own regression suite reruns unchanged, confirmed rather than
assumed). 9 new tests exercise the real generation/scan/probe-scan loop with mocked model/scanner
dependencies (the same mocking pattern already established for `run_model_case()`), covering probe
feedback reaching the next call, accept-and-stop, budget exhaustion, ineligible fallback, probe
scan errors, hidden-result gating, and the decode-failure resource-accounting scenario through the
real runner.

**29 new tests this round**, full suite now **133/133 passing**. No model calls, no real Semgrep
scans, no C/D inference. The frozen experiment manifest mechanism is built and tested, but no
concrete manifest file for the real 24-case selection has been generated yet -- that remains the
natural next step before any real C/D run.


### 2026-10-13 — C/D integration follow-up: three prior fixes verified, remaining integration gaps

The preceding entry's test increment is 23, not 29: 110 + 14 + 9 = 133. Tracking is corrected in
place; the historical entry here remains preserved. Independently verified 63 focused tests pass
(34 gate/cache, 9 integration, 20 existing diagnostic regressions); full 133-test suite not rerun.

Direct reproductions confirm the old cache-integrity, language/parser identity and decode-failure
accounting findings are fixed. The new runner nevertheless accepts independently supplied probe
paths without binding their bytes to the validated object, treats `probe_result=None` as legitimate
ineligibility, and imports the probe module on A/B's module path. Those three findings remain
open. Keeping the A/B function body unchanged does not preserve module import isolation.

A production adapter and concrete frozen manifest are still absent. A probe timeout also escapes
before attempt/episode recording; define durable interruption/error handling without a fresh call
budget (raw capture may independently retain consumed-call evidence). These checks and manifest
preparation are offline engineering, not inference spending. No C/D outcome was measured.

Full reproduced evidence, remedies and exact file accounting:
`Diagnostic_20261010/CD_Integration_Followup_Review_20261013.md`. No implementation, permanent test,
dependency, historical result or probe artifact was changed by this review; no model calls or real
scans. Only research records/audit artifacts were added or updated.

### 2026-10-13 — All four integration follow-up findings fixed and independently reproduced before/after; test-count arithmetic corrected

All four issues were run directly against the pre-fix code first (confirmed broken, matching the
review's exact reproductions), then re-run against the fix (confirmed closed). Full detail in
`Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/diagnostic_v2.py`: (1) the runner now hashes and compares the actual probe
files on disk against the validated `probe_result`'s text before any scan, raising
`ProbeMaterializationError` on a mismatch -- closing the gap where a tampered probe file reached
the scanner unverified and the episode was still accepted; (2) `probe_result` must now be a
genuine `ProbeResult`/`ProbeIneligible` instance with matching case/language identity --
`probe_result=None` previously fell through to an accepted visible-only fallback
indistinguishable from a real reviewed ineligibility, now raises immediately; (3) `combined_gate`/
`dev_probe` imports moved from module level to local (inside `run_model_case_cd()` only), closing
the gap where plain A/B runs imported the probe builder and tree-sitter grammars merely by
importing `diagnostic_v2`; (4) a probe scan `subprocess.TimeoutExpired` is now caught and
converted into an ordinary scan-error result instead of propagating uncaught and skipping
`attempt.json`/`episode.json` entirely.

Updated 9 existing tests to use real materialized probe files (replacing fake `/dev/null/...`
paths that could never have caught Finding 1) and added 7 new tests directly reproducing each
issue through the real runner. Full suite now **140/140 passing** (133 prior + 7 new).

Also corrected this session's second test-count arithmetic slip: "29 new tests" (previous round)
should have been **23** (110 to 133, i.e. 14+9) -- verified via `pytest --collect-only` this time
rather than computed from memory.

No model calls, no real Semgrep scans, no C/D inference. Still outstanding, per the review's own
ordering: the concrete frozen manifest for the real 24-case selection, and `main()`'s CLI adapter
connecting the manifest loader/materialization/`run_model_case_cd()` with construction-mode
binding for C/D -- neither performed this round.


### 2026-10-13 — C/D fixes verified with one materialization qualification

Independent verification: 70 focused tests executed and passed; 140 tests collected across the
seven intended files. Collection alone does not establish 140 passing executions. The new state/
identity checks, A/B import isolation, ineligibility-reason retention and probe-timeout recording
are verified, including all-timeout exhaustion within three calls.

The preceding entry's file-verification closure is partial: existing mismatches are rejected,
but verification runs once before generation. Synthetic changes during generation or between
attempts still reach the scanner while the episode records the earlier hash. CRLF normalization
also means the recorded text hash can differ from the scanned file's byte hash. No historical
corruption or actual Semgrep behavioral difference is claimed.

Next: close that boundary using immutable per-run files, raw-byte checks before each use and
accurate invocation provenance, then prepare the concrete manifest and full CLI adapter offline.
Full evidence and file accounting: `Diagnostic_20261010/CD_Materialization_Followup_Review_20261013.md`.
No implementation, tests, dependencies, historical results or existing probes changed; no model
calls or real scans. Prior log entries remain preserved.

### 2026-10-13 — Materialization-verification gap fixed and independently reproduced before/after

All three reproductions (file changed during generation; file changed between attempts; CRLF-vs-LF
hash disagreement) were run directly against the pre-fix code first (confirmed broken), then
re-run against the fix (confirmed closed). Full detail in `Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/diagnostic_v2.py`: every byte comparison switched from `Path.read_text()`
(which normalizes CRLF to LF, closing the hash-disagreement gap outright) to `Path.read_bytes()`.
After the initial verification, the bytes are copied into a freshly-created, exclusively-owned
per-episode snapshot directory and every subsequent probe scan reads only from that snapshot --
closing the TOCTOU gap where the caller-supplied files could change after the one-time startup
check. Each scan also re-verifies the snapshot's own bytes defensively; any detected drift is
routed through the same established probe-scan-error path a timeout already uses, never a new
fallback or a reset budget.

Added 3 tests reproducing each scenario through the real runner. Full suite now **143/143
passing** (140 prior + 3 new), verified via `pytest --collect-only` as well as a full run. No
model calls, no real Semgrep scans. Still outstanding, per the review's explicit ordering: the
concrete frozen manifest and `main()`'s CLI adapter, neither performed this round.


### 2026-10-13 — Snapshot fixes independently verified; filename and accounting follow-ups

Verified the three preceding materialization scenarios as fixed using the actual runner with
mocked generation/scanning. Independently executed 73 affected tests (all pass); collected 143
across the seven intended files, without rerunning the complete suite.

Two bounded issues remain in the new code: inputs from different directories with equal basenames
overwrite each other in the single snapshot directory, and snapshot-integrity rejection counts
as a scanner invocation despite skipping the scanner. Reproduced zero actual probe invocations
but three reported scans. Current historical coverage files have distinct basenames; no changed
historical outcome is claimed. Use distinct snapshot destinations and increment scan counts only
when a call occurs, including timeouts but excluding pre-scan rejection.

Carry these fixes into the offline frozen-manifest/CLI work. Full reproducible evidence and file
accounting: `Diagnostic_20261010/CD_Snapshot_Review_20261013.md`. Only research records and audit
artifacts changed in this review; no implementation, permanent tests, inference or real scans.

### 2026-10-13 — Both snapshot review findings fixed and independently reproduced before/after

Both reproductions were run directly against the pre-fix code first (confirmed broken), then
re-run against the fix (confirmed closed). Full detail in `Bounded_Investigation_Tracking.md`.

Fixed in `pipeline/diagnostic_v2.py`: snapshot destinations now use role-specific subdirectories
(`_probe_snapshot/vulnerable/`, `_probe_snapshot/patched/`) instead of one shared directory keyed
only on caller-supplied basenames -- closing a collision where two valid, independently-supplied
inputs sharing a basename silently overwrote each other. `scanner_invocations` now increments only
inside the actual-scan branch, not the defensive integrity-guard branch that deliberately skips
the scan -- closing a miscount where zero real scanner calls were reported as three.

Added 2 tests reproducing each through the real runner. Full suite now **145/145 passing** (143
prior + 2 new), confirmed by both a full run and `pytest --collect-only`. No model calls, no real
Semgrep scans. Still outstanding: the concrete frozen manifest and `main()`'s CLI adapter.


### 2026-10-13 — Bounded manifest/CLI build started; concurrent-edit conflict awaiting coordination

Added `pipeline/cd_experiment.py` and froze `benchmark/diagnostic_20261010/dev_probe_manifest_v1.json`
against the existing pinned reviewed selection, edit-report, builder and parser identities. All 24
source/disposition records match; 11 eligible probe pairs match reviewed hashes and 13 cases retain
explicit ineligibility. Freeze SHA-256:
`771400b84983a11b4edb97129e454ab860208b7727e7316a2c4b1689e093104f`.

Added `pipeline/tests/test_cd_cli.py` for complete offline C/D CLI trajectories (real prompt/parser,
raw capture, cache/manifest and snapshot paths; fake provider/scanner; real sockets prohibited),
and began a `--condition C|D` adapter in `pipeline/diagnostic_v2.py`. During testing, another writer
added a separate `--use-probes` adapter, manifest builder and adapter tests to the same workspace.
Both additions now register `--probe-manifest`; CLI tests fail on that duplicate option (10 failed,
76 passed), so this is NOT a completed or passing integration. The separately produced manifests'
24 case entries agree exactly.

Preserved the starting source and observed concurrent state in
`Diagnostic_20261010/CD_CLI_Build_20261013/` (paths relative to Research_Log); its
`Implementation_Status.md` records scope, files, evidence and pending work. Asked the user to pause
the other editor and choose consolidation before further shared-runner edits. No other writer's
implementation was removed. No model calls or real Semgrep scans occurred. Offline preparation is
partial; no new C/D inference or research result is implied.

### 2026-10-13 — Bounded manifest/CLI task completed: concurrent-session collision resolved, all four completion criteria verified

A second concurrent process, independently given the same bounded task, had built a separate,
more rigorous implementation (`pipeline/cd_experiment.py`, the frozen manifest, `test_cd_cli.py`,
a `--condition C|D` CLI adapter) and left it coexisting in `diagnostic_v2.py` with this session's
own earlier, weaker attempt (`run_cd_case_from_manifest`, `--use-probes`) -- a literal duplicate
`argparse` flag registration made the CLI crash on every invocation. Compared both designs on
merits (the other process's manifest pins exact reviewed selection/report/builder/parser hashes,
not just re-derivation; its CLI rejects conflicting flags outright rather than silently
overriding) and consolidated on the stronger one, removing this session's own superseded code
(`build_cd_probe_manifest.py`, `test_run_cd_case_from_manifest.py`, the stale manifest JSON, the
`run_cd_case_from_manifest` function/`--use-probes` path) and fixing the duplicate-flag bug that
blocked the merge. Full detail in `Bounded_Investigation_Tracking.md`.

All four completion criteria verified against the consolidated codebase: (1) the frozen 24-case
manifest (11 eligible/13 ineligible, hash-pinned) reproduces exactly via
`cd_experiment.build_frozen_manifest()`; (2) the CLI's `--condition C|D` forces the correct
construction mode and corrected acceptance, rejecting any conflicting explicit flag; (3)
`test_cd_cli.py`'s 11 tests verify the complete offline path, including one full mocked 24-case
run per condition covering acceptance/repair/exhaustion/ineligible-fallback/scan-error together,
plus a preflight dry run that prepares every probe snapshot/cache entry without any model/network
access; (4) this entry records the final configuration and file changes. Full suite now
**156/156 passing**, confirmed by both a full run and `pytest --collect-only`.

No other session was reachable via `ListAgents` to notify directly. Any live C/D inference run
remains a separate, explicitly-approved budget decision. Per the user's own direction, the next
step is paper synthesis, not further infrastructure refinement absent a concrete validity-threatening
defect.


### 2026-10-13 — Consolidated C/D build independently verified; coordination resolved

The paused concurrent session has now verified the consolidated implementation. Its coordination
question is no longer pending: the duplicate CLI option/competing adapter are absent, and the
retained `--condition C|D` path is working. Independently ran 86 relevant tests: all pass (9.91s),
including both full mocked 24-case CLI runs and the existing runner/gate/diagnostic regressions.
Independently collected 156 tests; the other editor's full 156-pass execution was not rerun here.
Manifest verification succeeds with the unchanged SHA-256
`771400b84983a11b4edb97129e454ab860208b7727e7316a2c4b1689e093104f`, 24 cases / 11 eligible / 13 ineligible.
The A/B `run_model_case` function source exactly matches this task's saved starting copy.

All four bounded completion criteria are now met. Preflight prepares validated caches/materialized
inputs; per-episode snapshots are created by the runner. Mocked runs are engineering validation,
not evidence of C/D E2E improvement. Stop infrastructure refinement and proceed to paper synthesis;
live C/D inference remains a separate budget decision. No confirmation-design decisions or automatic
resumption implementation are implied by this development-only completion.

The prior pending status has a resolved banner, with historical conflict/failure evidence retained.
Full evidence, final scope/limits and file accounting:
`CD_CLI_Build_20261013/Completion_Verification.md` (under Diagnostic_20261010). Only research records
changed in this verification; no implementation/test changes, model calls or real Semgrep scans.


### 2026-10-14 — C/D development pilot allocated; live inference pending

Prepared the next 12 C/D runs (two models × two conditions × three repeats), 288 episodes,
at most 864 model calls, in fresh output namespaces. No inference was performed. Both real
no-inference preflights pass with Semgrep 1.177.0 and the frozen 24-case / 11-eligible manifest.
The initial sandbox certificate-access failure is preserved; successful retries used fresh
C/D namespaces outside the sandbox. Provider connectivity/credentials were not tested.

Comparability verification checked all 209 A/B input hashes: 208 unchanged, with only the
expected diagnostic_v2.py integration change. Regenerated first-call prompts match all 288
saved A/B requests exactly. Record the remaining limitations: C/D uses fixed canonical case
order rather than A/B's per-repeat shuffle, and runs in a later provider time batch. Results
will be descriptive C−A and D−B comparisons within each model, using per-case repeat means
and the all-24 denominator, with the 11 eligible cases shown separately.

Full allocation, evidence, launch/inspection instructions and file accounting:
`Research_Log/Diagnostic_20261010/CD_Pilot_Allocation_20261014_v1/Readiness.md`.
Created the offline preparation script and allocation/verification/commands/readiness files;
updated the diagnostic README and both research logs, with generated preflight/command
artifacts retained. No source/test implementation or historical results changed. The prior
156-test suite was not rerun for this preparation-only work. Separate inference-budget
authorization remains pending; this entry does not claim any C/D improvement or resolve the
confirmation protocol decisions.


### 2026-10-14 — C/D pilot authorized; first launch blocked by missing credential

The user explicitly authorized execution of the prepared 12-run C/D pilot, within the
864-model-call ceiling. Reverified every pinned allocation input and all twelve unused
output destinations. GPTLAB_API_KEY is missing from the execution environment;
OPENAI_API_KEY is present (presence only, no provider connectivity/authentication check).
Executed the exact first allocated Qwen/C command through diagnostic_audit.py. It exited 1
at the credential gate, before any model request or output-directory creation. Preserved
command evidence: commands/20261013T231747936117Z_cd_dev_20261014_v1_qwen3_r1_c.log
under Research_Log/Diagnostic_20261010. No inference budget consumed, no experimental
failures measured, no reordering or alternate-model runs attempted.

Created CD_Pilot_Allocation_20261014_v1/Execution_Status.json; updated Commands.md,
Readiness.md, the diagnostic README and both research logs; appended audit events with
file hashes. The original allocation/verification artifacts remain unchanged. No source,
test, benchmark or historical result changes. Once the credential is made available,
recheck pins and execute command 1 using the same still-unused destination; approval
persists and does not need to be requested again.


### 2026-10-14 — Authorized C/D pilot started after local credential setup

Confirmed the user-created external credential file exists, is nonempty and mode 600,
without displaying or logging its contents. All allocation hashes still match and all
live destinations were unused. Retried the exact first allocated command using the key
only in its subprocess environment, outside the sandbox for provider/Semgrep access.
The provider credential gate passed and Qwen/C repeat 1 began. The earlier missing-key
command log is retained; it consumed no model calls.

Created `Research_Log/Diagnostic_20261010/audit_cd_pilot_20261014.py` for offline per-run
checks and final paired descriptive comparisons, and `execute_cd_pilot_20261014.py` for
the unchanged allocated commands 2–12, sequentially, only after run 1 verifies. The
coordinator checks pins/fresh outputs and caps, records per-run checkpoints, and pauses
on provider/process/verification failure; it does not resume partial episodes or reset
budgets. Its provider-error guard records possible in-flight-call uncertainty if it must
interrupt. No experimental implementation, prompts, benchmark or allocation changed.
Updated execution status, commands/readiness notices, these two logs and audit events.
Completion/results will be recorded separately after verified runs.

### 2026-10-14 — C/D development pilot results: descriptive, not confirmatory, real model-by-intervention heterogeneity

All 12 C/D runs (24 cases x 2 models x 3 repeats, 288 episodes) completed with real model calls
and real Semgrep scans. Full breakdown in `Bounded_Investigation_Tracking.md`. Headline, computed
directly from the 12 `summary.json`/288 `episode.json` files:

Complete-success rate: qwen3-coder:30b A=25.0% B=29.2% C=25.0% D=31.9% (construction +5.6pts,
feedback +1.4pts, both positive and compounding in D); gpt-4o A=22.2% B=23.6% C=23.6% D=20.8%
(construction -0.7pts, feedback -0.7pts, D is gpt-4o's worst cell). The two models disagree in
sign on every contrast -- the interaction the protocol's analysis plan flagged as plausible, not
noise.

Per-case detail: qwen3's entire A->C contrast involves zero case changes (the aggregate tie is the
literal same cases, not cancellation); its B->D and A->B gains each trace to exactly one flipped
case (CASE-0063, CASE-0340). gpt-4o shows genuine churn in both directions on every comparison,
consistent with its near-zero aggregate effects being real cancellation, not stability. Resource
cost: qwen3's D cell spent ~70% more repair calls than C for its gain; gpt-4o's D cost about the
same as C despite scoring worse. Zero probe scan errors across 864 real probe-eligible Semgrep
invocations; eligibility held at the frozen 11/24 in every run; every fallback acceptance was
correctly flagged.

This is descriptive development-set data, not a confirmatory result -- same standing caveat as the
A/B pilot. No confirmation-set decision is resolved by it, and no further inference was spent
beyond the already-approved 288-episode allocation.

### 2026-10-14 — Raw-vs-repair conditional-MCC comparison confounded by mismatched acceptance gates

Found while building `pipeline/paper_results.py` (the single source for manuscript numbers), when the
new first-attempt funnel showed that every visibly accepted raw rule (389/389, 15 models) also had a
location-correct visible pair -- zero loss between those two stages.

**Cause.** The workflows were accepted by different gates at run time:
- raw: `pipeline/run_generation.py` sets `semgrep_valid` only if `original_vulnerable` is a
  location-correct TP (finding on the annotated vulnerable lines) and `original_patched` is TN --
  location-aware;
- autogrep and the iterative loop ("C2"): `autogrep/rule_validator.validate_rule` -- any finding on
  the vulnerable file and none on the patched file -- location-blind.

Every conditional metric therefore pooled samples from two different definitions of "accepted".
Measured directly (15 open-weight models, 150 eligible cases): the location-blind validator accepted
**88 of 546 autogrep rules (16.1%) whose visible-pair finding was outside the vulnerable lines**
(per model 1-11). Those rules contribute an FN on `original_vulnerable` to the pooled confusion
matrix, lowering autogrep's (and the iterative loop's) conditional MCC relative to raw's.

**Effect, recomputed with one location-aware gate re-applied post hoc to every workflow (no re-run;
repository-aware bootstrap, 10,000 resamples, seed 42, Holm):**

| Comparison | Own gates (as reported 2026-10-07) | Common location-aware gate |
|---|---|---|
| raw vs autogrep, original 8: cond-MCC raw higher / significant | 7/8 / 2/8 | 1/8 / 0/8 |
| raw vs autogrep, all 15: cond-MCC raw higher / significant | 14/15 / 4/15 | 3/15 / 0/15 |
| raw vs iterative, 8: cond-MCC significant | 2/8 | 0/8 |
| ESR (end-to-end) significant, any comparison | 0 | 0 (unchanged) |
| autogrep acceptance > raw acceptance | 15/15 | 14/15 (qwen2.5-coder:32b ties, 39 vs 39) |

ESR is identical under both gates for every model and condition (it always required a
location-correct visible pair; self-checked in `paper_results.py`). The own-gate 0/8 and 2/8 counts
are reproduced exactly by the same script, so the difference is the gate, not the code.

**What this corrects.** The 2026-10-07 claim that raw's conditional MCC is higher than autogrep's
and the iterative loop's for 7 of 8 models, significant for 2 of 8, does not hold once both sides
are accepted by the same criterion: there is no detectable conditional-MCC difference in either
direction (raw is numerically higher for only 1 of the original 8 and 3 of all 15). The 2026-10-07 retraction of the earlier "repair improves conditional MCC" claim still
stands; its replacement claim ("raw is as good or better") is itself withdrawn. The study's central
end-to-end result is unaffected.

**Still carrying the superseded claim** (not edited here): `Paper_Draft_Notes.md` §7.2 (~lines
441-467), §7.4 (~line 660), §7.8 comparisons 4-5 and overall reading (~lines 1210-1276), and the
closing note (~lines 2020-2040). The manuscript (`~/Desktop/Paper Writing/`) already uses the
common-gate numbers via `numbers.tex`.

**Reproducibility.** `python pipeline/paper_results.py` writes `results_paper/model_rows_common_gate.json`,
`results_paper/model_rows_own_gate.json` and `results_paper/significance.json`
(`own_gate_raw_vs_autogrep_original8` is the reproduction of the published counts). No model calls,
no Semgrep scans, no change to any historical result file.

### 2026-10-15 — C2 iterative loop extended to the 7 follow-up models + gpt-4o; one real bug found and fixed mid-run

`results/runs_c2_primary/` (the "C2" iterative-single-agent loop, `pipeline/run_c2.py`) had only ever
been run for the original 8 primary-benchmark models. The 7-model follow-up campaign and gpt-4o
(`runs_followup_20261008/`, `runs_openai_full_20261010/`) had raw/autogrep coverage only, never C2.
Extended to all 8 remaining models on the CSC VM (`semvm`), same script, same 153 "supported" cases,
same Section 20 budget, output to the new `results/runs_c2_followup/`.

**Bug found before the full run (not a correction, a preflight fix):** `run_c2.py`'s `preflight_auth()`
called the host-blind `get_api_key()` (always reads `GPTLAB_API_KEY`, ignores which host it's
checking) instead of the already-corrected, host-aware `get_key_for_host(host)` that
`build_config()`'s real generation path already used — the same class of bug fixed in
`diagnostic_v2.py` earlier in the project, never propagated to `run_c2.py`. Fixed by importing and
calling `get_key_for_host` inside the per-host preflight loop. Verified via a 3-case/8-model
verification subset (`results/_c2_followup_verify/`) before committing to the full run.

**A second, more consequential bug found mid-run (environment, not code):** the first full-run
launch invoked the interpreter as `.venv/bin/python pipeline/run_c2.py ...` without activating the
venv, so `PATH` on the VM's shell never included `.venv/bin` — every single rule validation call
failed with `Error running semgrep: [Errno 2] No such file or directory: 'semgrep'`, even though
`semgrep` was correctly installed in that same venv. Result: 0/153 accepted across all 5 models that
had finished before this was caught (confirmed by reading raw episode records directly, not just the
acceptance tally). The invalid run was stopped, moved aside to
`results/runs_c2_followup_invalid_no_semgrep_path_20261015/` (not deleted), and relaunched with the
venv properly activated (`source .venv/bin/activate` before invoking `python`, confirmed via
`which semgrep` resolving inside the venv before relaunch). The relaunch completed cleanly: all 8
models, 153/153 episodes each, zero `semgrep`-path errors on verification.

**Results** (after applying the existing location-correctness retroactive correction —
`pipeline/rescore_variant_location.py`'s `TARGET_GLOBS` extended to include
`runs_c2_followup/*/sample_execution_log.jsonl`; 6-23 TP->FN flips per model, same mechanism as every
other result set this fix already covers), under the paper's common location-aware gate, 150
eligible cases:

| Model | Accepted | Complete success (ESR) | Conditional MCC | Hidden detect |
|---|---|---|---|---|
| gpt-4o | 55 | **11 (7.3%)** | 0.647 | 21.7% |
| qwen3-coder:30b | 61 | 9 (6.0%) | 0.618 | 24.7% |
| gpt-oss:20b | 29 | 9 (6.0%) | 0.700 | 12.3% |
| Mistral-Small-24B | 42 | 7 (4.7%) | 0.634 | 17.0% |
| phi4:14b | 27 | 6 (4.0%) | 0.646 | 11.7% |
| llama3.1:8b | 29 | 3 (2.0%) | 0.602 | 10.0% |
| granite-code:8b | 29 | 3 (2.0%) | 0.518 | 5.7% |
| opencoder:8b | 11 | 0 (0.0%) | 0.408 | 1.3% |

The original 8-model primary study's ESR range under the same gate is 0.7%-6.0% (max: DeepHat-V1-7B,
min: codellama:7b-instruct-fp16 and magicoder:7b, both 1/150).
**Only gpt-4o (7.3%) exceeds that range**; qwen3-coder and gpt-oss tie the primary-8's best rather
than clearly beating it. (An earlier exploratory pass, before the location-correctness correction and
without the common gate, had suggested two follow-up models beat the primary-8's best — that claim is
superseded by the numbers above, which use the audited pipeline.)

**Integration.** Added `C2_FOLLOWUP_MODEL_DIRS` to `pipeline/paper_results.py`, kept under its own
`"iterative_followup"` condition key rather than merged into the primary-8's `"iterative"` key — same
separation convention as `gptlab_config.py`'s `FOLLOWUP_MODEL_HOSTS`, so this later campaign is never
silently conflated with the original 8-model primary study's audited iterative results. `_load_iterative`
generalized to take a `run_subdir` argument (was hardcoded to `runs_c2_primary`); the existing
generic per-key self-checks (ESR and own-gate acceptance agreement between `crow` and `rows`) cover
the new entries automatically, with no special-casing needed, and all passed, alongside the existing
hard-coded 0/8-and-2/8 original-8 reconciliation check (unaffected, still passes). New LaTeX macros
(`FollowupIterNumModels`, `FollowupIterSuccessMin/Max`, `FollowupIterSuccessMaxModel`,
`FollowupIterBeatsPrimaryBestN`, `PrimaryIterSuccessMax`) and a new table
(`tab-followup-iterative-rows.tex`) added, additive only — no existing macro, table, or number changed.

**Reproducibility.** `ssh semvm` ran `pipeline/run_c2.py` directly (not relayed — standing preference
is the user runs remote commands themselves; GPTLAB_API_KEY/OPENAI_API_KEY exported transiently in
the VM's own shell, never written to a file). Results pulled to `results/runs_c2_followup/` via
rsync, verified locally (episode counts, zero semgrep-path errors) before use.
`python pipeline/rescore_variant_location.py` then `python pipeline/paper_results.py` regenerate
`results_corrected/runs_c2_followup/` and `results_paper/*.json` respectively.

### 2026-10-20 — Iterative-run timing disclosure applied to only 8 of 16 models; one claim was factually wrong

Found during the 2026-10-18 supervisor review (Issue 5), checked directly rather than taken on
description. The published table's dagger footnote ("iterative run made about a week after the
model's other runs") was applied only to the 7 follow-up models + gpt-4o
(`pipeline/paper_results.py`'s table-generation code: `later = m not in C2_MODEL_DIRS`). Checking
the real run_id timestamps for the original primary-8 directly
(`results/runs_phase5_primary/*/generation_log.jsonl` vs. `results/runs_c2_primary/*/c2_episode_log.jsonl`):
every one of those 8 models' C2 runs also happened separately in time from their raw/autogrep
runs — 2-3 days later in every case (e.g. `qwen2.5-coder:7b-instruct`: raw/autogrep 2026-09-28,
C2 2026-10-01), not the same session.

**Worse than under-disclosure: `Paper Writing/sections/03-study-design.tex:171-175` asserted the
opposite as fact** — *"the iterative runs of the first eight models... were made in one
campaign"*. This is directly contradicted by the timestamps above; it was not a hedge or an
omission, it was a specific, checkable claim that happened to be wrong.

**Corrected:**
- `pipeline/paper_results.py`: `later = m not in C2_MODEL_DIRS` -> `later = True` (the dagger now
  applies to every model's row, with an in-code comment citing the timestamp evidence).
- `Paper Writing/sections/03-study-design.tex:171-175`: *"All single-shot and Autogrep runs, and the
  iterative runs of the first eight models... were made in one campaign. The iterative runs of the
  remaining seven models and GPT-4o were made about a week later"* -> *"All single-shot and
  Autogrep runs were made in one campaign. The iterative runs were made separately for every model:
  2-3 days later for the first eight models... and about a week later for the remaining seven
  models and GPT-4o."*
- `Paper Writing/sections/04-results.tex:16-17` (table caption): "about a week" -> "days to about a
  week", to accurately span both the 2-3 day and ~week-long gaps now both covered by the footnote.

Regenerated the real table (`Paper Writing/tables/tab-results-rows.tex`) and macros
(`Paper Writing/numbers.tex`) from the fixed code. Every row now carries the dagger; every existing
self-check in `paper_results.py` (ESR, own-gate acceptance, significance, funnel) still passes
unchanged, since this correction only touches which rows get a footnote marker, not any underlying
number.

**What this does not fix.** The real confound this footnote discloses — the iterative loop's first
attempt is an independently-sampled query, not a reuse of the stored raw-condition response, for
every model, not just the ones now marked — still needs the fix described in
`Research_Log/Supervisor_Review_20261018.md`'s Issue 5 (a combined rerun sharing the first
candidate between raw and the iterative loop). This correction only fixes the disclosure's scope
and factual accuracy, not the underlying methodological confound itself.

**Reproducibility.** `python pipeline/paper_results.py --tex "~/Desktop/Paper Writing/numbers.tex"
--tables "~/Desktop/Paper Writing/tables"` regenerates both from the corrected code. No model
calls, no Semgrep scans, no change to any historical result file.

### 2026-10-20 — Part II's RQ5 takeaway box overclaimed relative to the paragraph right above it

Found during the 2026-10-18 supervisor review (Issue 7). The review's letter cites "clear promise"
as appearing "in the abstract" — checked directly and that's not quite right: the phrase appears
only in `Paper Writing/sections/04-results.tex:265`, the RQ5 summary box, not in `00-abstract.tex`.
Recorded here for precision rather than silently treating the review's citation as correct; the
underlying overclaiming concern is still valid regardless of which section it's actually in.

The paragraph immediately above the box was already carefully hedged before this correction: it
states the 24-case subset was "selected by outcome," gives the real sample size a confirmatory test
would need (207 cases, under the protocol's assumed effect size and disagreement rate), and calls
the result "a well-motivated candidate for testing at scale." The boxed takeaway, read in
isolation (the part most readers actually skim), used stronger language than that.

**Corrected** (`Paper Writing/sections/04-results.tex:265-269`): "Typed construction shows clear
promise: on the development subset it added one to two cases for Qwen3-Coder, gaining a case in
every repetition and losing none, at a moderate call cost, while probes and GPT-4o showed no
consistent change. These observations provide a well-specified hypothesis for a confirmatory
study." -> "Typed construction is a well-motivated candidate for confirmatory testing: on this
outcome-selected development subset it added one to two cases for Qwen3-Coder, gaining a case in
every repetition and losing none, at a moderate call cost, while probes and GPT-4o showed no
consistent change. These observations provide a well-specified hypothesis for a confirmatory
study, not a confirmed effect."

Same numbers, same observations — only the framing of the opening and closing clauses changed, and
"outcome-selected" was pulled into the box itself so the selection-bias caveat is visible without
needing the preceding paragraph. The abstract (`00-abstract.tex:26-27`, "An exploratory study
further shows...") and introduction (`01-introduction.tex:102-104`, "a promising direction for
confirmatory work") were checked and left unchanged — already appropriately hedged.

**What this does not fix.** This is language only, per path (b) of Issue 7's proposed path forward.
The four underlying confounds (outcome-based case selection, unequal example validity, unequal call
budgets, 11-case probe coverage) are untouched — see
`Research_Log/Supervisor_Review_20261018.md`'s Issue 7 for the real fix (path (a): a rerun with
outcome-blind case selection, matched examples, matched budgets).

**Reproducibility.** Manual text edit, no generated file involved (this is prose, not a
`paper_results.py` output). No model calls, no Semgrep scans, no change to any result file.

### 2026-10-20 — Abstract never stated which case population was actually evaluated

Found during the 2026-10-18 supervisor review (Issue 6). The abstract's headline dataset size is
\NumCases{} (299), and the sentence describing the actual evaluation ("we evaluate 15 open-weight
LLMs and GPT-4o under single-shot generation, Autogrep's validation-feedback loop, and an iterative
repair loop") named no population at all — a reader has no way to know from the abstract alone that
every reported result in the paper is computed on exactly half that, the 150 "supported" cases
(`\NumEligible`), not the full 299.

Checked first whether this was actually an inflation risk or just an omission: all 299 cases
genuinely do have complete six-sample bundles (`pipeline/section9_final/build_bundle_case*.py`,
342 individual scripts covering the full curated set) — the 299-case headline figure is accurate on
its own terms. The gap is specifically that the *evaluated* population was never named in the one
place most readers only read.

**Corrected** (`Paper Writing/sections/00-abstract.tex:14-18`): inserted "on the \NumEligible{}
cases whose vulnerability a Semgrep rule can structurally express" into the evaluation sentence,
using the already-defined `\NumEligible` macro (150) — consistent with how the real results section
already scopes itself (`04-results.tex:4-5`, "Table~\ref{tab:results} reports every Part~I workflow
for every model on the \NumEligible{} evaluation cases"). No macro values changed, no new macro
introduced — purely a missing clause added to existing prose.

**What this does not fix.** The disagreement-resolution gap (second-rater disagreements were never
arbitrated; the original single-rater label stands dataset-wide) and the positive control (no
expert-written or verified pre-existing rule has been run against any subset to show the benchmark
is solvable) are both untouched — see `Research_Log/Supervisor_Review_20261018.md`'s Issue 6.

**Reproducibility.** Manual text edit to `00-abstract.tex`; no generated file involved. No LaTeX
toolchain was available locally to compile-check the result — the edit is plain prose plus an
already-defined macro, low risk, but noted rather than assumed clean. No model calls, no Semgrep
scans, no change to any result file.

### 2026-10-20 — "Cost-efficient self-hosting" had no resource measurement behind it

Found during the 2026-10-18 supervisor review (Issue 8, sub-issue 5). Before deciding how to fix
this, checked whether a genuine resource estimate was actually possible: searched the project for
any recorded GPU hardware model, VRAM size, electricity cost, or dollar-per-hour figure for the
GPT-Lab hosts (`GPU-farmi-001/003/004`) that generated every result in this study. None exists
anywhere in the project — these are host names on a shared institutional cluster
(`Research_Log/Implementation_Log.md:11` onward), not infrastructure the user administers or has
specs for. Only call counts and wall-clock seconds were ever recorded, and only for
budget-enforcement purposes, not as a cost argument.

Building a "cost-efficient" estimate from this would require fabricating hardware/electricity-cost
assumptions with no way to verify them — against the grounded-analysis discipline this whole review
has followed. Removed the claim rather than inventing numbers to support it.

**Corrected** (`Paper Writing/sections/04-results.tex:62-66`): "Compact 7B--9B models are
competitive with much larger ones, which favors cost-efficient self-hosting." -> "Compact 7B--9B
models are competitive with much larger ones." Confirmed via `grep` that "cost-efficient"/
"self-hosting" phrasing does not recur anywhere else in the manuscript.

**What this does not fix, and why, deliberately.** Left "Compact 7B--9B models are competitive with
much larger ones" itself untouched. That claim rests on the same count-level tie this review's Issue
8 sub-issue 4 already flags as potentially misleading — Qwen2.5-Coder 7B matching its 32B sibling's
complete-success count exactly (`p=1.000`, `04-results.tex:55-60`) says nothing about whether it's
the *same* cases succeeding. Fixing this piecemeal now, before sub-issue 4's paired case-level view
exists, risks stating a claim that the next correction immediately re-examines. Both will be
revisited together.

**Reproducibility.** Manual text edit to `04-results.tex`; no generated file involved. No model
calls, no Semgrep scans, no change to any result file.

### 2026-10-20 — The repository-aware bootstrap wasn't actually reproducible across process runs

Found as a side effect of building the confidence-interval fix below, not something searched for
directly — worth recording that distinction, since it's a more consequential finding than the fix
it was found while building.

Re-running the new `success_rate_ci()` function in separate process invocations, same inputs, same
`seed=42`, gave slightly different results each time (`ci_hi` observed varying between 0.1164 and
0.1181 across 4 runs). Traced the cause: `eligible_cases.eligible_supported_cases()` returns a
Python `set`, and CPython randomizes string-hash seeding per process by default — so
`repo_ids = list(groups.keys())` in `analyze_section22_corrected.py` had a different repo *order*
each process run. The bootstrap's `seed=42` fixes the RNG's draw *sequence*, but not what repo each
drawn index actually points at once the list itself is reordered, so the same seed produced
slightly different resamples depending on which process happened to run it.

**This is not confined to the new code.** `repo_aware_bootstrap()` — the pre-existing
paired-comparison function used for every significance test reported anywhere in this study
(raw-vs-autogrep, raw-vs-iterative, and the two model-vs-model comparisons added earlier today) —
shares the identical `repo_ids = list(groups.keys())` pattern and the identical exposure.

**Corrected** (`pipeline/analyze_section22_corrected.py`, both `repo_aware_bootstrap()` and
`repo_aware_bootstrap_single()`): `repo_ids = list(groups.keys())` -> `repo_ids = sorted(groups.keys())`.
Sorting gives a canonical order independent of the process's hash seed, restoring the determinism
`seed=42` was always supposed to provide.

**Verified the fix, and verified it changes nothing already published.** Recomputed the same CI in
4 separate process runs post-fix: bit-for-bit identical every time. Then ran the full
`pipeline/paper_results.py` — including its hard-coded self-check that the original 8 models must
reproduce the published 0/8 ESR-significant and 2/8 MCC-significant counts exactly — three times in
separate processes: all three passed. The fix restores determinism without changing what the
bootstrap was already converging toward; no previously-reported significance count or p-value is
known to change as a result (the pre-fix instability was small enough, and far enough from any
reported threshold, not to have flipped a result in any run observed during this review, though
exhaustive historical reproduction was not attempted).

**Reproducibility.** `python pipeline/paper_results.py` run multiple times in separate processes,
compared directly, rather than trusting a single run.

**Searched for the same pattern elsewhere, found one more instance.** `grep` for
`list(....keys())` near repo-grouping logic turned up `pipeline/analyze_section22_subgroups.py`'s
`repo_aware_bootstrap_mcc()` — an independent implementation of the identical pattern
(`repo_ids = list(repo_to_cases.keys())`), imported directly (not reimplemented) by
`analyze_section22_subgroups_corrected.py`. Not part of `paper_results.py`'s current live import
graph (so it doesn't affect any number regenerated today), but referenced in
`Paper_Draft_Notes.md`/`Reproducibility_Package.md`, meaning it fed earlier subgroup analysis.
Fixed identically (`sorted()` instead of `list()`) for consistency; confirmed the file still
imports cleanly. Lower priority than the fix above since nothing currently regenerated depends on
it, but left unfixed it would have been the same latent bug waiting to resurface.

### 2026-10-20 — Part I's headline numbers had no confidence intervals anywhere

Found during the 2026-10-18 supervisor review (Issue 8, sub-issue 3). `03-study-design.tex` already
describes a real repo-aware bootstrap methodology, but checking where it's actually used: only for
pairwise significance tests (raw vs. autogrep, raw vs. iterative), never to attach an interval to a
model's own point estimate in the main results table or the headline prose claims.

**Scope decision** (asked rather than decided unilaterally, given the real editorial tradeoff):
added a CI for the primary outcome (complete success / ESR) only, not every metric in the main
table — the alternative (CIs on acceptance, MCC, hidden-only MCC, and detection rate too) would have
roughly doubled the table's width again on top of the hidden-only-MCC column just added.

**Implementation.** Added `repo_aware_bootstrap_single()` to `analyze_section22_corrected.py` —
identical repo-grouped resampling to the existing `repo_aware_bootstrap()` (same seed, `n_boot`,
percentile convention), with the paired subtraction removed since this is a CI around one group's
own point estimate. Identified which (model, condition) actually achieves `\SuccessMax` directly
rather than assuming: `qwen3-coder:30b`/autogrep, 11/150. Computed the matching CI for gpt-4o's
autogrep value (also 11/150), since both are named together in the "matching GPT-4o" claim.

**Result: 7.3% [95% CI 3.4%-11.6%]** for the best open-weight model, **7.3% [3.4%-11.8%]** for
gpt-4o. Genuinely wide — an honest reflection of n=150 cases with only 11 successes each, not a
computation error.

**Corrected** (`04-results.tex:142-145`, the RQ2 summary box): added the intervals directly next to
the existing point estimates, as new macros (`SuccessMaxCILo/Hi`, `GPTFourSuccessCILo/Hi`), not
hardcoded values. Reran and confirmed all self-checks pass unchanged.

**With this, all six Issue 8 sub-issues are resolved** — see
`Research_Log/Supervisor_Review_20261018.md` for the complete record of each.

**Reproducibility.** `python pipeline/paper_results.py --tex "~/Desktop/Paper Writing/numbers.tex"
--tables "~/Desktop/Paper Writing/tables"` regenerates both from the corrected code. No model
calls, no Semgrep scans, no change to any historical result file.

### 2026-10-20 — Conditional MCC pooled the guaranteed-correct visible pair with the genuinely-uncertain hidden samples

Found and quantified during the 2026-10-18 supervisor review (Issue 8, sub-issue 2). Conditional
MCC (`pipeline/analyze_phase5_primary.py`'s `gated_samples` + `_row_from_cases` in
`paper_results.py`) pools all 6 sample types for every accepted case, including
`original_vulnerable`/`original_patched` — which are guaranteed correct for every accepted case by
definition of the acceptance gate itself. Recomputed conditional MCC restricted to only the 4 hidden
samples, for all 16 models; the gap is substantial (e.g. `opencoder:8b` drops from 0.456 pooled to
0.152 hidden-only, a 67% relative difference) — full table in
`Research_Log/Supervisor_Review_20261018.md`'s Issue 8.

**Corrected:**
- `pipeline/paper_results.py`: added `hidden_only_mcc` to `_row_from_cases()`'s return value (same
  `confusion_from_samples`/`mcc` functions, input restricted to exclude the visible pair) and
  `HiddenMCCMin`/`HiddenMCCMax` summary macros (same pooling scope as the existing
  `CondMCCMin`/`CondMCCMax`: all three conditions).
- `Paper Writing/sections/04-results.tex`: added MCC$_h$ as a new column in the main results table
  (Table~\ref{tab:results}) — not a separate table or prose-only range, per the user's explicit
  choice on this editorial tradeoff. Required updating the column spec (`llrrrrrr...` ->
  `llrrrrrrr...`), the Autogrep group's span (`\multicolumn{4}` -> `\multicolumn{5}`,
  `\cmidrule(lr){5-8}` -> `\cmidrule(lr){5-9}`), the iterative group's span
  (`\cmidrule(l){9-10}` -> `\cmidrule(l){10-11}`), and the header row and caption, consistently.
  Verified the regenerated row count matches the new 11-field header before treating this as done.
- Added two prose mentions so the new column has context: `04-results.tex:74-80` (RQ2, immediately
  after the existing pooled-MCC-range sentence) and `05-discussion.tex:41-49` (the "Report
  all-requested denominators" benchmark-design paragraph, extended to also recommend separating the
  visible pair from the hidden samples — the paragraph now models the practice it argues for).

Reran `pipeline/paper_results.py` after every step; all existing self-checks (ESR, own-gate
acceptance, significance, funnel) passed unchanged throughout — confirms this was purely additive,
no existing number changed. Spot-checked `opencoder:8b`'s regenerated value (0.46/0.15 at 2 decimal
places) against the hand-computed figures from the original investigation (0.456/0.152) — matches.

**Reproducibility.** `python pipeline/paper_results.py --tex "~/Desktop/Paper Writing/numbers.tex"
--tables "~/Desktop/Paper Writing/tables"` regenerates both from the corrected code. No model
calls, no Semgrep scans, no change to any historical result file.

### 2026-10-20 — "Equal complete-success counts" hid that the two models solve almost entirely different cases

Found and quantified during the 2026-10-18 supervisor review (Issue 8, sub-issue 4). The manuscript
cites two model pairs as having equal or statistically-indistinguishable complete-success counts
(`04-results.tex`: Qwen2.5-Coder 7B vs. 32B, 7 vs. 7, `p=1.000`; DeepHat-V1 vs.
Qwen2.5-Coder-Instruct, 9 vs. 7, `p=0.551`) without stating whether it's the same cases succeeding.

Checked whether new bootstrap infrastructure was needed: it wasn't —
`analyze_section22_corrected.paired_comparison_corrected` (already used throughout this script for
raw-vs-autogrep/raw-vs-iterative) is generic over any two per-case result dicts and already computes
the paired gained/lost counts via its own `mcnemar_b`/`mcnemar_c` fields; it had simply never been
pointed at two *models* instead of two *conditions* of the same model. Verified its loader
(`_load_condition_own_gate`) reproduces the manuscript's exact cited counts (7/150 and 7/150) before
trusting it further.

**Result, striking:** the Qwen2.5-Coder 7B/32B pair solves almost entirely *different* cases despite
the identical total — only 4 of 7 cases in common, each model solving 3 the other doesn't. DeepHat-V1
vs. Qwen2.5-Coder-Instruct shows more but still partial overlap (5 common, DeepHat solving 4 the
other doesn't, missing 2 of the other's own).

**A process note worth recording honestly**: the first draft of this fix wrote these numbers
directly into the manuscript's prose as hardcoded values. Caught before finishing — this violates
the project's own strict convention that every quoted number comes from a generated macro, never
typed by hand. Corrected course: added `model_capability_overlap()` to `pipeline/paper_results.py`,
added `QwenPairCommon`/`QwenPairAOnly`/`QwenPairBOnly` and
`DeepHatPairCommon`/`DeepHatPairAOnly`/`DeepHatPairBOnly` as real macros, and rewrote
`04-results.tex:58-66` to cite those macros instead. Verified the macros match the manual computation
exactly (4/3/3 and 5/4/2) before finalizing.

**Reproducibility.** `python pipeline/paper_results.py --tex "~/Desktop/Paper Writing/numbers.tex"
--tables "~/Desktop/Paper Writing/tables"` regenerates both from the corrected code. All existing
self-checks passed unchanged throughout. No model calls, no Semgrep scans, no change to any
historical result file.

### 2026-10-20 — "Rules rarely flag safe code" pooled two different false-positive rates

Found during the 2026-10-18 supervisor review (Issue 8, sub-issue 6). Checked first whether the
disaggregated numbers needed to be computed from scratch — they didn't: `\HidAltFixPct{}=91.3` and
`\HidBenignPct{}=77.5` are already defined in `numbers.tex` and already used in the RQ2 summary box
(`04-results.tex:121-123`). The overclaim was isolated to the body paragraph above that box, which
used the pooled `\HidFailNegOnlyPct` (16.6%, blending both negative categories together) to
conclude rules "rarely flag safe code" — a reader working straight through the prose would reach
that sentence before the more precise box a few lines later.

**Corrected** (`Paper Writing/sections/04-results.tex:101-104`): "Generated rules are therefore far
more often too narrow than too broad. This is good news for precision, since rules rarely flag
safe code, and it gives generators a clear target..." -> "...though not uniformly good news for
precision: accepted rules stay silent on the alternative fix in \HidAltFixPct\% of cases but on
the benign look-alike in only \HidBenignPct\% — a real false-positive rate on the one negative
sample built to look structurally similar to the vulnerability." No new macro introduced; reused
the two that already existed, so the number (100 - 77.5 = 22.5%) matches the independently
recomputed figure from `results_paper/hidden_breakdown.json` exactly.

Checked the other similarly-worded sentence (`04-results.tex:217`, the RQ4 summary box: "accepted
rules lean toward being too narrow, which favors precision") — softer framing, doesn't make the
specific "rarely" claim, left unchanged.

**Reproducibility.** Manual text edit to `04-results.tex`; no generated file involved, no macro
values changed. No model calls, no Semgrep scans, no change to any result file.

### 2026-10-20 — "Complete success"/"six samples" framing checked, no change needed

Checked during the 2026-10-18 supervisor review (Issue 8, sub-issue 1): does "complete success on
all six samples" get read anywhere as a claim of general correctness or deployment readiness? Read
every occurrence — the abstract, the actual metric definition (`03-study-design.tex:256-259`), the
results section, and discussion/conclusion (`05-discussion.tex`, `08-conclusion.tex`). Found no
instance of either phrase being claimed; every usage states "on all six samples" or the equivalent
explicitly, and the discussion section already pre-empts over-reading directly: "It is not a final
verdict, since at most \AcceptedPassMax\% of a configuration's accepted rules also pass the hidden
samples." No edit made — this is a verified non-issue, recorded so the response table's "remains
unresolved" column can say so accurately rather than silently dropping it.
