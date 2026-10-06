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
- [ ] **Step 2 — Audit the evaluator.** Wrapper schema restrictions, Semgrep errors, skipped files,
      finding-location checks, original vs. transformed samples; separate compilation success from
      visible-pair acceptance. IN PROGRESS.
- [ ] **Step 3 — Audit questionable dataset cases.** All "kept and flagged" cases, incomplete
      fixes, uncertain negatives, parsing problems; complete the prepared independent label review.
      NOT STARTED.
- [ ] **Step 4 — Recompute all metrics consistently.** Compilation rate / acceptance coverage /
      conditional MCC·VGR·FPR / end-to-end hidden-positive detection rate / end-to-end successful
      rule rate, each with an explicit, stated denominator; missing or invalid rules treated as
      failures, never silently excluded or credited as true negatives. NOT STARTED (depends on
      Step 2's evaluator audit being complete first).
- [ ] **Step 5 — Verify workflow comparability.** One table documenting C2/C3/C4's actual shared
      settings and differences (generator input, review stages, acceptance gates, repair
      opportunities, enforced budgets). NOT STARTED.
- [ ] **Step 6 — Recalculate statistics.** Paired comparisons on consistent cases, repository-aware
      uncertainty throughout (including the 7 main comparisons, not just the subgroup analysis —
      a real inconsistency already identified, see below), declared multiple-comparison correction.
      NOT STARTED.
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

**Still open for Step 2**: wrapper schema restrictions beyond what Finding 2's breakdown already
surfaces (the 30 "X is not of type 'string'" / nested-metavariable-pattern cases from the §24
failure-taxonomy work are a start, not a complete audit of the wrapper itself); Finding 4's
real-data check.
