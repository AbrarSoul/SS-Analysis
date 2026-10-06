# Section 22 (Formal Statistical Analysis) — Scope

Written 2026-10-06. This is the last unbuilt piece of the whole study -- every condition design
Section 22 wants compared (C1-C4, the 8-model primary benchmark, raw-vs-autogrep) already has real,
collected data. This is a genuinely new build (no prior analysis script does paired significance
testing), so scoped first per established practice (same as C2/C3/C4 each got their own scope pass).

## What already exists, confirmed by direct inspection (not assumed)

- **Primary benchmark** (`results/runs_phase5_primary/<model>__autogrep_default/`): 8 models, both
  `raw` and `autogrep` conditions, full 300-case set, `generation_log.jsonl` + `sample_execution_log.jsonl`.
  `raw` IS exactly C1 ("one model, one attempt, no feedback") -- Section 18.1's definition matches
  the `raw` condition's own description verbatim.
- **C2** (`results/runs_c2_primary/`): iterative single-agent, Section 20 budget, run across multiple
  models on the 153 `supported` cases.
- **C3-S/C3-E** (`results/runs_c3/`): homogeneous multi-agent, 153 supported cases each.
- **C4-A/C4-B** (`results/runs_c4/`): heterogeneous multi-agent, 153 supported cases each.
- **Manifest fields needed for subgroup analysis** (`benchmark/manifest_frozen_final.jsonl`, 300
  rows) -- checked directly, all populated except one:
  - `language` (python/java/javascript/typescript): 300/300
  - `pattern_or_taint` (pattern/taint): 300/300
  - `context_complexity` (structural/context_heavy): 300/300
  - `semgrep_representability` (supported/partially_supported/unsupported): 300/300
  - `cwe_ids` (list, e.g. `["CWE-1236"]`): 300/300
  - `patch_size_added`/`patch_size_deleted`: 300/300
  - `repository`: 300/300, 258 unique repos, only 27 repos contribute >1 case (69 cases total,
    max 5 from one repo) -- non-independence is real but limited in scale.
  - **`advisory_date` is 0/300 (never populated)**. Substitute: parse the year out of `cve_id`
    (or the first entry of `cve_ids_all`) -- works for all 300 cases (`no_year` count is 0), gives
    a usable year distribution (2010-2026, median year 2023) for an older/newer median split. This
    is coarser than a real advisory date but the design doc's own intent ("older versus newer CVE
    reporting") is satisfied by year-level granularity; flagged as an approximation, not hidden.

## Statistical toolbox: what's available vs what needs hand-rolling

`scipy.stats` (1.18.1, already installed) provides `friedmanchisquare` and `wilcoxon` directly.
`statsmodels` is NOT installed -- rather than add a new pinned dependency this late, McNemar's test
and Holm's correction are both simple enough to hand-roll correctly:
- **McNemar's test** (paired binary outcomes): exact binomial test on the discordant pairs
  (`scipy.stats.binomtest(min(b,c), n=b+c, p=0.5)`), the standard small-sample-exact form; falls
  back to the continuity-corrected chi-square form only if a continuity-corrected variant is
  specifically wanted (not needed here -- case counts are small enough, b+c <= ~150, that the exact
  binomial test is preferred anyway, and it's what McNemar's exact test literally IS).
- **Holm-Bonferroni correction**: trivial to implement directly (sort p-values ascending, compare
  each to alpha/(m-i), one pass) -- no dependency needed.
- **Bootstrap CIs**: hand-rolled resampling (the project already has pooled-confusion-matrix
  machinery in `analyze_phase5_primary.py`; bootstrap just resamples the unit of interest with
  replacement and recomputes the same functions, reused directly).

## The one real methodological decision: how to pair "MCC" for significance testing

Section 22.2 says "Wilcoxon signed-rank test for paired MCC, latency, token, and cost outcomes."
This is unambiguous for latency/tokens/cost (each case naturally produces one scalar per condition
-- directly pairable). It is NOT directly applicable to MCC, which this study has always computed as
a single POOLED statistic over all of a condition's sample-level TP/FP/FN/TN counts (Section 21.9's
own "overall sample-level" framing, used consistently in every prior analysis in this project) --
there is no natural "one MCC value per case" to hand to a paired test; a per-case confusion matrix
from only 6 samples is usually degenerate (Section 7.3's own `analyze_phase5_primary.py` comment
already documents this: per-case VGR only takes 3 possible values, per-case FPR only 4).

**Resolution, applied consistently across every comparison below rather than reinvented per-case**:
- **For binary pass/fail outcomes per case** (does this case's rule meet Section 16.2's correctness
  criteria, i.e. ESR), use **McNemar's test** directly -- ESR is already computed per-case in
  `analyze_phase5_primary.py` and is a genuine paired binary outcome.
- **For the POOLED metrics (MCC, VGR, FPR, PDS)**, use a **case-level paired bootstrap**: resample
  cases (not samples) with replacement, N=10,000 times; for each resample, recompute BOTH
  conditions' pooled MCC (etc.) restricted to the resampled cases (with repetition), take the
  difference; report the 95% percentile CI of the difference distribution and a two-sided bootstrap
  p-value (twice the smaller tail past zero). This is the standard, defensible way to get a paired
  significance estimate for a pooled/aggregate statistic, preserves the pooling methodology this
  entire study has used throughout (never silently switched to a different, less comparable
  per-case MCC definition), and naturally extends to repository-aware resampling for Section 22.4
  (resample at the REPOSITORY level instead of the case level, to respect non-independence).
- **For latency/tokens/cost**, genuine per-case scalars exist already in `generation_log.jsonl`
  (`generation_seconds`, `input_tokens`, `output_tokens`) -- real Wilcoxon signed-rank applies
  directly, no substitution needed.
- **Friedman's test** (omnibus, >2 conditions) is used for the "family effect" and "C3 vs C4"
  comparisons (more than 2 conditions each) on the per-case ESR binary outcome (0/1, matched across
  all conditions for the same case) -- Friedman handles this as a special case of a repeated-measures
  rank test; Holm-corrected pairwise McNemar/bootstrap follow-ups only run if the omnibus is significant.

This is flagged explicitly as a deviation from the letter of Section 22.2 (which names Wilcoxon for
MCC) but not its intent (a paired, significance-tested comparison of a pooled quality metric) --
worth stating in the eventual paper's methods section rather than silently departing from the design
doc's wording.

## The 7 predefined comparisons (Section 22.3), mapped to real data

All restricted to the 153 `supported` cases (Section 7.3's own established primary-ranking scope,
kept consistent so results compare like-for-like across comparisons 1-7).

1. **Qwen2.5-Coder 7B vs 32B (scale effect)** -- primary benchmark, `autogrep` condition, same model
   family. Paired per-case ESR (McNemar) + case-level bootstrap (MCC/VGR/FPR/PDS) + Wilcoxon
   (tokens/latency).
2. **Qwen2.5-Coder 7B vs DeepHat 7B (security fine-tuning effect)** -- same shape as #1.
3. **Small code-model family effect at similar scale** -- Friedman omnibus across the ~7-9B models
   (`qwen2.5-coder:7b-instruct`, `deepseek-coder:6.7b`, `codegemma:7b`, `magicoder:7b`,
   `yi-coder:9b`, `DeepHat-V1-7B`; `qwen2.5-coder:32b` excluded as the scale outlier already covered
   by #1, `codellama:7b-instruct-fp16` excluded per its existing precision-confound flag, Section
   12.23) on per-case ESR, Holm-corrected pairwise follow-ups if significant.
4. **Raw vs Autogrep (pipeline effect)** -- paired within each of the 8 models separately (same
   model, same case, two conditions) -- McNemar/bootstrap/Wilcoxon as above, reported per model
   AND as an aggregate statement (e.g. "N/8 models show a significant autogrep improvement after
   Holm correction across the 8 per-model tests").
5. **C1 vs C2 (iterative feedback effect)** -- `raw` condition (restricted to the 153-case subset,
   since C2 only exists there) vs C2's own results. Confirmed directly: C2 was run on all 8 models
   (`results/runs_c2_primary/*__c2/`), so this comparison runs per-model across the full 8-model set,
   same shape as #4, plus the aggregate "N/8 models" statement.
6. **C2 vs C3 (role-separation effect)** -- C2 vs C3-S for `qwen2.5-coder:32b`, C2 vs C3-E for
   `qwen2.5-coder:7b-instruct` (the only 2 models where both conditions exist) -- formalizes the
   descriptive comparison already reported in Implementation_Log 12.52 with real paired tests.
7. **C3 vs C4 (heterogeneous assignment effect)** -- Friedman omnibus across all 4 multi-agent
   configs {C3-S, C3-E, C4-A, C4-B} on per-case ESR (same 153 cases, same workflow/budget throughout
   -- the one place in this whole study where 4 genuinely comparable conditions exist on an
   identical case set), Holm-corrected pairwise follow-ups.

## Subgroup analysis (Section 22.4)

Applied to the primary benchmark's `autogrep` condition across all 8 models (the condition with the
most statistical power, full 300-case set before the supported-only restriction) AND to the 4
multi-agent configs on the 153-case set where cell sizes allow:
- Language, pattern-vs-taint, structural-vs-context-heavy, supported-vs-partially-supported,
  older-vs-newer CVE (median-year split): all have enough cases per bucket for a repository-aware
  bootstrap CI (resample at the repository level within each bucket).
- Patch size: report as a continuous-vs-outcome correlation (not a bucketed subgroup) given it's a
  continuous field, OR bucketed into tertiles -- tertiles chosen for consistency with the other
  categorical subgroups, each bucket's own bootstrap CI.
- **CWE**: flagged explicitly as likely too sparse for meaningful per-CWE statistics (300 cases
  across what is probably 100+ distinct CWE IDs, most appearing only once or twice) -- will report
  CWE-level counts honestly and only break out a confidence interval for CWEs with >= 10 cases,
  stating explicitly which CWEs that excludes rather than silently dropping them.

## Implementation plan

New `pipeline/analyze_section22.py`, importing `confusion_from_samples`/`mcc`/`rate`/
`per_case_vgr_fpr` from `analyze_phase5_primary.py` directly (no duplication) plus the new
hand-rolled `mcnemar_exact()`, `holm_correct()`, `paired_case_bootstrap()`, `friedman_on_esr()`
functions. Will verify the hand-rolled McNemar/Holm implementations against a known textbook example
(fixed small contingency table with a known p-value) before trusting them on real data -- same
discipline used for every other piece of analysis code in this project.

