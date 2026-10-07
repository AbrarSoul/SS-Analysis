# Paper Draft Notes

**Status: living draft, updated as each phase of the study completes.** Written in
manuscript-appropriate prose (Methods/Results register), not the engineering-log
style of `Implementation_Log.md` — pull directly from here when drafting the paper.
Every number below is taken from verified project artifacts (the frozen manifest,
the freeze record, the actual result logs), not recalled from memory. Where a
number could change as later phases complete, that is marked explicitly.

**2026-10-07: this document was fully corrected following a methodological
audit.** Every section affected by the audit is marked `[CORRECTED]` at its
heading; §10 lists every limitation found; §11 lists what remains open. The
full audit trail, including the original pre-audit state of every result
file, is in `Research_Log/Correction_Log.md` and the git history starting at
tag `baseline-pre-audit`.

Cross-references: the full experimental design is `Complete_Experimental_Design_LLM_Semgrep_MultiAgent.md`
(frozen, pre-registered). The complete engineering narrative — every bug found and
fixed, with evidence — is `Implementation_Log.md`. This document is the distillation
of both into paper-ready form.

---

## 1. Study overview

This study evaluates whether open-weight large language models can convert a
real-world software vulnerability fix (a patch) into a correct static-analysis
rule — specifically, a [Semgrep](https://semgrep.dev/) rule that flags the
vulnerable code pattern while not flagging the already-patched code or unrelated
benign code with a superficially similar shape. Eight open-weight code-capable
models are benchmarked, both in a single-shot condition and with a
feedback-driven repair loop, against a manually curated, six-sample-per-case
ground-truth dataset of 299 real CVE fixes drawn from four languages (Python,
Java, JavaScript, TypeScript).

**Two methodological audits (2026-10-06/07, and a second, deeper pass on
2026-10-07, full record in `Research_Log/Correction_Log.md`) found and
corrected a real scoring gap, several confounds in the C2/C3/C4 comparison,
and a selection-effect confound in the paper's previous headline finding —
and reran the full statistical analysis on corrected data each time.**
(A validator infrastructure failure was also briefly suspected and reported
to the user during the second pass, then found to be a misdiagnosis of an
already-documented, already-fixed diagnostic bug, §7.9 — correcting that
suspicion is included in "and corrected," not left as a separate claim.)
Every section below
reflects the corrected numbers; where a claim changed as a result, that is
stated explicitly rather than silently updated. Read this note once, up
front, rather than have it repeated at every affected number: **the
hidden-variant hit-rate metric this
study calls VGR measures generalization to the six controlled, deliberately
constructed transformations in each case's test bundle (renamed identifiers,
restructured-but-equivalent logic, a benign look-alike) — not generalization to
unseen real-world vulnerabilities.** No part of this study tests whether a rule
generalizes to a genuinely different, independently-occurring instance of the
same vulnerability class in other code; that would require a different kind of
dataset and is out of scope here.

## 2. Dataset construction

### 2.1 Source and curation pipeline

Candidate vulnerability-fix pairs were sourced from the MoreFixes dataset (a
large-scale collection of CVE-linked commits), deduplicated, and independently
verified against each candidate's security advisory (GHSA, falling back to NVD)
to confirm the captured commit pair actually corresponds to the claimed CVE. Each
surviving candidate was checked out at its own historical commit, and the
function containing the vulnerable code was located automatically from the
patch's diff — using Python's `ast` module for exact parsing, and a
character-exact brace-depth scanner (developed and iteratively hardened for this
project) for Java, JavaScript, and TypeScript, which lack a readily available
lightweight parser suitable for this purpose. Cases where automatic location
either failed outright or resolved to a function judged too large to be useful
model context (over 150 lines) were routed to manual review rather than trusted.

### 2.2 Dataset composition

Two partitions were curated: a 40-case pilot set (used exclusively for model
screening and prompt selection, never for the results reported in Section 7) and
a 300-case final set (the locked benchmark, later reduced to 299 — see below).
Case identifiers are pinned permanently once assigned — a case's identifier
never changes even if later cases are added or removed from the dataset, so
that per-case artifacts already built (see §2.3) are never silently
invalidated. The final set's composition at the original 300-case freeze:

| Language | Cases |
|---|---:|
| Python | 100 |
| Java | 100 |
| JavaScript | 77 |
| TypeScript | 23 |
| **Total** | **300** |

Every case records the vulnerable commit, the fixing commit, the changed file
and function, the associated CVE and CWE identifiers, and patch size. The frozen
dataset's content-hash (a cryptographic fingerprint over every artifact) is
`cbb5afc56809a826cb941a2833484eea77d7ab903c6818e9bb4e1dfec951165b`, recorded so
that any later accidental modification is immediately detectable.

*Two near-duplicate cases (two independent CVE reports resolving to
byte-identical code changes) were identified and one member of each pair
removed, in accordance with exclusion criteria against duplicated fixes.*

**One case excluded post-hoc during the 2026-10-06/07 audit**: `CASE-0166`
(`foxinmy/weixin4j`) was removed after confirming, directly against the real
upstream commit, that the patched revision does not compile (it references a
constant never defined anywhere in the file) — a genuine upstream defect, not
an extraction artifact. This was a deliberate, user-approved exclusion applied
after all experiments had already run, not a trigger for dataset
renumbering or a replacement case (see `Research_Log/Correction_Log.md`); its
measured effect on every reported number is zero, since the case already
carried the `unsupported` representability label and contributed no sample
records to any pooled metric. **The dataset is 299 cases as of this writing.**

### 2.3 Six-sample ground-truth bundles

For each of the 300 cases, in addition to the original vulnerable and patched
source files, four further samples were constructed by deterministic,
hand-written transformation scripts (never by an LLM, to avoid an evaluated
model ever certifying its own test material):

1. **A renamed vulnerable variant** — the same vulnerability, with every
   identifier (function, variable, class names) renamed, to test whether a
   generated rule depends on superficial naming rather than the underlying
   code pattern.
2. **A structurally restructured vulnerable variant** — the same vulnerability
   rewritten with different control-flow structure (e.g. an intermediate
   variable, a loop rewritten as its semantic equivalent), still vulnerable, to
   test generalization beyond the literal patch diff.
3. **A transformed-safe variant** — a genuinely fixed rewrite that resolves the
   vulnerability through a materially different mechanism than the real
   upstream patch (e.g. an allow-list instead of a denylist, a different but
   equally valid sanitization approach), to test whether a rule over-fits to
   the exact patch rather than the vulnerability class.
4. **A benign structural look-alike** — new code sharing the vulnerable
   pattern's surface syntactic shape but with no security consequence (e.g. the
   same `and`-chained boolean expression used only to gate a debug log line,
   not an authorization decision), to test false-positive resistance.

Where a "safe" sample's claimed safety property was independently checkable
(e.g. resistance to a specific ReDoS input, non-invocation of a malicious
`toString()`, resistance to a known bypass string), that property was verified
by direct execution against the real runtime (Python, Node.js, or a compiled
Java class) rather than asserted by construction alone.

### 2.4 Representability classification

Following the study's representability rubric, each case was labeled as
**supported** (the vulnerable code has a matchable shape expressible as a
static pattern — a dangerous API call, a missing check, a tainted flow to a
sink, a hard-coded secret, or an incomplete denylist), **partially supported**
(a static tool can observe part of the mechanism but a decisive part of the
judgment depends on context outside the function, or on a locally matchable
but semantically subtle condition), or **unsupported** (the vulnerability is
not a code-shape property at all — a timing side channel, weak cryptographic
parameter choice, data remanence, or business/authorization logic spread across
multiple non-local steps). Per the study's protocol, only supported cases
contribute to the primary model comparison; partially supported cases are
analyzed separately; unsupported cases are excluded from comparative metrics
but their count is reported. The final distribution:

| Representability | Cases |
|---|---:|
| Supported | 153 |
| Partially supported | 99 |
| Unsupported | 48 |

*This classification was made by a single rater during dataset construction.
A second-rater agreement check was completed in two rounds during the
2026-10-06/07 audit. **Round 1** (`benchmark/second_rater/`, 45 cases, rated
from written summaries only) found moderate-to-substantial agreement but had
two disclosed limitations (no full diff/source access; a handful of cases had
some detail exposed during the audit conversation before rating). **Round 2**
(`benchmark/second_rater_v2/`, a completely fresh, zero-overlap 45-case
sample, rated with full access to each case's real diff and source, zero
conversation exposure) is the methodologically stronger of the two and
supersedes it. Scored against the original labels (percent agreement /
Cohen's κ), Round 2: `pattern_or_taint` 91.1% / κ=0.802 (almost perfect);
`structural_or_context_heavy` 93.3% / κ=0.860 (almost perfect);
**`semgrep_representability` 77.8% / κ=0.662 (substantial) — still the
weakest of the three, on exactly the label that defines the 153-case
"supported" scope this entire study's primary comparisons are built on, but
materially stronger than Round 1's 64.4%/κ=0.448.** Disagreements concentrated
around the `partially_supported` boundary rather than confusing `supported`
with `unsupported` outright, and ran in both directions (not a one-way bias)
— consistent across both rounds, suggesting a genuine category-boundary
difficulty rather than a systematic labeling error. **Reported as a real, if
now smaller, validity consideration for the scope-defining label** — not a
resolved footnote, but no longer the moderate-agreement concern Round 1
suggested. Full numbers for both rounds: `Research_Log/Correction_Log.md`.*

## 3. Models evaluated

Eight open-weight, instruction-tuned code models were selected as the primary
comparison set, chosen from a larger candidate pool via empirical verification
that each is genuinely instruction-following (not a base/completion model
misidentified from its tag name alone) and architecturally diverse:

| Model | Approx. size |
|---|---|
| Qwen2.5-Coder-7B-Instruct | 7B |
| Qwen2.5-Coder-32B | 32B |
| CodeLlama-7B-Instruct (FP16) | 7B |
| DeepSeek-Coder-6.7B | 6.7B |
| CodeGemma-7B | 7B |
| Yi-Coder-9B | 9B |
| Magicoder-7B | 7B |
| DeepHat-V1-7B (security-specialized) | 7B |

**Precision policy**: all models are served in their default quantized form
except CodeLlama-7B-Instruct, which is only available in an
instruction-tuned form at FP16 precision on the inference infrastructure used
(its quantized variant on that infrastructure has never been verified as
instruction-tuned and is very likely a base/completion model). Comparing an
FP16 model directly against quantized ones would confound precision with
model quality, so CodeLlama's results are reported but excluded from the
primary cross-model ranking, and flagged wherever it appears.

## 4. Generation pipeline and conditions

Rule generation used a fork of Autogrep, an existing LLM-to-Semgrep-rule
pipeline, adapted to call the study's inference infrastructure and to consume
the curated case data described in §2. For each (model, case) pair, generation
was evaluated under two conditions:

- **Raw**: the model's first, completely untouched response to the prompt,
  independently re-evaluated — the model given one attempt, no feedback.
- **Autogrep**: the tool's own retry loop, which feeds a failed attempt's
  Semgrep validation error back to the model as feedback and allows up to
  three attempts total before giving up.

The prompt template used throughout (`autogrep_default`, the tool's original
built-in template) was selected over one alternative template evaluated during
pilot screening, on the basis of pilot performance (mean MCC 0.541 versus
0.394 for the alternative). Generation used temperature 0 (deterministic
decoding) for the primary benchmark; a temperature-0.2, five-repeat stability
condition over a stratified 100-case subset is reported separately (§7.3,
in progress as of this writing).

Each generated rule was validated by executing it with a pinned Semgrep
version (1.177.0) against all six samples of its case's ground-truth bundle
(§2.3), producing a true/false positive/negative outcome for each sample.

**C2/C3/C4 workflow comparability, summarized here and detailed in full in
`Research_Log/Workflow_Comparability_C2_C3_C4.md`**: the multi-agent
configurations introduced later in §7 (C2, C3, C4) share the same
underlying model pool and a 6-call budget ceiling, but a 2026-10-06/07
audit found they are NOT matched on several other dimensions — C3/C4's
Rule Generation call receives a compressed, agent-authored specification
rather than the raw diff C2 sees; C2 gets 3 repair rounds to C3/C4's 1;
and C3/C4's first acceptance check requires both a correct reviewer
verdict and the deterministic Semgrep result, while C2's check is
deterministic-only throughout. Every comparison across these
configurations in §7 is therefore presented as a comparison of complete,
differently-configured workflows, not an isolated test of role separation.

## 5. Evaluation metrics

Standard classification metrics (precision, recall, F1, false-positive rate,
specificity, balanced accuracy) and the Matthews Correlation Coefficient (MCC,
used as the primary overall discrimination metric) were computed from one
pooled confusion matrix per model per condition — every sample-level outcome
across every case in scope, summed, rather than a per-case average — consistent
with treating MCC as an "overall sample-level" measure. Study-specific metrics:

- **Patch Discrimination Score (PDS)**: the fraction of cases where the
  generated rule correctly fires on the original vulnerable sample and does
  not fire on the original patched sample.
- **Vulnerability Generalization Recall (VGR)**: the fraction of hidden
  vulnerable variants (the renamed and restructured samples, §2.3) that the
  rule correctly detects, pooled across all cases.
- **Balanced Semantic Drift Rate (BSDR)**: one minus balanced accuracy,
  reported alongside its two components (false-negative rate and
  false-positive rate).
- **End-to-End Successful Rule Rate (ESR)**: the fraction of cases where a
  rule meets every one of five conditions simultaneously — it compiles and
  executes, it detects the vulnerable sample at the correct location, it does
  not flag the patched sample, its VGR for that case meets a threshold, and
  its false-positive rate across the case's three negative samples meets a
  threshold. The design's protocol specifies a threshold-sensitivity sweep
  (VGR at 0.60/0.80/1.00, false-positive rate at 0.00/0.10/0.20).

**A methodological finding worth reporting explicitly**: with exactly two
hidden vulnerable variants and three negative samples per case, a case's own
VGR can only take the values {0, 0.5, 1.0} and its own false-positive rate only
{0, 0.33, 0.67, 1.0}. Consequently the prescribed 3×3 threshold sensitivity
sweep is degenerate for this bundle size — every one of the nine threshold
combinations produces an identical ESR value, verified directly rather than
argued analytically. This is reported as a limitation of the six-sample bundle
design at this size, not a limitation of the models evaluated: a bundle with
more than two hidden variants per case would be needed to make the prescribed
sensitivity analysis actually informative.

**A real scoring gap found and fixed during the 2026-10-06/07 audit**: VGR's
own definition above requires the hidden variant's finding to be at the
correct location, but that check was never actually implemented for the two
hidden vulnerable-variant samples specifically (it was correctly implemented
for the visible original-vulnerable sample throughout) — every VGR number
originally reported in earlier drafts of this document counted a Semgrep match
anywhere in the transformed file as a hit, not necessarily a match on the
transformed vulnerability itself. This was corrected retroactively (new
per-variant line-range annotations, derived without re-running any model or
Semgrep call — see `Research_Log/Correction_Log.md`, Finding 1): **21.6% of
all "detected" hidden-variant positives across the whole study (879 of 4,063)
were wrong-location matches**, now correctly reclassified. Every VGR/MCC number
in the sections below reflects this correction. The pilot screening numbers in
§6 have NOT been recomputed with this fix (out of scope for this audit pass,
since the pilot only ever informed the prompt-template/early-model-direction
decision, not any reported headline comparison) — flagged as an explicit,
not-yet-addressed gap rather than silently left inconsistent.

**Also clarified per the audit**: the pooled MCC/VGR/FPR/BSDR numbers reported
throughout are computed **only among cases where a rule was actually accepted**
— a *conditional* quality measure, not an end-to-end one. §7.9 (new) reports
the explicit end-to-end detection and end-to-end success rates — computed over
every requested case, with a missing or rejected rule counted as a failure on
every hidden-positive sample it never had a chance to flag, never silently
excluded from the denominator and never credited as a true negative for a scan
that never ran. The conditional metrics below should not, on their own, be
read as characterizing whole-system performance; §7.9 is the complete picture.

## 6. Results: pilot screening (40 cases)

The pilot screening run (8 models × 2 prompt templates × 40 cases, both
conditions) established the primary prompt template and gave an initial model
ranking. Headline pilot finding: `qwen2.5-coder:7b-instruct` ranked first
overall (mean MCC 0.598 across both prompt templates), narrowly ahead of the
larger `qwen2.5-coder:32b` (0.567) — notably, the smaller model in the same
family slightly outperformed the larger one on this task. Coverage (the
fraction of attempts producing any validated rule at all) was low across the
board: even the best model/prompt combination validated only 10 of 40 cases
(25%); the highest coverage anywhere in the full grid was 18 of 40 (45%).

## 7. Results: primary benchmark (300 cases)

### 7.1 Headline ranking [CORRECTED — see note below]

Restricting to the 150 eligible supported cases (§2.4,
`pipeline/eligible_cases.py` v2026-10-07.1 — 153 minus the 3 cases excluded
in audit round 2's Priority 2) — the design's primary comparison set — and
sorting by MCC under the autogrep (repaired) condition, **computed from the
corrected sample data (Finding 1's location-correctness fix,
`results_corrected/`)**:

| Rank | Model | MCC | PDS | VGR | FPR | ESR |
|---:|---|---:|---:|---:|---:|---:|
| 1 | DeepHat-V1-7B | 0.545 | 0.327* | 0.445* | 0.085* | 0.060 |
| 2 | Qwen2.5-Coder-32B | 0.539 | 0.261* | 0.533* | 0.123* | 0.047 |
| 3 | Yi-Coder-9B | 0.534 | 0.248* | 0.478* | 0.096* | 0.053 |
| 4 | CodeGemma-7B | 0.521 | 0.157* | 0.375* | 0.060* | 0.020 |
| 5 | Qwen2.5-Coder-7B-Instruct | 0.513 | 0.248* | 0.510* | 0.111* | 0.047 |
| 6 | Magicoder-7B | 0.427 | 0.065* | 0.233* | 0.067* | 0.007 |
| 7 | DeepSeek-Coder-6.7B | 0.373 | 0.085* | 0.222* | 0.074* | 0.013 |
| — | CodeLlama-7B-Instruct (FP16, precision outlier) | 0.510 | 0.150* | 0.292* | 0.056* | 0.007 |

*MCC and ESR are recomputed directly on the 150-case population
(`pipeline/build_step4_tables.py`); PDS/VGR/FPR columns marked `*` are
carried over from the 153-case computation rather than individually
rerun — §10's sensitivity table shows the 153→150 effect on MCC/ESR is
≤0.005 for 7 of 8 models (the one exception, Magicoder-7B, is shown with
its real recomputed 150-case MCC above, 0.427, not the stale 0.374), so the
carried-over PDS/VGR/FPR values are a reasonable approximation but not
independently verified at the 150-case population for this table.

**This ranking changed from an earlier draft of this document as a direct
consequence of the audit's Finding 1.** VGR (and therefore MCC, which pools
hidden-variant samples into its confusion matrix) had never actually checked
whether a hidden-variant detection landed on the correct, transformed
vulnerable construct — only whether Semgrep fired anywhere in the file. Fixed
retroactively without re-running any model (see §5's note above); 21.6% of
all hidden-variant "detections" study-wide were wrong-location matches, now
correctly reclassified as misses. The two models with the weakest
format-following/discipline elsewhere in this study (`deepseek-coder:6.7b`,
`magicoder:7b`) show the largest corrections, consistent with looser,
less-precisely-targeted rules having received more undeserved credit under
the uncorrected scoring — not noise. `qwen2.5-coder:7b-instruct`, previously
reported first, now ranks fifth; `DeepHat-V1-7B`, previously fifth, now ranks
first.

**This table reports conditional quality (among cases where a rule was
accepted) and should not be read alone as "the" measure of overall system
performance — §7.9 reports the end-to-end picture (computed over every
requested case, not just accepted ones), which is substantially more
sobering for every model.**

### 7.2 Secondary findings [numbers corrected]

- **Coverage and discrimination quality are not the same thing.** DeepHat had
  the highest raw coverage of any model on the full dataset (30.7% of
  attempts producing a validated rule) and now ALSO ranks first by corrected
  MCC on supported cases — unlike the pre-correction picture, where it ranked
  fifth. This specific secondary finding ("coverage and quality diverge") no
  longer holds for DeepHat specifically; it still holds in general (e.g.
  `codegemma:7b` has middling coverage and middling MCC, not a clean monotone
  relationship across all 8 models) — stated plainly as a changed conclusion,
  not silently dropped.
- **The strict end-to-end success bar (ESR) is far more demanding than raw
  coverage.** Across all eight models, corrected ESR ranges from 0.7% to 5.9%
  of supported cases — versus 10–31% raw coverage — because ESR additionally
  requires zero false positives across every negative sample, correct-location
  detection of both hidden variants, and the visible pair being discriminated
  correctly. This corroborates and sharpens the pilot's own low-coverage
  finding (§6), and is explored fully in §7.9's explicit end-to-end tables.
- **[CORRECTED, 2026-10-07 audit round 2] Feedback-driven repair produces a
  large conditional-MCC gain — but this is no longer reported as the
  study's headline finding, and the earlier claim that it was
  "statistically confirmed" is retracted.** Pooled across all eight models
  with repository-aware bootstrap on the 150-case eligible population, the
  raw-vs-autogrep conditional MCC gain is large for every model (e.g.
  `qwen2.5-coder:7b-instruct` moves from raw MCC 0.101 to autogrep MCC
  0.513) and each gap individually bootstraps to `p < 0.0001`. **But raw and
  autogrep conditional MCC are each computed only among that condition's own
  accepted cases — different, self-selected populations, not the same 150
  cases for both** — so this comparison cannot distinguish "repair makes the
  same cases' rules better" from "repair changes which cases become
  acceptable at all." Repeating the comparison on the end-to-end metric
  (§7.9: identical 150-case denominator for both conditions, no selection
  effect) shows **0 of 8 models with a statistically detectable raw-vs-
  autogrep difference after Holm correction** (repo-aware bootstrap,
  `results_corrected/section22_corrected_report_round2.txt`, Comparison 4).
  Both numbers are reported in §7.8/§7.9; the end-to-end result, not the
  conditional-MCC gap, is what this paper's conclusion is built on.

### 7.3 Stability experiment

A five-repetition, temperature-0.2 run over a stratified 100-case subset (drawn
proportionally by language and representability label from the 300-case set,
with the selection method and random seed fixed before any primary-run result
existed, to avoid post-hoc subset selection) was run following completion of
the primary run described in §7.1–7.2.

**Case-level outcome agreement is high across all eight models.** For each
case and model, the fraction of the five repeats matching the single most
common outcome (both for the narrow validate-or-not outcome and for the full
six-sample bundle pattern) ranges from 93.3% to 98.4% — even the least
consistent model agrees with its own most frequent result on roughly 19 of
every 20 repeats.

**Metric-level spread on the 51 supported cases within the subset** (autogrep
condition, MCC mean/min/max across the five repeats, **corrected data**):

| Model | MCC mean | MCC min | MCC max |
|---|---:|---:|---:|
| Yi-Coder-9B | 0.522 | 0.443 | 0.575 |
| CodeGemma-7B | 0.517 | 0.496 | 0.543 |
| DeepHat-V1-7B | 0.515 | 0.458 | 0.605 |
| Magicoder-7B | 0.485 | 0.364 | 0.592 |
| Qwen2.5-Coder-7B-Instruct | 0.481 | 0.451 | 0.507 |
| CodeLlama-7B-Instruct (FP16) | 0.471 | 0.422 | 0.505 |
| Qwen2.5-Coder-32B | 0.452 | 0.424 | 0.479 |
| DeepSeek-Coder-6.7B | 0.419 | 0.385 | 0.509 |

**[CORRECTED, 2026-10-07 audit round 2, Priority 8] A methodological
finding, re-investigated and now resolved for most of the ranking, with a
smaller residual explicitly flagged rather than left as a blanket
mystery.** Before correction, this section claimed the stability-run
ranking's mismatch with §7.1's primary ranking was fully explained by
case-composition (restricting the primary run's own temperature-0 results
to the same 51-case subset reproduced the stability ranking almost
exactly). Re-checked after applying the Finding-1 correction to both sides:
the match was no longer close, and round 1 left this flagged as an open,
uninvestigated discrepancy. Investigating it directly for this audit pass:

- **Ruled out a script/config bug first.** This table's own generating
  script (`pipeline/analyze_phase5_stability.py`) was found, while
  investigating this discrepancy, to still be reading `sample_execution_log`
  from the uncorrected `results/` tree in every code path, despite this
  document labeling its output "corrected data" — that label was not
  actually true of the script's own committed state (likely a one-off
  corrected run was done by hand and never fixed back into the script).
  Fixed to read from `results_corrected/`, matching the pattern used
  throughout the rest of this audit; rerunning now reproduces this table's
  existing numbers almost exactly (one model, Magicoder-7B, shifts by
  0.008 due to Priority 1's later manual location-annotation fixes). The
  table above is correct and reproducible going forward — this was a
  pipeline-hygiene problem, not the source of the ranking discrepancy.
- **Ruled out an averaging-method artifact.** "MCC mean" above averages 5
  separately-computed per-repeat MCC values; pooling all 5 repeats' raw
  samples into one confusion matrix per model and computing MCC once
  instead produces essentially the same ranking (`yi-coder` >
  `codegemma` > `DeepHat` > `magicoder` ≈ `qwen7b` > `codellama` >
  `qwen32b` > `deepseek-coder`) — ruling out mean-of-ratios vs.
  ratio-of-pooled-sums as the explanation.
- **Confirmed identical run configuration apart from temperature.**
  Diffing `environment.json` between the primary (temp 0) and stability
  (temp 0.2) runs for the models with the largest rank swaps shows the same
  host, same Autogrep commit, same Semgrep version, same prompt variant —
  temperature is the only varied setting.
- **For 6 of 8 models, the single temp-0 draw's MCC falls inside that
  model's own 5-repeat temp-0.2 range**, computed directly:
  `qwen2.5-coder:7b-instruct` (0.499, range [0.451, 0.507]), `DeepHat-V1-7B`
  (0.492, [0.458, 0.605]), `deepseek-coder:6.7b` (0.452, [0.385, 0.509]),
  `codegemma:7b` (0.528, [0.496, 0.543]), `magicoder:7b` (0.422,
  [0.364, 0.592]), `yi-coder:9b` (0.557, [0.443, 0.575]). **This resolves
  the bulk of the apparent ranking swap**: several models' MCCs cluster
  tightly (roughly 0.45–0.57) at this 51-case subset size, where ordinary
  single-draw sampling noise is enough to reorder them — the temp-0
  ranking is one specific noisy realization, not a more "correct" ranking
  than the 5-repeat average.
- **2 of 8 models are a genuine, same-direction exception, not explained by
  ordinary sampling noise, and reported as an open hypothesis rather than
  resolved**: `qwen2.5-coder:32b` (temp-0 MCC 0.550, ABOVE its entire
  5-repeat range [0.424, 0.479]) and `codellama:7b-instruct-fp16` (temp-0
  MCC 0.566, ABOVE its entire 5-repeat range [0.422, 0.505]) both score
  better at temp=0 than on any of their 5 stochastic draws. One plausible,
  untested hypothesis: determinism specifically benefits these two models
  more than the others — `codellama` is already flagged elsewhere in this
  document as precision/quantization-confounded, and a quantized or
  otherwise less-robust model could plausibly be more sensitive to
  temperature-induced decode variance than the others. This is stated as a
  hypothesis, not confirmed; a direct case-level investigation of which
  specific samples flip for these two models would be needed to test it,
  and was not run as part of this audit.

**Net status**: the original "case composition, not temperature" explanation
remains withdrawn (it does not hold under corrected scoring). In its place,
6 of 8 models' ranking swap is now resolved as ordinary single-draw sampling
variation among closely-clustered MCCs, confirmed not to be a script, config,
or averaging-method artifact. `qwen2.5-coder:32b` and `codellama:7b-instruct-fp16`
remain a genuine, unresolved residual, carried forward as an open hypothesis
rather than a confirmed mechanism.

### 7.4 C2 (iterative single agent): an interim comparison

The design's multi-agent configurations (§4) include C2, "the same model
generates, interprets Semgrep feedback, and repairs its rule," under an
explicit per-case budget (at most 6 LLM calls, 30,000 combined input tokens,
6,000 combined output tokens, 3 repair rounds, 10 minutes wall clock). This
is distinct from the study's existing "autogrep" condition in two ways:
autogrep's own retry loop has no cumulative token or wall-clock budget (only
a 3-attempt cap), and C2's purpose is specifically to be the fair,
budget-matched baseline for an eventual C2-vs-C3 (multi-agent) comparison —
C3 does not exist yet, so what follows is an interim reference point, not
the design's intended final test.

One methodological choice is worth surfacing: the budget's own numbers
resolve an ambiguity the spec's prose leaves open. Interpreting "interprets
feedback, and repairs" as two calls per round would total seven calls across
three rounds plus the initial generation — over the six-call limit on its
own. Only a one-call-per-round reading (interpretation and repair combined
in a single prompt) fits within budget, so that is what was implemented.

Run on the 150 eligible supported cases (`pipeline/eligible_cases.py`
v2026-10-07.1), all eight primary models, at temperature 0 (matching §4's
primary deterministic configuration; the design specifies no temperature
for C2 itself):

**C2's conditional MCC is nearly indistinguishable from the autogrep
condition's for most models**: 5 of 8 models match to three decimal places
exactly (CodeGemma-7B 0.521 vs. 0.521; Qwen2.5-Coder-32B 0.539 vs. 0.539;
DeepHat-V1-7B 0.545 vs. 0.545; DeepSeek-Coder-6.7B 0.373 vs. 0.373;
CodeLlama-7B-Instruct 0.510 vs. 0.510), and the largest remaining gap
(Magicoder-7B, 0.403 vs. 0.427) is still modest. Models used an average of
3.0–3.7 of the 6 available calls; a small number of cases per model (1–3 of
150) were bound by the output-token cap specifically, showing it is a real
constraint and not merely a theoretical one.

**[CORRECTED, 2026-10-07] Every model's C2 conditional MCC is far above its
raw (single-shot) conditional MCC — but this is no longer presented as "the
single most robust finding in the study," and the earlier "p≈0.0000"
figure is retracted along with it.** Re-examining this comparison for audit
round 2's Priority 6/8: conditional MCC for raw and C2 is each computed only
among that condition's OWN accepted cases — different, self-selected
populations, not the same 150 cases for both. Repeating the comparison on
the end-to-end metric instead (§7.9: same 150-case denominator for every
condition, no selection effect) shows **0 of 8 models with a statistically
detectable raw-vs-C2 difference after Holm correction** (repo-aware
bootstrap, `results_corrected/section22_corrected_report_round2.txt`,
Comparison 5) — a materially different conclusion from the conditional-MCC
read above. Both numbers are reported here, but the end-to-end result is
the one this paper's conclusion is built on; the large conditional-MCC gap
is consistent with "repair changes which cases become acceptable" and
cannot, on its own, support a claim that repair improves rule quality on a
fixed population of cases.

**Interim reading, stated as interim**: giving a single model a richer,
explicitly budgeted repair loop produces conditional MCC about as well as
the simpler retry mechanism already built into the pipeline, among each
condition's own accepted cases — but neither condition detectably
outperforms the other end-to-end, on the shared 150-case population. If a
future C3 is to outperform C2, the design's own framing suggests the
mechanism will need to be genuine role specialization, not simply more
attempts at the same undifferentiated task — and any such claim should be
checked against the end-to-end metric, not conditional MCC alone.

### 7.5 Role-capability screening (Phase 3, complete)

The design calls for testing each of five prospective multi-agent roles'
capability on "pilot or development data" before assigning models to roles
by measured performance rather than by hypothesis (§19 of the design
document). A fresh 50-case development partition was considered and
deliberately not curated: the design's own phrasing treats it as optional
("if available"), and reusing the existing 40-case pilot set — already
fully bundled and already screened across all eight primary models — avoids
a multi-day repeat of the curation pipeline for a data-independence benefit
the design does not require.

Of this role's five sub-tasks, "rule generation" needed no new work (the
pilot's own per-model MCC/ESR/PDS figures, §6, answer it directly). The
other four each needed a new prompt, response schema, and measurement
harness, built and run one at a time:

**Syntax review** (diagnose YAML/Semgrep-DSL problems; selection measurement:
diagnosis accuracy and compilation-recovery rate). A 45-item test set was
mined from real pilot generation failures, stratified across three
ground-truth categories: a YAML-level parse failure, a genuine Semgrep
pattern/DSL rejection, and — a deliberate negative-control category — a rule
that compiled and ran correctly but simply discriminated incorrectly (i.e.,
nothing for a syntax reviewer to fix). Candidates (Qwen2.5-Coder-7B-Instruct,
Magicoder-7B) were asked to diagnose the category and, where applicable,
propose a corrected rule, re-validated by real re-execution.

| Model | Overall diagnosis accuracy | Compilation-recovery rate |
|---|---:|---:|
| Qwen2.5-Coder-7B-Instruct | 66.7% | 3.3% |
| Magicoder-7B | 26.7% | 0.0% |

Magicoder's low score is substantially a format-compliance failure (42% of
its responses did not follow the requested structure at all), consistent
with its weaker instruction-following noted elsewhere in this study. Both
models were specifically weak at recognizing the negative-control category
(correctly concluding "no syntax problem here": 20.0% and 0.0%) — both tend
to diagnose a syntax issue even when none exists, a real and consistent
finding rather than a test artifact. Role assigned to
**Qwen2.5-Coder-7B-Instruct**.

**Rule repair** (revise a failing rule; selection measurement: repair
success and **post-repair over-broad rate**, both newly operationalized here
since the design names them without exact formulas). Reusing the same
45-item test set under a repair-framed prompt, across the three candidates
named in the design (Qwen2.5-Coder-32B, DeepHat-V1-7B, Qwen3-Coder-Next):

| Model | Repair success rate | Post-repair over-broad rate (of successes) |
|---|---:|---:|
| Qwen2.5-Coder-32B | 4.4% (2/45) | 50.0% |
| DeepHat-V1-7B | 0.0% | n/a |
| Qwen3-Coder-Next | 0.0% | n/a |

**Terminology correction (2026-10-06/07 audit)**: this column was originally
labeled "regression rate," which implies a previously-working behavior was
damaged by repair. No such before/after comparison exists or is possible
here — every input rule was already broken (that's why repair was invoked),
so there is no "before" state to regress from. What this column actually
measures, confirmed directly against the scoring code: among the rules that
passed repair's narrow visible-pair re-check, whether the repaired rule ALSO
produces a false positive elsewhere in the case's full six-sample bundle —
i.e., whether the fix that satisfied the narrow check is over-broad. Renamed
throughout to reflect this.

These absolute numbers are low across every model — manually re-verified to
rule out a measurement artifact (one failed attempt was independently
re-validated outside the harness and confirmed to be a genuine Semgrep
pattern rejection). This is read as a real property of the *task as tested*
— a single repair call with no iteration and no structured review input —
rather than evidence about the full multi-agent workflow, where the actual
Rule Repair Agent receives up to three rounds and structured diagnostic
output from dedicated review agents. Qwen2.5-Coder-32B is nonetheless the
only candidate with any measured success, and is assigned the role on that
basis, consistent with the design's instruction to follow measured
performance over the preliminary hypothesis table.

**Semantic review and patch analysis** are not yet complete as of this
writing. The semantic-review test set (67 items, five categories: miss,
patched-code finding, over-generalization, under-generalization, and a
"nothing wrong" control) was constructed with particular care around the
design's hidden-evaluation-protection rule (§17.3): the three
generalization-related categories are, by construction, indistinguishable
from what a real agent is permitted to see (the rule and the original
vulnerable/patched pair's outcome only — never the hidden transformed
variants or look-alikes used to derive the label), so scoring on those
categories is a genuine test of judgment from patch evidence rather than a
test of reading back visible execution results. One candidate
(DeepHat-V1-7B) is complete and shows a degenerate pattern worth flagging
methodologically: its apparent 22.4% accuracy is fully explained by always
predicting a single category, which happens to match its prevalence in the
test set — i.e., zero measured diagnostic capability once the base rate is
accounted for, not partial competence.

**DeepSeek-R1-14B**, the first of the two reasoning-model candidates to
complete, scores 40.3% overall — genuinely non-degenerate, unlike DeepHat's
result: 73.3% on the patched-code-finding category and 75.0% on the
"nothing wrong" control, but only 7.1% on each of the two generalization
categories specifically. This pattern — strong on the two categories
directly readable from the visible execution outcome, weak on the two
requiring actual judgment from patch evidence alone — is consistent with
what the test is designed to isolate, and is a real, substantive
capability difference from DeepHat's constant-answer pattern.

Both reasoning models are substantially slower per item than the
non-reasoning candidate (on the order of 100× in per-item latency), and
running them required moving the work to a persistent remote session rather
than a local one-shot invocation. Two tooling issues surfaced during this
evaluation are worth noting for methodological transparency, even though
neither affects any number reported here: a latent bug in the retry/resume
logic (keying retries by case and category alone, which collides when
different source models independently produce the same failure category
for the same case) caused one of DeepSeek-R1's 67 test items to be silently
dropped rather than scored, caught and corrected before the figure above
was finalized (which reflects the complete, re-verified 67-item
evaluation); and **QwQ-32B could not be reliably evaluated on the available
infrastructure** — the majority of its requests failed to return a response
within a 10-minute timeout, well beyond what any other candidate model in
this study required. QwQ-32B is therefore recorded as inconclusive for this
role rather than scored, a statement about infrastructure availability, not
a measured capability finding. The role is assigned to **DeepSeek-R1-14B**
on the basis of the completed comparison.

**Patch analysis** required a hand-labeled ground-truth subset rather than a
derivation from existing execution data, since its selection measurement
(mechanism/source/sink/fix accuracy) is inherently free-text rather than a
clean categorical label. Fifteen pilot cases were hand-annotated directly
from each case's real diff and, where the diff alone was insufficient,
corroborating evidence (the upstream fixing commit, the official security
advisory, or — for one case, a regular-expression denial-of-service claim —
a live empirical timing test). This annotation went through five rounds of
independent review before being treated as settled, catching along the way
a specific factual error in an initial draft (a claimed bypass of a path
sanity check that further analysis showed does not actually work) and a
genuine implementation defect in one patch's own fix that had gone
unnoticed (a null-dereference inside an error-handling branch). Several
entries are deliberately marked as evidence-limited — some detail a real
patch fixes is simply not recoverable from the diff and context available,
and the final ground truth says so explicitly rather than filling the gap
with a plausible-sounding guess.

Scoring free-text answers against this ground truth required a different
approach from the categorical roles: a fixed judge model (never one of the
role's own candidates, the same model already used elsewhere in this study
to avoid self-certification) rates each of a candidate's four fields
against the ground truth and its own documented evidence limitations. A
candidate that correctly states that something is not established by the
available evidence is scored as a correct outcome — the same standard the
ground truth itself was held to — while a candidate that asserts
unsupported specifics is scored as incorrect even when those specifics
sound individually plausible.

| Model | Overall | Mechanism | Source | Sink | Fix |
|---|---:|---:|---:|---:|---:|
| Qwen3-Coder-Next | 31.7% | 6.7% | 33.3% | 33.3% | 53.3% |
| DeepSeek-R1-14B | 25.0% | 13.3% | 20.0% | 6.7% | 60.0% |

Both models are weakest at explaining *why* a vulnerability is exploitable
and strongest at describing what the patch does — a consistent pattern
across both candidates rather than an artifact of either model's specific
behavior, and broadly consistent with this role's difficulty relative to
the more mechanically checkable roles. QwQ-32B was again excluded on
infrastructure grounds (§7.5 above), not evaluated capability. Role
assigned to **Qwen3-Coder-Next** on the basis of its modest but consistent
lead.

**All five agent roles are now assigned, completing role-capability
screening** (design §19): rule generation needed no new screening (§6);
syntax review → Qwen2.5-Coder-7B-Instruct; rule repair →
Qwen2.5-Coder-32B; semantic review → DeepSeek-R1-14B; patch analysis →
Qwen3-Coder-Next. These per-role assignments are reserved for C4-A ("best
pilot model assigned to each role") — a separate, later configuration. C3
itself, described next, uses a single model across every role, per its own
definition (§18.3).

### 7.6 C3 (homogeneous multi-agent): a root-caused coverage finding [CORRECTED]

**Read this note before the rest of the section.** A 2026-10-06/07 audit found
and fixed two things that affect every number and claim below: (1) Finding 1,
the location-correctness scoring gap described in §5, which moves every MCC/VGR
value; (2) a workflow-comparability audit (`Research_Log/
Workflow_Comparability_C2_C3_C4.md`) found that C2 and C3 are NOT matched on
generator input or repair-round count, despite the design document's own
framing suggesting they are — C3's Rule Generation call never sees the raw
diff (only a Patch Analysis agent's 4-field summary, unlike C2's full prompt),
and C2 gets 3 repair rounds to C3's 1. **Any difference between C2 and C3
reported below should be read as a difference between two complete,
differently-configured workflows, not as an isolated test of "role separation"
as a single causal variable** — the original framing below is preserved but
explicitly hedged throughout.

C3 assigns one model to every role in the §17.1 workflow (Patch Analysis →
Rule Generation → Syntax Review → Semgrep Executor → Semantic Review →
[repair → Syntax Review] → Hidden Evaluator), in two variants distinguished
by parameter scale: C3-S (Qwen2.5-Coder-32B) and C3-E (Qwen2.5-Coder-7B-Instruct,
also this study's top single-agent performer). The design's own per-call
budget (§20) does not fit the workflow as literally diagrammed if a full
Semantic Review call re-runs after every repair round — a single pass alone
already costs four of the six available calls. This was resolved by
allowing exactly one repair round, whose post-repair accept/reject decision
uses the deterministic Semgrep Executor's result directly rather than a
second Semantic Review call — spending the full six-call budget with no
slack, rather than silently exceeding it.

**C3-E's results (150 eligible supported cases)**: 13 accepted (8.7%
coverage), every one on the first pass — not one of 140 repair attempts
recovered a case. Pooled MCC over the accepted cases is 0.545 (corrected),
close to this same model's MCC under the simpler C2 (0.502, corrected) and
autogrep (0.513, corrected) conditions — quality among accepted rules is not
materially worse here. Coverage is: the
single-agent conditions accept something on roughly a quarter to a third of
cases; C3-E accepts on well under a tenth.

The zero-recovery repair finding was investigated rather than reported at
face value. In 139 of the 140 rejected episodes, the Semantic Review step
had judged the rule ACCEPTED despite the deterministic check failing it —
a near-total disagreement between the model's self-assessment and the
ground-truth execution result it was shown. A direct test isolated why:
presenting the identical visible-evidence pattern (both samples "not
detected," what a parse-broken rule looks like from the outside) alongside
a deliberately nonsensical rule produced a correct NOT_ACCEPTED verdict with
a sensible repair instruction. The same model, given the same kind of
evidence, judges correctly when the rule under review looks obviously
wrong — and apparently defers to a rule's surface plausibility (well-formed
YAML, sensible metadata, a specific CWE tag) over the explicit execution
evidence when the rule looks competent but has a subtler flaw. This failure
mode has no analogue in the single-agent conditions, which never ask a
model to judge its own rule's acceptability — they check the deterministic
Semgrep result directly. It is consistent with an independent observation
from a verification pass before the full run: the same model's Syntax
Review step correctly diagnosed a DSL-level error in one case but proposed
a "correction" reproducing the identical invalid syntax, unchanged.

**C3-S's results tell a different story.** Coverage is 35/150 (23.3%,
against C3-E's 8.7%), and the repair round actually recovers cases: 12 of
130 attempts (9.2%), against C3-E's zero. The larger model's self-assessment
weakness clearly attenuates with scale — a live check reproduced the exact
scenario from §7.6's investigation (an obviously broken rule given the same
visible-evidence pattern) and this time Semantic Review correctly rejected
it — though it does not disappear: 90.8% of repair attempts still fail.

This makes the design's own main comparison (§18.3: C3 against C2 under the
same model and nominal budget) directly answerable for both model scales,
using data already collected — no further runs were needed, since C2's
original primary run already covered both models. **As established in the
note at the top of this section, C2 and C3 are not matched on generator
input or repair-round count — this is a comparison of two complete,
differently-configured workflows that happen to share a model and a
call-count ceiling, not an isolated test of "role separation."**

**[CORRECTED]**

| Model | Condition | Coverage | MCC | VGR | FPR | PDS |
|---|---|---:|---:|---:|---:|---:|
| Qwen2.5-Coder-32B | C3-S | 23.3% | **0.649** | 0.714 | 0.143 | 0.220 |
| Qwen2.5-Coder-32B | C2 | 30.0% | 0.539 | 0.544 | 0.126 | 0.260 |
| Qwen2.5-Coder-7B-Instruct | C3-E | 8.7% | 0.545 | 0.538 | 0.154 | 0.087 |
| Qwen2.5-Coder-7B-Instruct | C2 | 32.0% | 0.502 | 0.490 | 0.111 | 0.253 |

The two model scales still produce an opposite-signed pattern after
correction, though the magnitudes moved: for the larger model, C3-S trades
coverage for a real MCC gain over C2 (0.539 → 0.649), still driven mainly by
better VGR (0.544 → 0.714). For the smaller model, C3-E trades away most of
its coverage for a small, likely-noise MCC difference (0.502 → 0.545).

**What can and cannot be claimed here, stated precisely per the audit**:
the pattern above is consistent with "role separation helps a capable model
and doesn't help (or mildly hurts) a weaker one," and the root-caused
self-assessment-weakness mechanism described above is directly observed
(not inferred) — the live verification tests of Semantic Review's behavior
on deliberately-broken rules are real, reproducible evidence. But because C2
and C3 differ in more than just role separation (§7.6's opening note), **this
pattern cannot be attributed to role separation ALONE** without a controlled
ablation that holds generator input and repair-round count fixed while
varying only whether roles are separated — not run in this study. Presented
here as a hypothesis consistent with the evidence, not a confirmed causal
finding.

This comparison is still scoped to one specific budget resolution (one
repair round, no second Semantic Review call, §7.6). Whether an
unrestricted-budget variant — §20 explicitly permits this as a secondary
analysis — narrows or widens the gap in either direction remains open.

**Formal significance testing (§7.8, rerun on the 150-case eligible
population with repository-aware bootstrapping extended to both metrics)**:
the `qwen2.5-coder:32b` C2-vs-C3-S MCC difference is **not statistically
significant** — 95% CI (−0.238, +0.020), p = 0.099 — and neither is the
end-to-end (ESR) difference between the same two conditions, p = 0.909. The
`qwen2.5-coder:7b-instruct` C2-vs-C3-E difference is also not significant on
either metric (MCC p = 0.633; ESR p = 0.121), with wide CIs that cross zero.
**Report both as "no statistically detectable difference," not as evidence
of equivalence and not as a confirmed role-separation effect** — the point
estimates above are directionally suggestive but neither comparison clears
conventional significance at this sample size on either metric.

### 7.7 C4-A (heterogeneous, best model per role): measured-best roles do not compose [CORRECTED]

**Read §7.6's opening note first** — the same Finding-1 correction and the
same workflow-comparability caveats (C4 shares C3's workflow/budget
asymmetries relative to C2) apply here. Additionally, Step 5's audit found
C4's generator input is identical to C3's (a Patch Analysis summary, not the
raw diff) — so the C3-vs-C4 comparison below is cleaner than C2-vs-C3 (same
generator-input shape, same repair-round count throughout), but still not a
controlled ablation isolating "which model per role" as the only variable.

C4-A assigns each of the five Section 17.1 roles the model Phase 3's
role-capability screening (§7.5) measured as individually best for that
role: patch analysis → `qwen3-coder-next:latest`, rule generation and
syntax review → `qwen2.5-coder:7b-instruct`, semantic review →
`deepseek-r1:14b`, rule repair → `qwen2.5-coder:32b`. No new model
selection was needed — this configuration is exactly Phase 3's measured
output, run once through the unchanged §17.1 workflow and §20 budget.

Full run on all 153 of the then-current supported cases, verified complete
(153/153 episodes, 66 sample records = 11 accepted × 6, exact match) —
figures below rerun on the 150-case eligible population (§2.4) alongside
every other condition measured so far on the same case set:

| Condition | Roles | Coverage | MCC | VGR | FPR | PDS |
|---|---|---|---|---|---|---|
| C3-S | all roles: 32B | 23.3% | **0.649** | 0.714 | 0.143 | 0.220 |
| C2 (32B) | single agent | 30.0% | 0.539 | 0.544 | 0.126 | 0.260 |
| C2 (7B) | single agent | 32.0% | 0.502 | 0.490 | 0.111 | 0.253 |
| C3-E | all roles: 7B | 8.7% | 0.545 | 0.538 | 0.154 | 0.087 |
| **C4-A** | best model per role (4 distinct models) | **7.3%** | **0.524** | 0.545 | 0.152 | **0.067** |

**C4-A is the lowest-performing condition measured so far on MCC and PDS**,
and close to lowest on VGR. This is a striking result on its face precisely
because the role assignments are not arbitrary — each one is the
pilot-measured best performer for that specific role (§7.5) — yet the
composed five-role pipeline underperforms both C3-S (a single strong model
doing every role) and even the plain single-agent C2 baselines.

**Candidate mechanism, explicitly presented as an untested HYPOTHESIS, not a
confirmed finding**: Phase 3's role screening evaluated each role in
isolation, against fixed, pre-built test items — never against another
LLM's live output produced in situ. C4-A composes `qwen3-coder-next`'s
patch-analysis output into `qwen2.5-coder:7b-instruct`'s rule-generation
prompt, and `deepseek-r1:14b`'s natural-language repair instructions into
`qwen2.5-coder:32b`'s repair call — pairings that were never jointly
measured during screening. C3-S and C3-E avoid this by construction: one
model, one output convention, internally consistent at every hand-off. **This
pattern is consistent with the hypothesis that per-role screening metrics
don't compose additively across a heterogeneous pipeline — but §7.8's
formal significance testing on corrected data finds NONE of the pairwise MCC
differences among {C3-S, C3-E, C4-A, C4-B} reach even uncorrected
significance.** The "interface mismatch" explanation should be read as a
plausible account of the observed point estimates, not a statistically
confirmed effect, and not confirmed by inspecting individual episodes'
intermediate hand-offs directly (that would be the natural next step if this
hypothesis is to be tested properly).

C4-B (two models — `32b` for analysis/generation/repair, `7b-instruct` for
syntax/semantic review, reusing the C3-S/C3-E pair) is the natural next
test of whether partial heterogeneity degrades more gracefully than
C4-A's four-distinct-model configuration, or whether any cross-model
interface mismatch is enough to reproduce the same collapse.

**C4-B result: it does degrade more gracefully — quality is essentially
preserved.** Full run, 153/153 of the then-current supported cases complete
(26 accepted, 17.3% coverage on the 150-case eligible population — between
C4-A's 7.3% and C3-S's 23.3%, as expected for "some heterogeneity, not
maximal"). Pooled quality metrics (corrected, 150-case population): MCC
0.668, VGR 0.788, FPR 0.192, PDS 0.173.

The complete six-condition picture, ranked by MCC **[CORRECTED]**:

| Condition | Roles | Coverage | MCC | VGR | FPR | PDS |
|---|---|---|---|---|---|---|
| **C4-B** | 32B (analysis/gen/repair) + 7B (syntax/semantic) | 17.3% | **0.668** | **0.788** | 0.192 | 0.173 |
| C3-S | all roles: 32B | 23.3% | 0.649 | 0.714 | 0.143 | 0.220 |
| C2 (32B) | single agent | 30.0% | 0.539 | 0.544 | 0.126 | 0.260 |
| C3-E | all roles: 7B | 8.7% | 0.545 | 0.538 | 0.154 | 0.087 |
| C2 (7B) | single agent | 32.0% | 0.502 | 0.490 | 0.111 | 0.253 |
| C4-A | best model per role (4 distinct models) | 7.3% | 0.524 | 0.545 | 0.152 | 0.067 |

**C4-B's corrected MCC (0.668) is now the highest of all six conditions**,
narrowly ahead of C3-S (0.649), and its VGR (0.788) remains the highest of
every condition tested. The pattern is the same shape as before correction:
C4-B's two-model split mirrors C3-S/C3-E's own internal role pairing (one
convention for analysis/generation/repair, another for the two review
roles) spread across two models rather than collapsed into one, and
preserves C3-S-level quality; C4-A's four-distinct-model split collapses on
every metric except FPR. **But see the significance testing immediately
below: this ranking is a point-estimate description, not a statistically
confirmed ordering.**

**Stated plainly, not just the favorable half**: C4-B's FPR (0.192) is the
*worst* of all six conditions, moderately higher than C3-S's 0.143. The
quality picture is not a uniform win — VGR improves, MCC holds or improves,
but false-positive rate drifts upward.

Both C4 configurations are now complete.

### 7.8 Formal statistical analysis (§22) [CORRECTED, rerun on corrected data]

The 7 predefined comparisons (§22.3), formally tested on the 153 supported
cases, **rerun in full against the Finding-1-corrected data, with
repository-aware bootstrapping applied consistently to every comparison**
(the original run used case-level bootstrapping for the 7 main comparisons
and repository-level for the subgroup analysis only — an inconsistency found
during the audit and fixed here; cases from the same repository are not
independent, and every comparison below now accounts for that). Full
methodology in `Research_Log/Section22_Scope.md`; full output in
`results_corrected/comparisons_1_7_corrected_report.txt`.

One methodology note stated up front: §22.2 specifies Wilcoxon
signed-rank for paired MCC, but MCC here has always been a pooled
statistic (no natural per-case value exists) — resolved with a
repository-level paired bootstrap (resample repositories with replacement,
recompute each condition's pooled MCC per resample, report the 95% CI and a
two-sided bootstrap p-value on the difference) instead, reserving real
Wilcoxon for genuinely per-case scalars and McNemar for the per-case
binary ESR outcome. Per the audit's explicit instruction, every
nonsignificant result below is reported as **"no statistically detectable
difference"** — not as evidence of equivalence.

**Results [CORRECTED, 2026-10-07 audit round 2, Priority 6]**: rerun on the
150-case eligible population (`pipeline/eligible_cases.py` v2026-10-07.1),
with repository-aware bootstrapping now extended to the ESR/end-to-end
metric as well as MCC (not just McNemar, which assumes independent pairs —
false here per `Section22_Scope.md`'s own stated principle). Both metrics
are reported for every comparison, and the end-to-end (ESR) result is what
significance/Holm-correction decisions are based on; the conditional-MCC
result is reported alongside but flagged wherever it reflects different,
self-selected accepted-case populations rather than a same-population
comparison. Full output:
`results_corrected/section22_corrected_report_round2.txt`.

1. **Qwen2.5-Coder 7B vs 32B**: no statistically detectable difference on
   either metric (ESR repo-aware bootstrap p = 1.000; conditional MCC
   p = 0.586) — consistent with both scales performing comparably on this
   task, though this is not evidence they are equivalent.
2. **Qwen2.5-Coder 7B vs DeepHat 7B**: no statistically detectable
   difference on either metric (ESR p = 0.551; MCC p = 0.463).
3. **Small code-model family effect** (6 models, ~7–9B scale, Friedman on
   ESR): omnibus **is** significant (p = 0.008). Running the Holm-corrected
   pairwise follow-ups with the same repo-aware bootstrap used for MCC
   (not McNemar), **2 of 15 pairs survive correction**: CodeGemma-7B vs
   DeepHat-V1-7B (Holm-adj p = 0.042) and Magicoder-7B vs Yi-Coder-9B
   (Holm-adj p = 0.039). A real, specific aggregate difference exists
   within this family at the ~7–9B scale, not just an unresolved omnibus
   signal.
4. **Raw vs Autogrep, all 8 models**: **0 of 8 models show a statistically
   detectable end-to-end (ESR) difference after Holm correction**
   (repo-aware bootstrap p ranging 0.10–1.00, all non-significant). The
   **conditional-MCC bootstrap shows a large, "p < 0.0001" difference for
   every model** (e.g. `qwen2.5-coder:7b-instruct` 0.101 → 0.513) — but
   raw and autogrep conditional MCC are each computed only among that
   condition's own accepted cases, not the same 150 cases for both, so
   this is evidence repair changes which cases become acceptable, not
   directly evidence it improves rule quality on a fixed population. **This
   replaces the earlier claim that the MCC gain was "the single most
   robust, best-powered finding in the whole analysis" — on the metric
   with no selection-effect confound, there is no detectable difference.**
5. **C1 vs C2**: same shape and conclusion as #4 for all 8 models — 0 of 8
   detectable end-to-end, large but selection-confounded conditional-MCC
   gaps (expected, since C2 and Autogrep were already known to track
   closely).
6. **C2 vs C3**: no statistically detectable difference on either metric
   for either model pair (ESR — 32B: p = 0.909; 7B: p = 0.121 — MCC — 32B:
   p = 0.099; 7B: p = 0.633). Report as "no statistically detectable
   difference," not as evidence the two conditions perform equivalently,
   and not as a confirmed role-separation effect even for the 32B pair,
   which trends in that direction on MCC without clearing significance on
   either metric.
7. **C3 vs C4**: Friedman omnibus on ESR is significant (p = 0.028,
   consistent with round 1's finding). Running BOTH pairwise follow-up
   families with the repo-aware bootstrap: of the 6 ESR pairs, **none reach
   significance after Holm correction** (closest: C3-S vs C4-A, raw
   p = 0.024, Holm-adjusted p = 0.142); of the 6 conditional-MCC pairs
   (the metric the original C4-A/C4-B narrative was built on), **none reach
   significance after Holm correction either** (closest: C3-S vs C4-A, raw
   p = 0.107, Holm-adjusted p = 0.644). The omnibus signal does not resolve
   into any specific confirmed pairwise difference on either metric.

**Overall reading [CORRECTED, 2026-10-07 audit round 2]**: this study's
previously-reported headline finding — that feedback-driven repair
produces a large, statistically established end-to-end quality improvement
— does not survive repeating the comparison on a metric without the
conditional-MCC selection-effect confound. **Across every one of the 7
predefined comparisons, 0 of 8 per-model end-to-end (ESR) differences are
statistically detectable after Holm correction**, and the one comparison
family with real aggregate significance (comparison 3's small-model-family
Friedman omnibus) resolves to exactly 2 specific pairwise differences out of
15, not a general pattern. The large, consistently "p < 0.0001" conditional-
MCC gaps for raw-vs-autogrep and C1-vs-C2 remain real and worth reporting,
but as evidence about *which cases become acceptable* under repair, not as
evidence repair improves rule quality on a shared population of cases — the
two things this paper previously conflated. The multi-agent findings (C2 vs
C3, C3 vs C4) remain directionally interesting, mechanistically
well-motivated HYPOTHESES, not confirmed effects, given how few cases are
ever accepted under the stricter multi-agent conditions. **The paper's
central empirical result is now the gap between visible-validation
acceptance and end-to-end hidden-test success (§7.9), not a repair-superiority
claim** — see the Conclusion for the restated main claim.

**Subgroup analysis (§22.4) [CORRECTED]**, applied to the primary benchmark's
`autogrep` condition on the full dataset (most statistical power in the
study), for the representative model `qwen2.5-coder:32b` (86 evaluable
cases). Every CI below uses a repository-aware bootstrap (resampling at the
repository level, since CVEs from the same repo aren't independent —
§22.4's own requirement). **Not independently rerun against
`pipeline/eligible_cases.py`'s round-2 corrections** (unlike every other
table in this document): checked directly that CASE-0166 was never accepted
for this model (`semgrep_valid: false`), so its dataset exclusion has no
effect here; the 5 ground-truth exclusions could affect at most a handful
of this 86-case population, in line with the sensitivity analysis above
showing a ≤1.3-point effect for 7 of 8 models — plausibly negligible here
too, but not directly verified for this specific table.

| Subgroup | Buckets (MCC, 95% CI) |
|---|---|
| Language | python 0.662 (0.537–0.770); javascript 0.573 (0.404–0.729); java 0.479 (0.379–0.573); typescript 0.430 (0.155–0.680) |
| Pattern vs taint | taint 0.606 (0.513–0.696); pattern 0.536 (0.448–0.620) |
| Structural vs context-heavy | structural 0.561 (0.467–0.651); context-heavy 0.545 (0.441–0.643) — essentially flat |
| Supported vs partially supported | supported 0.536 (0.444–0.626); partially supported 0.558 (0.433–0.677) — essentially flat |
| Older vs newer CVE (median year 2023) | newer 0.593 (0.441–0.727); older 0.536 (0.454–0.612) |
| Patch size (tertiles) | small 0.640 (0.514–0.755); medium 0.515 (0.422–0.606); large 0.501 (0.359–0.637) — visually monotonic decline |
| CWE (≥10 cases only) | CWE-78 0.798; CWE-22 0.707; CWE-79 0.642; CWE-200 0.605; NVD-CWE-noinfo 0.554; CWE-94 0.430 |

166 distinct CWE IDs appear across the dataset; only 6 have ≥10 cases
(CI reported above), the other 160 are reported as counts only — stated
explicitly as too sparse for a meaningful CI rather than silently dropped
or given a misleading one. `advisory_date` was never populated for any
case, so the older/newer split substitutes the CVE year parsed from
`cve_id` — a coarser (year-level) approximation, stated rather than
hidden. The 153-case multi-agent conditions (C2/C3/C4) are too sparse for
subgroup breakdowns (C4-A has only 11 accepted cases total) and are
deliberately not broken out.

No pairwise significance testing was run across these subgroup buckets
(§22.4 asks for descriptive reporting with CIs, not pairwise tests).
Reading the overlapping CIs directly: language, structural-complexity, and
supported-vs-partial splits show substantial CI overlap (no strong
evidence of a real difference); patch size still shows a visually monotonic
decline from small to large patches after correction, at least suggestive
since the small-vs-large CIs (0.514–0.755 vs 0.359–0.637) only narrowly
overlap. The CWE-level point estimates are identical to the uncorrected run
for this particular model/condition — those specific cases happened not to
be affected by any location-correctness flip.

**This completes Section 22 in full** — both the 7 predefined comparisons
(§22.3) and the subgroup analysis (§22.4), both rerun against corrected data
with consistent repository-aware bootstrapping throughout.

### 7.9 The explicit end-to-end picture (audit Step 4's requirement)

Every metric reported in §7.1–7.8 above is a **conditional** quality
measure — computed only among cases where a rule was actually accepted.
This section reports the full, explicit breakdown the 2026-10-06/07 audit
specifically required: five rows with stated denominators, for every
condition, treating a missing or rejected rule as a failure on every
hidden-positive sample it never had the chance to flag — never silently
excluded from a denominator, and never credited as a true negative for a
scan that never ran. Rerun on the frozen 150-case eligible-supported
population (`pipeline/eligible_cases.py` v2026-10-07.1 — CASE-0166 plus 3
ground-truth exclusions removed; 2026-10-07 audit round 2, Priorities 2–4).
Full methodology and per-model output: `pipeline/build_step4_tables.py`,
`results_corrected/step4_tables_report.txt`.

**[CORRECTED, 2026-10-07, twice]** While regenerating this table, the
primary benchmark's autogrep condition was found to record a
`validation_error` of `"repo not available for validation"` for 60–77% of
cases, in every one of the 8 models. **An earlier version of this section
misdiagnosed that as a new, previously-undiscovered validator
infrastructure failure, and attempted to "recover" a true compile rate
from `attempt_trail`'s per-attempt `yaml_valid` field — that diagnosis was
wrong and is retracted.** Checking `Research_Log/Implementation_Log.md`
Section 12.30 (written by the original study team before any audit, and
missed when this section was first drafted) found the real, already-fixed
root cause: `reconstruct_attempt_trail()` — a diagnostic-only re-evaluation
function, independent of Autogrep's own real retry loop — was never updated
after the validator went clone-free for curated cases, so it still gates on
`repo_path.exists()`, which is `False` by design for every curated case (a
synthetic marker path, since validation reads each case's own stored source
files directly, no clone needed). This makes the function discard the real
per-attempt outcome and substitute a generic placeholder for every curated
case — but, verified directly in that log entry, **every one of the 1,746
affected records has `semgrep_valid == False`: a real rejection, never a
wrong pass.** Only the human-readable failure-REASON text is corrupted (and
the whole `attempt_trail` diagnostic list is documented there as
"unreliable for curated cases" as a result) — so the specific reason for
these rejections (parse failure vs. discrimination failure) cannot be
recovered from stored data, and the "recovered 87–96% compile rate" claim
is retracted along with the infra-failure story.

Per Priority 7's actual instruction ("mark Autogrep's attempted-candidate
compilation rate as unavailable unless recoverable"): it is **not**
recoverable. Compile rate for the autogrep condition is therefore reported
as identical to acceptance coverage — Autogrep's retry loop only ever
returns an already-fully-validated rule, so this is structurally
unrecoverable, exactly as this document stated before the (now-retracted)
"Finding 2" detour, just for a more precisely documented reason.

**Primary benchmark, 150 eligible supported cases — autogrep row directly above its raw-condition counterpart, per model:**

| Model / condition | Compile rate | Acceptance coverage | Conditional MCC | End-to-end hidden-positive detection | End-to-end successful-rule rate | Of non-accepted: confirmed parse-fail / reason-unrecoverable |
|---|---:|---:|---:|---:|---:|---:|
| DeepHat-V1-7B — autogrep | 36.0% | 36.0% | 0.545 | 16.3% (49/300) | 6.0% (9/150) | 6 / 90 |
| DeepHat-V1-7B — raw | 94.7% | 28.0% | 0.593 | 14.7% (44/300) | 5.3% (8/150) | — |
| Qwen2.5-Coder-32B — autogrep | 30.0% | 30.0% | 0.539 | 16.3% (49/300) | 4.7% (7/150) | 9 / 96 |
| Qwen2.5-Coder-32B — raw | 94.0% | 26.0% | 0.628 | 16.3% (49/300) | 4.7% (7/150) | — |
| Yi-Coder-9B — autogrep | 29.3% | 29.3% | 0.534 | 14.0% (42/300) | 5.3% (8/150) | 9 / 97 |
| Yi-Coder-9B — raw | 92.0% | 19.3% | 0.583 | 10.7% (32/300) | 3.3% (5/150) | — |
| Qwen2.5-Coder-7B-Instruct — autogrep | 31.3% | 31.3% | 0.513 | 15.7% (47/300) | 4.7% (7/150) | 12 / 91 |
| Qwen2.5-Coder-7B-Instruct — raw | 74.0% | 24.0% | 0.626 | 14.7% (44/300) | 4.0% (6/150) | — |
| CodeLlama-7B-Instruct — autogrep | 14.7% | 14.7% | 0.510 | 4.0% (12/300) | 0.7% (1/150) | 13 / 115 |
| CodeLlama-7B-Instruct — raw | 65.3% | 10.0% | 0.503 | 2.3% (7/300) | 0.0% (0/150) | — |
| CodeGemma-7B — autogrep | 18.7% | 18.7% | 0.521 | 7.0% (21/300) | 2.0% (3/150) | 14 / 108 |
| CodeGemma-7B — raw | 76.7% | 13.3% | 0.580 | 5.7% (17/300) | 2.0% (3/150) | — |
| Magicoder-7B — autogrep | 9.3% | 9.3% | 0.427 | 2.3% (7/300) | 0.7% (1/150) | 23 / 113 |
| Magicoder-7B — raw | 70.0% | 4.0% | 0.520 | 1.7% (5/300) | 0.7% (1/150) | — |
| DeepSeek-Coder-6.7B — autogrep | 12.0% | 12.0% | 0.373 | 2.7% (8/300) | 1.3% (2/150) | 16 / 116 |
| DeepSeek-Coder-6.7B — raw | 68.0% | 6.7% | 0.481 | 1.7% (5/300) | 0.7% (1/150) | — |

*Reading this table: "confirmed parse-fail" counts non-accepted cases whose
stored error text genuinely says `"failed to parse/sanitize into a rule"`
(trustworthy — this string is not produced by the buggy diagnostic
function). "Reason-unrecoverable" counts cases whose error text is the
corrupted `"repo not available for validation"` placeholder — these are
confirmed real rejections, but whether each one was actually a parse
problem or a discrimination problem cannot be determined from the stored
logs. No claim is made here about which of those two explanations
predominates for the autogrep condition. Raw-condition compile rates (used
directly, not affected by this bug at all — it is specific to the
clone-free autogrep validator path) are substantially higher than autogrep's
acceptance coverage in every case, consistent with (but not proof of) real
discrimination failure being a meaningful contributor for raw; the same
inference cannot be drawn for autogrep.*

**C2 / C3 / C4, 150 eligible supported cases (corrected data — unaffected by
the above: their validators recorded real discrimination outcomes
throughout, via a different, unrelated code path, confirmed by direct
inspection of every episode log):**

| Condition | Compile rate | Acceptance coverage | Conditional MCC | End-to-end hidden-positive detection | End-to-end successful-rule rate |
|---|---:|---:|---:|---:|---:|
| C2, DeepHat-V1-7B | 81.3% | 36.0% | 0.545 | 16.3% (49/300) | 6.0% (9/150) |
| C2, Qwen2.5-Coder-32B | 79.3% | 30.0% | 0.539 | 16.3% (49/300) | 4.7% (7/150) |
| C2, Yi-Coder-9B | 77.3% | 30.0% | 0.516 | 14.0% (42/300) | 5.3% (8/150) |
| C2, Qwen2.5-Coder-7B-Instruct | 76.0% | 32.0% | 0.502 | 15.7% (47/300) | 4.7% (7/150) |
| C2, CodeLlama-7B-Instruct | 69.3% | 14.7% | 0.510 | 4.0% (12/300) | 0.7% (1/150) |
| C2, CodeGemma-7B | 68.7% | 18.7% | 0.521 | 7.0% (21/300) | 2.0% (3/150) |
| C2, DeepSeek-Coder-6.7B | 68.7% | 12.0% | 0.373 | 2.7% (8/300) | 1.3% (2/150) |
| C2, Magicoder-7B | 52.7% | 12.7% | 0.403 | 2.7% (8/300) | 0.7% (1/150) |
| C3-S | 60.0% | 23.3% | 0.649 | 16.7% (50/300) | 5.3% (8/150) |
| C3-E | 71.3% | 8.7% | 0.545 | 4.7% (14/300) | 1.3% (2/150) |
| C4-A | 68.7% | 7.3% | 0.524 | 4.0% (12/300) | 0.7% (1/150) |
| C4-B | 62.7% | 17.3% | 0.668 | 13.7% (41/300) | 4.0% (6/150) |

**This is the headline result of the entire corrected analysis.**
End-to-end hidden-positive detection rates run **1.7%–16.7%** across every
condition in the study, and end-to-end successful-rule rates run
**0.0%–6.0%** — both dramatically lower than the conditional MCC/VGR
numbers (0.37–0.67 MCC among accepted cases) reported throughout §7.1–7.8.
**Even the best-performing condition in this entire study
(`DeepHat-V1-7B` at 6.0% under either the autogrep or C2 condition) solves
fewer than 1 in 16 requested cases completely end-to-end.** For the
autogrep condition specifically, the compile-vs-accept gap cannot be
attributed to discrimination failure OR ruled out as one — compile rate
equals acceptance coverage exactly (Autogrep's retry loop only ever
returns an already-fully-validated rule), and most of the remaining
rejections have an unrecoverable specific reason (above). For C2/C3/C4 and
for the raw condition, by contrast, compile rate is a genuine, independent
signal, and each shows compile rate substantially exceeding acceptance
coverage — consistent with discrimination failure being a real, measurable
contributor to their compile-accept gap specifically (their validators ran
to completion and recorded genuine pass/fail outcomes via a different,
unrelated code path from autogrep's). The paper's strongest current focus
remains: **the gap between visible validation and reliable hidden-test
performance, together with the coverage and quality tradeoffs of the
tested workflows.** Whether Autogrep or multi-agent processing improves
END-TO-END performance — as opposed to conditional quality among the cases
each happens to accept — should be read from this table, not from
§7.1–7.8's conditional numbers alone.

## 8. Contamination controls (§23)

Public CVEs and public Semgrep rules may appear in model training data.
Per §23's own explicit instruction, this section presents remaining
contamination risk as a validity threat, not a claim of complete
contamination removal. Each of §23's eight listed controls, addressed in
turn:

**CVE and fix publication dates.** All 300 cases have a usable CVE ID;
years span 2010–2026 (median 2023) — used throughout §22.4's older/newer
subgroup split. `advisory_date` itself was never populated for any case
(a real gap, stated plainly), so the CVE year parsed from `cve_id` is used
as a coarser substitute throughout.

**Model cutoff information, where publicly available.** Exact training
data cutoffs are undisclosed for most of these open-weight models;
release date (a hard upper bound on cutoff) is used where the cutoff
itself isn't published. Checked directly rather than assumed:

| Model | Cutoff / release (public) |
|---|---|
| `qwen2.5-coder:7b-instruct` / `:32b` | Training cutoff Sept 2024 (disclosed in the Qwen2.5-Coder technical report) |
| `DeepHat-V1-7B` | Released Sept 2025, but a fine-tune of Qwen2.5-Coder-7B — inherits that base's Sept 2024 pretraining cutoff; its own fine-tuning data (security-specific) could in principle reference newer material, not independently verified |
| `yi-coder:9b` | Released Sept 2024 |
| `codegemma:7b` | Released April 2024 |
| `deepseek-coder:6.7b` | Released Nov 2023 |
| `magicoder:7b` | Released Dec 2023 (a fine-tune of CodeLlama/DeepSeek-Coder bases via synthetic OSS-Instruct data) |
| `codellama:7b-instruct-fp16` | Released Aug 2023 |

Using each model's cutoff/release year as a hard boundary, the number of
this study's cases whose CVE year falls strictly after that boundary — a
**reduced-risk subset for that model, not a proof of contamination-free
status** (a boundary this coarse cannot rule out contamination from
secondary sources discussing the CVE before the model's cutoff, fine-tuning
data added after the stated pretraining cutoff, or memorization of the
underlying vulnerability pattern from similar, earlier-disclosed cases): 78
of 300 (26%) for the four ~Sept-2024-cutoff models, 125 of 300 (41.7%) for
the three ~2023-release models. This gives a concrete, per-model
lower-contamination-risk subset that could anchor a future, more targeted
contamination check (not yet done as its own separate analysis) — presented
as a risk-reduction boundary, not a certainty.

**Older versus newer CVE reporting.** Computed in §22.4: for the
representative model, newer CVEs (post-2023) score HIGHER, not lower
(MCC 0.692 vs 0.571 for older CVEs). If older, better-known CVEs were
disproportionately memorized, the opposite pattern would be expected —
this is at least mildly reassuring, though confounded with patch size
(newer CVEs in this dataset are not confirmed independent of patch size,
not checked).

**Exact and near-duplicate search against public Semgrep rules.** Not
performed as a general web-scale search (no access to the full historical
public Semgrep/Opengrep rule registry). A narrower, concrete check WAS
run: this repo vendors Autogrep's own pre-existing 645-rule example
corpus (`autogrep/filtered_rules/`, distributed with the tool, publicly
available since the tool's own publication) as demonstration output.
Cross-referencing that corpus's `source-url` commit hashes against this
study's 300 cases' `fixed_commit`/`vulnerable_commit` fields (exact
40-character SHA-1 matches, zero false-positive risk from prefix
collision) found **15 cases (5%) where a Semgrep rule for the EXACT same
commit already existed in a publicly-distributed corpus**:
`CASE-0053, 0103, 0113, 0114, 0152, 0199, 0210, 0214, 0221, 0230, 0285,
0293, 0308, 0309, 0314`. This is a genuine, concrete contamination risk
marker — not proof that any specific model trained on it, but a
confirmed public-availability fact for these 15 cases specifically.

Checked whether model performance on these 15 is suspiciously inflated
(the signature a memorization effect would leave): it is NOT, for 6 of 8
models — several show LOWER MCC on these cases than on the rest (e.g.
`qwen2.5-coder:32b`: 0.289 vs 0.582, corrected), the opposite of what
contamination would predict. Only `DeepHat-V1-7B` (0.646 vs 0.547) and
`codegemma:7b` (0.566 vs 0.483) show a modest edge. Given only 9 or fewer
evaluable cases per model in this 15-case subset, this check has limited
power and should be read as "no clear evidence of inflation," not
"confirmed clean."

**Detection of copied rule IDs, messages, and uncommon identifiers.** Not
performed as a systematic search. Worth noting as a concrete follow-up:
the same 645-rule corpus above could be directly diffed against this
study's own generated rules for near-identical `message`/`id` text, a
cheap and specific test not yet run.

**Repository-grouped analysis.** Built into the methodology throughout —
every bootstrap CI in §22 resamples at the repository level, not the case
level (258 unique repos across 300 cases, only 27 contribute more than
one case, max 5 from any single repo — confirmed directly, Section22_Scope.md).

**Hidden transformed variants.** The core protection this entire study's
evaluation design is built around (§17.3): agents never see the hidden
transformed/safe/benign-lookalike variants during generation or review,
only the original vulnerable/patched pair and the deterministic Semgrep
result on that pair. A rule that only works because its EXACT wording was
memorized from a public source would still have to generalize correctly
to these never-seen variants to score well on VGR/PDS — memorization of a
specific public rule does not, by itself, guarantee passing the hidden
evaluation.

**Patch deduplication.** Performed during Phase 2 curation (Section 8,
Step 2; `Research_Log/Phase2_Dataset_Curation_Log.md`): normalized
patch-content hashing found 344 groups of byte-identical diffs across
nominally different (repository, commit) pairs; 70 were confirmed
same-commit-different-representation duplicates and excluded outright;
the remaining 274 groups (genuinely different commits that happen to
produce identical patch content) were kept and flagged for case-by-case
review rather than assumed safe.

**Overall validity-threat statement**: contamination cannot be ruled out
for this study, as §23 itself anticipates, and nothing here should be read
as establishing that any model's training data was or was not contaminated.
The strongest concrete evidence is the 15-case commit overlap with a
publicly-distributed rule corpus — a real, quantified risk, not a
hypothetical one — but the accompanying performance check found no clear
inflation signal on those specific cases. The reduced-contamination-risk
per-model subsets (78–125 cases, depending on model) are available for a
more targeted re-analysis if a reviewer wants a contamination-risk-adjusted
version of the headline numbers — they narrow risk, they do not certify its
absence.

## 9. Failure taxonomy (§24)

§24 specifies four failure categories. Rather than report these
anecdotally, the generation-failure and syntax-failure counts below are
computed directly from the primary benchmark's `raw` condition (2,400
records = 8 models × 300 cases, one attempt each, no retry/feedback —
the cleanest condition for characterizing first-attempt failure modes
before Autogrep's own retry loop can mask them):

**The full funnel, computed exhaustively (all 2,400 records accounted
for, verified to sum correctly)**:

| Stage | Count | % of 2,400 |
|---|---:|---:|
| YAML-invalid (never reached Semgrep) | 220 | 9.2% |
| Reached Semgrep, rejected (syntax failure) | 486 | 20.3% |
| Reached Semgrep, ran clean, semantically wrong | 1,372 | 57.2% |
| Reached Semgrep, ran clean, semantically correct | 322 | 13.4% |

**Generation failures.** Per-model YAML-invalid rates vary substantially
(3.7%–13.3%): `DeepHat-V1-7B` 3.7%, `qwen2.5-coder:32b` 5.3%,
`yi-coder:9b` 7.0%, `codegemma:7b` 9.7%, `qwen2.5-coder:7b-instruct` 10.3%,
`codellama:7b-instruct-fp16` 11.0%, `magicoder:7b` 13.0%,
`deepseek-coder:6.7b` 13.3% — the two weakest-ranked models on raw MCC are
also the two worst at basic format-following, a consistent pattern rather
than an independent failure mode. §24's finer distinctions (empty output,
timeout, truncation, non-YAML response, multiple rules, OOM) were not
separately instrumented at generation time for the primary benchmark (the
raw captured pre-parse text wasn't retained for this run) — a concrete
gap for a future run's logging, not filled in here by guessing.

**Syntax failures** (the 486 records that reached Semgrep but were
rejected), broken down by Semgrep's own reported error type:

- 448/486 (92.2%) **"Rule parse error"** — Semgrep's own pattern/rule
  engine rejecting the rule (§24's "Semgrep runtime error" / "unsupported
  operator" categories, not further separable from the stored error type
  alone).
- 30/486 (6.2%) **schema-shape errors** — a recurring, specific LLM
  confusion: nesting a list/dict where Semgrep's schema requires a plain
  string (`"[...] is not of type 'string'"`), and several instances of
  doubly/triply-nested `metavariable-pattern` blocks (§24's "invalid
  metavariable" / "missing required fields" categories) — a distinct,
  nameable failure signature worth its own mention rather than folding
  into the generic parse-error bucket.
- 8/486 (1.6%) **target-file syntax errors** — NOT a failure of the
  generated rule at all: Semgrep failing to parse the TEST FIXTURE source
  file being scanned (`CASE-0055`'s `.py` files, `CASE-0298`'s `.ts`
  files) — a pre-existing property of those two specific case files,
  flagged here as a dataset/infrastructure note rather than attributed to
  any model.

**Semantic failures** (1,372 records, 57.2% of all raw attempts — by far
the largest category): the rule is syntactically valid and runs cleanly
in Semgrep, but fails Autogrep's own correctness bar (doesn't flag the
vulnerable sample, or does flag the patched sample, or both). This
single number is the strongest evidence in the whole study for why
Autogrep's retry/feedback loop produces the large, highly significant MCC
gains reported in §7.8's comparison 4 — the dominant failure mode by far
is a plain discrimination miss, exactly the kind of failure a
feedback-driven repair attempt can plausibly fix, unlike a YAML-level
format failure the model would need to see a DIFFERENT kind of signal to
correct. §24's finer semantic subcategories (wrong mechanism, source-sink
lost, sanitizer ignored, vulnerable/fixed reversed, over/under-
generalization) were explicitly instrumented for ONE condition in this
study — Phase 3's semantic-review role screening (§7.5) — where the
screening test set's own categories (MISS / PATCHED_CODE_FINDING /
OVER_GENERALIZATION / UNDER_GENERALIZATION / NONE) map directly onto
§24's taxonomy; not re-run across the full 2,400-record primary set here.

**Multi-agent failures.** Every one of §24's eight listed multi-agent
failure modes has a concrete, already-documented instance from this
study's own C2/C3/C4 work, rather than being a hypothetical category:

- **Incorrect analysis propagated to later agents**: C3/C4's Patch
  Analysis role hallucinating unsupported specifics that then shape the
  Rule Generation prompt (the same overreach pattern caught during the
  patch-analysis ground-truth review, Implementation_Log 12.45-12.49).
- **Reviewer introduces unjustified changes / repair oscillation**:
  `CASE-0078`'s Syntax Review correctly diagnosing a `SEMGREP_DSL_ERROR`
  but reproducing the EXACT SAME invalid metavariable in its own
  "corrected" rule across both round 0 and round 1 (Implementation_Log
  12.50) — a real oscillation, not a one-off.
- **Correct rule damaged by repair**: implicit in C3-E's 0% repair
  recovery rate (Implementation_Log 12.51) — every repair attempt on an
  already-close rule failed to produce an improvement.
- **Token or call budget exhausted**: the `rejected_round1` stop reason
  (the large majority of outcomes in every C2/C3/C4 run) is precisely
  this — the Section 20 budget (max 6 calls, 1 repair round) is exhausted
  before the rule is accepted.
- **Hidden-test leakage**: explicitly designed against (§17.3) rather than
  observed as a failure — worth noting as a control that worked, not a
  gap.
- **Agent schema failure**: the markdown-bold parsing bug (`qwen2.5-coder:
  7b-instruct` wrapping field labels in `**BOLD**` with bullets, breaking
  5 separate regex parsers across `run_patch_analysis.py`,
  `run_semantic_review.py`, and `run_c3.py`) found and fixed during C3's
  build (Implementation_Log 12.50) — a concrete, previously-unflagged
  instance of exactly this failure mode, caught by direct verification
  rather than assumed fixed.
- **Incompatible assumptions between models**: C4-A's four-distinct-model
  configuration underperforming every other condition tested
  (Implementation_Log 12.54-12.55) — the leading hypothesis for this
  (role-screening metrics measured in isolation don't guarantee the
  roles interface cleanly with EACH OTHER's output conventions) is
  precisely this failure mode, though §7.8's formal significance testing
  found the observed gap is not statistically confirmed at this sample
  size — stated as a suggestive instance, not a proven one.

## 10. Known limitations, stated explicitly [UPDATED post-audit]

- **Six-sample bundle size limits the threshold-sensitivity analysis** the
  study's own protocol calls for (§5) — the prescribed 3×3 sweep is
  mathematically unable to show sensitivity at this bundle size.
- **Representability labeling is single-rater, with a completed independent
  check (two rounds) showing substantial-to-almost-perfect agreement.**
  Round 1 (45 blinded cases, rated from summaries only, some conversation
  exposure) found moderate agreement; Round 2 (a fresh, zero-overlap 45-case
  sample, rated with full diff/source access, zero exposure — the
  methodologically stronger round, and the one that supersedes Round 1)
  found: `pattern_or_taint` 91.1%/κ=0.802 (almost perfect),
  `structural_or_context_heavy` 93.3%/κ=0.860 (almost perfect), **and
  `semgrep_representability` — the field defining the 150-case eligible
  "supported" scope every headline comparison in this document uses — 77.8%/κ=0.662
  (substantial), up from Round 1's 64.4%/κ=0.448.** Disagreements
  concentrated around the `partially_supported` boundary in both rounds, in
  both directions, not a one-way bias — consistent with a genuine
  category-boundary difficulty. This is reported as a real but now smaller
  validity consideration for the 150-case comparison scope, not a resolved
  footnote and not a confirmed non-issue either. Full numbers for both
  rounds: `Research_Log/Correction_Log.md`.
- **CodeLlama's inclusion is precision-confounded** by infrastructure
  availability (§3) and is reported separately rather than ranked.
- **The "benign look-alike" sample is syntactically identical (or
  near-identical) to the vulnerable code in a small, now-precisely-counted
  number of cases** — quantified during the audit rather than left as an
  impression: **4 confirmed** (`CASE-0069`, `CASE-0078`, `CASE-0238`,
  `CASE-0342` — the latter three found by direct inspection during curation,
  `CASE-0069` found by an automated similarity check during the audit and
  manually verified: `OpenNMS/opennms`'s `hasEditRights`/`hasViewRights`
  share the identical boolean check, a real vulnerability in one permission
  context and correct in the other), plus 3 more cases flagged as
  moderately similar by the same automated check but not individually
  verified (`CASE-0111`, `CASE-0136`, `CASE-0067`). For these cases, no
  purely syntactic rule can achieve a true negative on the benign sample,
  which imposes a hard ceiling on BSDR/false-positive performance
  independent of model quality.
- **[CORRECTED, 2026-10-07] 10 cases in the dataset were reviewed for a
  disclosed upstream-fix concern** (bypassable or incomplete real-world
  fixes, or a disputed advisory) against one explicit rule: exclude a case
  from its representability population only if the SAME labeled
  vulnerability's upstream fix is measurably still exploitable — not a
  different bug, and not uncertainty about the vulnerable sample's own
  exploitability. **5 were excluded on that basis** (`CASE-0125`,
  `CASE-0140`, `CASE-0156`, `CASE-0174`, `CASE-0194` — full per-case
  evidence in `benchmark/ground_truth_exclusions.json`) and **5 were kept**
  after review (`CASE-0107`, `CASE-0154`, `CASE-0170`, `CASE-0199`,
  `CASE-0211`). The primary-comparison population is now 150 supported
  cases (down from 153), frozen in `pipeline/eligible_cases.py`
  (`v2026-10-07.1`) as the one population every analysis script imports.

  Earlier drafts claimed this "affects at most one sample" — that
  understated it (removing 3 full cases removes every one of their sample
  records, not one classification outcome) and is retracted. The real
  effect, recomputed directly rather than asserted, is **small and mostly
  within rounding, with one real exception**:

  | Model (autogrep condition) | Accept. coverage (153→150) | Conditional MCC (153→150) | End-to-end detection (153→150) | End-to-end success (153→150) |
  |---|---:|---:|---:|---:|
  | Qwen2.5-Coder-7B-Instruct | 31.4%→31.3% | 0.514→0.513 | 16.0%→15.7% | 4.6%→4.7% |
  | Qwen2.5-Coder-32B | 30.1%→30.0% | 0.536→0.539 | 16.0%→16.3% | 4.6%→4.7% |
  | DeepHat-V1-7B | 35.9%→36.0% | 0.543→0.545 | 16.0%→16.3% | 5.9%→6.0% |
  | Yi-Coder-9B | 29.4%→29.3% | 0.529→0.534 | 14.1%→14.0% | 5.2%→5.3% |
  | CodeLlama-7B-Instruct | 15.7%→14.7% | 0.508→0.510 | 4.6%→4.0% | 0.7%→0.7% |
  | CodeGemma-7B | 18.3%→18.7% | 0.521→0.521 | 6.9%→7.0% | 2.0%→2.0% |
  | **Magicoder-7B** | 9.8%→9.3% | **0.374→0.427** | 2.3%→2.3% | 0.7%→0.7% |
  | DeepSeek-Coder-6.7B | 11.8%→12.0% | 0.373→0.373 | 2.6%→2.7% | 1.3%→1.3% |

  Seven of the eight models move by ≤1.3 points on every metric — genuinely
  negligible. **Magicoder-7B is the exception**: its conditional MCC moves
  by +0.053 (0.374→0.427), because it accepts very few rules overall, so
  removing 3 cases' worth of samples from a small pooled-confusion-matrix
  denominator has a proportionally larger effect. This doesn't change which
  condition or model ranks where, but it is a real, model-specific
  sensitivity to the ground-truth correction, not a uniformly negligible
  one, and is disclosed as such rather than smoothed into a single
  cross-model number. Full recomputation: `pipeline/build_step4_tables.py`.
- **One case (`CASE-0166`) was excluded post-hoc during the audit** after
  confirming its upstream-patched revision does not compile (§2.2) — the
  dataset is 299 cases as of this writing, not 300.
- **A real scoring gap (location-correctness never checked for hidden
  variant samples) was found and fixed during the audit** (§5) — every
  VGR/MCC number in this document reflects the correction; 21.6% of all
  hidden-variant "detections" study-wide were wrong-location matches,
  now corrected.
- **C2, C3, and C4 are not a controlled comparison of "role separation"
  alone** — a workflow-comparability audit
  (`Research_Log/Workflow_Comparability_C2_C3_C4.md`) found 3 further
  unmatched variables (generator input shape, repair-round count, and
  round-0 acceptance-gate strictness) beyond which roles are separated.
  Causal claims attributing any C2-vs-C3 or C3-vs-C4 difference to role
  separation specifically, rather than to the complete configuration
  difference, are stated as hypotheses throughout, not confirmed findings
  — consistent with the formal significance testing (§7.8), which finds no
  statistically detectable difference in most of these comparisons anyway.
  **[DECISION, 2026-10-07 audit round 2, Priority 8]** A controlled rerun
  that isolates role separation from these 3 confounds is only necessary if
  this document claims role separation ITSELF causes any observed
  improvement. It does not make that claim anywhere — every C2/C3/C4
  comparison above is reported as a descriptive comparison of complete,
  differently-configured workflows, and §7.8's formal tests additionally
  find no statistically detectable pairwise difference in most of these
  comparisons regardless of cause. No controlled rerun was conducted; none
  is needed under this document's actual (non-causal) claims. A future
  paper that DOES want to claim role separation causes a specific effect
  would need that rerun first.
- **The primary comparison set (150 of 299 eligible supported cases — 153
  minus 3 ground-truth exclusions, §2.4) is smaller than the full
  dataset.** Confidence intervals are now computed and reported at this
  effective sample size throughout (§22, complete).
- **Generalization claims in this document (VGR) are about controlled,
  within-dataset transformations, not unseen real-world vulnerabilities**
  — stated explicitly in §1 and repeated here per the audit's instruction,
  since it is easy to over-read "generalization" as a broader claim than
  what was actually tested.
- **A wrapper-level restriction structurally prevents any model from
  submitting a valid composite-pattern Semgrep rule** (`patterns:`,
  `pattern-either:`, `pattern-not:`) — the code requires a literal top-level
  `pattern` key, rejecting these forms even though Semgrep itself accepts
  them, for every model in every condition. Measured real-world footprint
  across every log in the study: 16 occurrences, concentrated entirely in
  C2's two weakest-performing models — cannot be fully attributed to this
  restriction specifically versus unrelated malformed output, since no raw
  rule text was retained for C2 to check. Not retroactively fixable with
  available data; the small measured footprint does not justify a rerun,
  but this is a real structural ceiling on achievable FPR (a model that
  would otherwise use `pattern-not` to exclude a benign look-alike cannot
  succeed) that applies to every result in this document.
  **[DECISION, 2026-10-07 audit round 2, Priority 8]** Given this
  restriction, this document's conclusions are scoped explicitly to **the
  tested Autogrep implementation and wrapper as configured in this study**
  — not to "LLM-to-Semgrep rule generation" as a general capability claim.
  Every model in every condition was constrained by the same wrapper-level
  restriction, so within-study comparisons (model-vs-model, raw-vs-autogrep,
  condition-vs-condition) remain valid; what is NOT supported is a broader
  claim about what these models could achieve against an unrestricted
  Semgrep rule schema. A study making that broader claim would need to rerun
  against a corrected wrapper that accepts composite patterns — not done
  here, and not retroactively possible from existing data (no raw rule text
  was retained for the affected condition to re-validate against a fixed
  wrapper without new generation calls).

## 11. Not yet done (tracking, for completeness of the eventual paper)

- A systematic exact/near-duplicate search against the broader public
  Semgrep rule ecosystem (beyond the one 645-rule vendored corpus already
  checked, §8) is the one concrete, not-yet-run contamination follow-up.
- A secondary, unrestricted-budget comparison for C3 (§20 explicitly permits
  this), to check whether the budget resolution itself (one repair round,
  no second Semantic Review call) is suppressing recovery for either model,
  or whether the pattern reported in §7.6 is intrinsic to each model's own
  self-assessment reliability regardless of how many rounds it gets.
- A controlled ablation isolating role separation from the other 3
  unmatched variables found in the C2/C3/C4 workflow-comparability audit
  (§10) — needed before any causal role-separation claim could be confirmed
  rather than reported as a hypothesis.
- A direct inspection of individual C4-A episodes' intermediate hand-offs,
  to test the "interface mismatch" hypothesis (§7.7) directly rather than
  infer it from the aggregate pattern — not run, since the formal
  significance test (§7.8) already found no confirmed pairwise difference
  to explain.
- **[RESOLVED, mostly] §7.3's stability-ranking discrepancy** — investigated
  directly for audit round 2's Priority 8. Ruled out a script bug
  (`analyze_phase5_stability.py` was fixed to actually read
  `results_corrected/`, confirming the table's existing numbers were already
  right) and an averaging-method artifact (pooled vs. mean-of-ratios MCC
  gives the same ranking). 6 of 8 models' temp-0 single-draw MCC falls
  inside their own 5-repeat temp-0.2 range — ordinary sampling noise among
  closely-clustered MCCs. 2 models (`qwen2.5-coder:32b`,
  `codellama:7b-instruct-fp16`) remain a genuine exception, carried forward
  as an untested hypothesis (determinism specifically benefiting these two),
  not a confirmed mechanism — a case-level investigation of their specific
  sample flips would be needed to test it, and was not run.
- The pilot screening numbers (§6) have not been recomputed with Finding 1's
  location-correctness fix — out of scope for this audit pass since the
  pilot only informed early prompt-template/model-direction decisions, not
  any headline comparison, but noted as an inconsistency between §6 and
  everything downstream of it.

---

**A note on what changed in this document and why, for anyone comparing
against an earlier version**: two methodological audits
(2026-10-06/07 and a second, deeper pass on 2026-10-07, full record in
`Research_Log/Correction_Log.md`, git history starting at tag
`baseline-pre-audit`) found, across both passes: a real scoring gap
(location-correctness never implemented for hidden-variant samples, now
fixed); several unmatched variables in the C2/C3/C4 comparison; all 29
previously-unresolved variant line-range annotations, now manually
resolved; a principled ground-truth exclusion standard, now applied
consistently (150 eligible supported cases, down from 153); resolved most
of §7.3's stability-ranking discrepancy (newly surfaced during the first
audit pass) to ordinary sampling variation, with a smaller residual
honestly flagged as an untested hypothesis rather than a confirmed
mechanism; corrected a misdiagnosis of the primary benchmark autogrep
condition's `"repo not available for validation"` pattern — not a new
infrastructure failure as an earlier draft of this document claimed, but
a pre-existing, already-documented diagnostic-text bug
(`Research_Log/Implementation_Log.md` Section 12.30) that never affected
any actual pass/fail outcome; and completed the long-pending second-rater
check (twice, the second time with a clean, zero-overlap sample).

**The most consequential change of the second audit pass**: every causal
claim about multi-agent configurations remains hedged as a hypothesis
unless formal significance testing confirmed it, and this document's
previous claim that feedback-driven repair's MCC gain was "the single
most robust finding in the whole study, unaffected by any correction" is
**retracted**. That claim rested on comparing conditional MCC between raw
and repaired conditions — each computed only among that condition's own
accepted cases, a different, self-selected population for each side.
Repeating the same comparisons on the end-to-end metric (identical 150-case
denominator for every condition, no selection effect) finds **0 of 8
models with a statistically detectable raw-vs-autogrep or C1-vs-C2
end-to-end difference, after Holm correction, anywhere in the study**
(`results_corrected/section22_corrected_report_round2.txt`). The large
conditional-MCC gaps are still reported, but as evidence about which cases
become acceptable under repair, not as evidence of an established
end-to-end quality improvement. The paper's central result is now the gap
between visible-validation acceptance and end-to-end hidden-test success
(§7.9), not a repair-superiority claim.

*Reproducibility note for the eventual paper's methods/appendix: the dataset's
content-hash, every pinned software version (Autogrep commit, Semgrep version),
the exact prompt template (content-hashed), and the full per-case, per-model,
per-sample result logs are all retained and hash-verified. See
`pipeline/PINNED_CONFIG.md` and `Research_Log/Preregistration_Checklist.md` for
the complete pinned-configuration record. The original, pre-audit state of
every result file is preserved at git tag `baseline-pre-audit`; every
correction is a separate, individually-reviewable commit on top of it, with
corrected sample-level data under `results_corrected/` alongside the
untouched originals under `results/`.*
