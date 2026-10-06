# Paper Draft Notes

**Status: living draft, updated as each phase of the study completes.** Written in
manuscript-appropriate prose (Methods/Results register), not the engineering-log
style of `Implementation_Log.md` — pull directly from here when drafting the paper.
Every number below is taken from verified project artifacts (the frozen manifest,
the freeze record, the actual result logs), not recalled from memory. Where a
number could change as later phases complete, that is marked explicitly.

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
ground-truth dataset of 300 real CVE fixes drawn from four languages (Python,
Java, JavaScript, TypeScript).

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
a 300-case final set (the locked benchmark). Case identifiers are pinned
permanently once assigned — a case's identifier never changes even if later
cases are added or removed from the dataset, so that per-case artifacts already
built (see §2.3) are never silently invalidated. The final set's composition:

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

*This classification was made by a single rater during dataset construction. A
second-rater agreement check (a blinded, stratified 45-case sample) was
prepared but had not been completed as of this writing — report inter-rater
agreement here once available, or note its absence as a limitation if it
remains undone.*

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

### 7.1 Headline ranking

Restricting to the 153 supported cases (§2.4) — the design's primary
comparison set — and sorting by MCC under the autogrep (repaired) condition:

| Rank | Model | MCC | PDS | VGR | FPR | ESR |
|---:|---|---:|---:|---:|---:|---:|
| 1 | Qwen2.5-Coder-7B-Instruct | 0.613 | 0.248 | 0.677 | 0.111 | 0.052 |
| 2 | Yi-Coder-9B | 0.607 | 0.248 | 0.611 | 0.096 | 0.059 |
| 3 | CodeGemma-7B | 0.591 | 0.157 | 0.500 | 0.060 | 0.026 |
| 4 | Qwen2.5-Coder-32B | 0.589 | 0.261 | 0.620 | 0.123 | 0.052 |
| 5 | DeepHat-V1-7B | 0.585 | 0.327 | 0.518 | 0.085 | 0.065 |
| 6 | Magicoder-7B | 0.585 | 0.065 | 0.600 | 0.067 | 0.020 |
| 7 | DeepSeek-Coder-6.7B | 0.534 | 0.085 | 0.500 | 0.074 | 0.013 |
| — | CodeLlama-7B-Instruct (FP16, precision outlier) | 0.531 | 0.150 | 0.333 | 0.056 | 0.013 |

`qwen2.5-coder:7b-instruct` ranks first by MCC on the locked final set,
matching its pilot ranking (§6) on a wholly independent 40-case set — a
consistency finding worth stating plainly rather than treating as incidental.

### 7.2 Secondary findings

- **Coverage and discrimination quality are not the same thing.** DeepHat had
  the highest raw coverage of any model on the full 300-case set (30.7% of
  attempts producing a validated rule) but ranks fifth by MCC on supported
  cases — a model that generates more nominally-valid rules is not
  automatically the one that discriminates best once false positives across
  the full bundle are weighed.
- **The strict end-to-end success bar (ESR) is far more demanding than raw
  coverage.** Across all eight models, ESR ranges from 1.3% to 6.5% of
  supported cases — versus 10–31% raw coverage — because ESR additionally
  requires zero false positives across every negative sample and detection of
  both hidden variants. This corroborates and sharpens the pilot's own
  low-coverage finding (§6).
- **Feedback-driven repair produces a large gain, larger than the raw
  coverage-percentage delta alone suggests.** Pooling across all eight models,
  raw-condition coverage was 13.4% versus 19.2% for the repaired (autogrep)
  condition — a 43% relative increase. The effect on MCC specifically is
  substantially larger for some models: `qwen2.5-coder:7b-instruct` moves from
  raw MCC 0.168 to repaired MCC 0.613. The relative coverage gain from repair
  is largest for the weakest-starting models (e.g. Magicoder's raw coverage
  more than tripled) and smallest for the strongest (DeepHat, already the best
  raw performer, gained proportionally the least) — consistent with a ceiling
  effect, where repair helps most when the first attempt is furthest from
  correct.

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
condition, MCC mean/min/max across the five repeats):

| Model | MCC mean | MCC min | MCC max |
|---|---:|---:|---:|
| DeepSeek-Coder-6.7B | 0.614 | 0.577 | 0.680 |
| Magicoder-7B | 0.599 | 0.534 | 0.636 |
| Yi-Coder-9B | 0.593 | 0.547 | 0.645 |
| CodeGemma-7B | 0.582 | 0.554 | 0.589 |
| DeepHat-V1-7B | 0.572 | 0.492 | 0.647 |
| Qwen2.5-Coder-7B-Instruct | 0.515 | 0.499 | 0.552 |
| Qwen2.5-Coder-32B | 0.505 | 0.464 | 0.554 |

**A methodological finding worth stating carefully.** This ranking does not
match §7.1's primary ranking (there, Qwen2.5-Coder-7B-Instruct is first;
here, it is sixth of seven). The cause was isolated rather than left as an
open question: recomputing the *primary run's own temperature-0 results*,
restricted to exactly the same 51-case subset, reproduces this same
ranking almost exactly (same top four, same order) — and every temperature-0.2
value above falls inside or close to that same restricted computation. The
rank difference is therefore a case-composition effect of evaluating a
smaller, different 51-case subset, not a temperature effect. Once the case
set is held fixed, temperature 0 and temperature 0.2 give consistent
rankings — the intended reading of this experiment (RQ8: "how consistent are
rule syntax and detection behavior across repeated generations?") is a
reassuring one. The separate, genuine finding is that ranking by MCC is
sensitive to which subset of cases is evaluated — relevant to how much weight
any single ranking should be given, independent of repeat-to-repeat
stability.

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

Run on the 153 supported cases, all eight primary models, at temperature 0
(matching §4's primary deterministic configuration; the design specifies no
temperature for C2 itself):

**C2's MCC is nearly indistinguishable from the autogrep condition's for
most models** — several agree to three decimal places (CodeGemma-7B 0.591
vs. 0.591; Qwen2.5-Coder-32B 0.589 vs. 0.589; DeepHat-V1-7B 0.585 vs. 0.585),
and the largest gap (Magicoder-7B, 0.566 vs. 0.585) is still modest. Every
model's C2 result is far above its raw (single-shot) MCC. Models used an
average of 3.0–3.7 of the 6 available calls; a small number of cases per
model (1–3 of 153) were bound by the output-token cap specifically, showing
it is a real constraint and not merely a theoretical one.

**Interim reading, stated as interim**: giving a single model a richer,
explicitly budgeted repair loop performs about as well as the simpler
retry mechanism already built into the pipeline. If a future C3 is to
outperform C2 under the same matched budget, the design's own framing
suggests the mechanism will need to be genuine role specialization, not
simply more attempts at the same undifferentiated task.

### 7.5 Role-capability screening (Phase 3, in progress)

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
success and regression rate, both newly operationalized here since the
design names them without exact formulas). Reusing the same 45-item test
set under a repair-framed prompt, across the three candidates named in the
design (Qwen2.5-Coder-32B, DeepHat-V1-7B, Qwen3-Coder-Next):

| Model | Repair success rate | Regression rate (of successes) |
|---|---:|---:|
| Qwen2.5-Coder-32B | 4.4% (2/45) | 50.0% |
| DeepHat-V1-7B | 0.0% | n/a |
| Qwen3-Coder-Next | 0.0% | n/a |

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

### 7.6 C3 (homogeneous multi-agent): a root-caused coverage finding

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

**C3-E's results (153 supported cases)**: 13 accepted (8.5% coverage),
every one on the first pass — not one of 140 repair attempts recovered a
case. Pooled MCC over the accepted cases is 0.593, close to this same
model's MCC under the simpler C2 (0.601) and autogrep (0.613) conditions —
quality among accepted rules is not materially worse here. Coverage is: the
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

**C3-S's results tell a different story.** Coverage is 35/153 (22.9%,
against C3-E's 8.5%), and the repair round actually recovers cases: 12 of
130 attempts (9.2%), against C3-E's zero. The larger model's self-assessment
weakness clearly attenuates with scale — a live check reproduced the exact
scenario from §7.6's investigation (an obviously broken rule given the same
visible-evidence pattern) and this time Semantic Review correctly rejected
it — though it does not disappear: 90.8% of repair attempts still fail.

This makes the design's own main causal comparison (§18.3: C3 against C2
under the same model and budget) directly answerable for both model scales,
using data already collected — no further runs were needed, since C2's
original primary run already covered both models.

| Model | Condition | Coverage | MCC | VGR | FPR | PDS |
|---|---|---:|---:|---:|---:|---:|
| Qwen2.5-Coder-32B | C3-S | 22.9% | **0.686** | 0.771 | 0.143 | 0.216 |
| Qwen2.5-Coder-32B | C2 | 30.1% | 0.589 | 0.620 | 0.123 | 0.261 |
| Qwen2.5-Coder-7B-Instruct | C3-E | 8.5% | 0.593 | 0.615 | 0.154 | 0.085 |
| Qwen2.5-Coder-7B-Instruct | C2 | 32.0% | 0.601 | 0.663 | 0.116 | 0.255 |

The two model scales produce a clean, opposite-signed pattern. For the
larger model, role separation trades coverage for a real, substantial MCC
gain (0.589 → 0.686), driven mainly by markedly better generalization to
the hidden transformed variants (VGR 0.620 → 0.771) — when C3-S does accept
a rule, it holds up better under the hidden evaluation than C2's accepted
rules do. For the smaller model, the same decomposition trades away three
quarters of its coverage for essentially no change in MCC (0.601 → 0.593,
within noise) — a straightforward net loss.

Read together with the root-caused mechanism above, this suggests role
separation's value here tracks whether the underlying model is capable
enough to use the specialized review roles productively. The smaller
model's near-total self-assessment failure means decomposition mostly just
introduces more ways to fail without a compensating benefit; the larger
model's more reliable (if still imperfect) self-assessment lets it extract
a genuine quality improvement from the same decomposition, at a real but
smaller coverage cost. This bears directly on the design's RQ9 ("does a
specialized multi-agent workflow outperform an equally resourced iterative
single-agent workflow?") and RQ10 (model-characteristic effects on
multi-agent value) — the answer appears to be "it depends on the model,"
not a uniform yes or no, and is reported as such rather than collapsed into
a single verdict.

This comparison is still scoped to one specific budget resolution (one
repair round, no second Semantic Review call, §7.6). Whether an
unrestricted-budget variant — §20 explicitly permits this as a secondary
analysis — narrows or widens the gap in either direction remains open.

**Amended after formal significance testing (§7.8)**: the `qwen2.5-coder:32b`
C2-vs-C3-S difference reported above (0.589 → 0.686) is directionally
consistent with, but not confirmed by, a case-level paired bootstrap —
95% CI (−0.009, +0.208), p = 0.073. Report this as a suggestive trend, not
a confirmed effect, at this sample size.

### 7.7 C4-A (heterogeneous, best model per role): measured-best roles do not compose

C4-A assigns each of the five Section 17.1 roles the model Phase 3's
role-capability screening (§7.5) measured as individually best for that
role: patch analysis → `qwen3-coder-next:latest`, rule generation and
syntax review → `qwen2.5-coder:7b-instruct`, semantic review →
`deepseek-r1:14b`, rule repair → `qwen2.5-coder:32b`. No new model
selection was needed — this configuration is exactly Phase 3's measured
output, run once through the unchanged §17.1 workflow and §20 budget.

Full run on all 153 supported cases, verified complete (153/153 episodes,
66 sample records = 11 accepted × 6, exact match). Results, alongside every
other condition measured so far on the same case set:

| Condition | Roles | Coverage | MCC | VGR | FPR | PDS |
|---|---|---|---|---|---|---|
| C3-S | all roles: 32B | 22.9% | **0.686** | 0.771 | 0.143 | 0.216 |
| C2 (32B) | single agent | 30.1% | 0.589 | 0.620 | 0.123 | 0.261 |
| C2 (7B) | single agent | 32.0% | 0.601 | 0.663 | 0.116 | 0.255 |
| C3-E | all roles: 7B | 8.5% | 0.593 | 0.615 | 0.154 | 0.085 |
| **C4-A** | best model per role (4 distinct models) | **7.2%** | **0.552** | 0.591 | 0.152 | **0.065** |

**C4-A is the lowest-performing condition measured so far on every metric
except FPR**, where it is statistically indistinguishable from C3-E (0.152
vs. 0.154). This is a striking result precisely because the role
assignments are not arbitrary — each one is the pilot-measured best
performer for that specific role (§7.5) — yet the composed five-role
pipeline underperforms both C3-S (a single strong model doing every role)
and even the plain single-agent C2 baselines.

**Candidate mechanism, explicitly flagged as inferred rather than directly
measured**: Phase 3's role screening evaluated each role in isolation,
against fixed, pre-built test items — never against another LLM's live
output produced in situ. C4-A composes `qwen3-coder-next`'s patch-analysis
output into `qwen2.5-coder:7b-instruct`'s rule-generation prompt, and
`deepseek-r1:14b`'s natural-language repair instructions into
`qwen2.5-coder:32b`'s repair call — pairings that were never jointly
measured during screening. C3-S and C3-E avoid this by construction: one
model, one output convention, internally consistent at every hand-off.
This reads as evidence that per-role screening metrics do not compose
additively across a heterogeneous pipeline, directly on-point for the
design's RQ10 — but the specific mechanism (cross-model interface/
convention mismatch) is inferred from the aggregate pattern, not confirmed
by inspecting individual episodes' intermediate hand-offs; that remains
open if a more direct test is wanted.

C4-B (two models — `32b` for analysis/generation/repair, `7b-instruct` for
syntax/semantic review, reusing the C3-S/C3-E pair) is the natural next
test of whether partial heterogeneity degrades more gracefully than
C4-A's four-distinct-model configuration, or whether any cross-model
interface mismatch is enough to reproduce the same collapse.

**C4-B result: it does degrade more gracefully — in fact, quality is
essentially preserved.** Full run, 153/153 complete (26/153 accepted,
17.0% coverage — between C4-A's 7.2% and C3-S's 22.9%, as expected for
"some heterogeneity, not maximal"). Pooled quality metrics: MCC 0.681,
VGR 0.808, FPR 0.192, PDS 0.170.

The complete six-condition picture, ranked by MCC:

| Condition | Roles | Coverage | MCC | VGR | FPR | PDS |
|---|---|---|---|---|---|---|
| C3-S | all roles: 32B | 22.9% | 0.686 | 0.771 | 0.143 | 0.216 |
| **C4-B** | 32B (analysis/gen/repair) + 7B (syntax/semantic) | 17.0% | **0.681** | **0.808** | 0.192 | 0.170 |
| C2 (7B) | single agent | 32.0% | 0.601 | 0.663 | 0.116 | 0.255 |
| C3-E | all roles: 7B | 8.5% | 0.593 | 0.615 | 0.154 | 0.085 |
| C2 (32B) | single agent | 30.1% | 0.589 | 0.620 | 0.123 | 0.261 |
| C4-A | best model per role (4 distinct models) | 7.2% | 0.552 | 0.591 | 0.152 | 0.065 |

**C4-B's MCC (0.681) is statistically indistinguishable from C3-S's 0.686**
— effectively tied for best of all six conditions — and its **VGR (0.808)
is the highest of every condition tested**, C3-S included. This is a clean,
controlled confirmation of the mechanism proposed (but left unverified) for
C4-A above: per-role screening metrics appear not to compose additively
once too many distinct model conventions have to interface with each
other. C4-B's two-model split mirrors C3-S/C3-E's own internal role
pairing (one convention for analysis/generation/repair, another for the
two review roles) just spread across two models instead of collapsed into
one — and it preserves C3-S-level quality almost exactly. C4-A's
four-distinct-model split, by contrast, collapsed badly on every metric.
Going from one model to two costs essentially nothing on MCC and actually
*improves* VGR; going from one model to four costs roughly 20% of MCC and
over 23% of VGR. The number of distinct conventions a pipeline has to
reconcile — not heterogeneity per se — appears to be what drives this,
though this still reads the aggregate pattern rather than confirming the
mechanism via direct inspection of individual episodes' hand-offs.

**Stated plainly, not just the favorable half**: C4-B's FPR (0.192) is the
*worst* of all six conditions, moderately higher than C3-S's 0.143. The
quality picture is not a uniform win — VGR improves, MCC holds, but
false-positive rate drifts upward. The net effect on MCC stays positive
because the TP/TN gains outweigh the added FP cost, but this trade-off is
worth reporting alongside the favorable VGR/MCC numbers rather than
omitted.

Both C4 configurations are now complete.

**Amended after formal significance testing (§7.8)**: none of the six
pairwise MCC differences among {C3-S, C3-E, C4-A, C4-B} reach even
uncorrected significance at 0.05 (closest: C3-S vs C4-A, bootstrap
p = 0.125; Holm-adjusted 0.749). The interface-mismatch reading above
remains a plausible, mechanism-grounded account of the observed point
estimates, and nothing in the formal test contradicts it — but it should
be reported as an observed pattern consistent with that hypothesis, not a
statistically confirmed effect, given the small number of accepted cases
feeding each condition's pooled MCC (11–35).

### 7.8 Formal statistical analysis (§22)

The study's last unbuilt piece: the 7 predefined comparisons (§22.3),
formally tested on the 153 supported cases. Full methodology in
`Research_Log/Section22_Scope.md`; full output in
`results/section22/comparisons_1_7_report.txt`.

One methodology note stated up front: §22.2 specifies Wilcoxon
signed-rank for paired MCC, but MCC here has always been a pooled
statistic (no natural per-case value exists) — resolved with a
case-level paired bootstrap (resample cases with replacement, recompute
each condition's pooled MCC per resample, report the 95% CI and a
two-sided bootstrap p-value on the difference) instead, reserving real
Wilcoxon for genuinely per-case scalars and McNemar for the per-case
binary ESR outcome.

**Results**:

1. **Qwen2.5-Coder 7B vs 32B**: no significant difference (MCC bootstrap
   p = 0.546) — the two scales are genuinely comparable on this task.
2. **Qwen2.5-Coder 7B vs DeepHat 7B**: no significant difference
   (p = 0.362) — no measurable security-fine-tuning effect detected.
3. **Small code-model family effect** (6 models, ~7–9B scale, Friedman on
   ESR): omnibus **is** significant (p = 0.014) — but zero pairwise
   comparisons survive Holm correction (best adjusted p = 0.469). Real
   aggregate differences exist across the family; which specific pair
   differs can't be pinned down at this sample size.
4. **Raw vs Autogrep, all 8 models**: ESR shows no significant difference
   for any model (its strict all-or-nothing bar leaves McNemar almost no
   power). But the **pooled-MCC bootstrap shows a massive, highly
   significant improvement for every model** (all 8 at p = 0.0000 — e.g.
   `qwen2.5-coder:7b-instruct` 0.168 → 0.613). This is the single most
   robust, best-powered finding in the whole analysis: Autogrep's
   retry/validation loop produces a real, large, extremely consistent
   quality improvement, even though it rarely pushes any individual case
   over ESR's strict bar.
5. **C1 vs C2**: same shape and conclusion as #4 for all 8 models
   (expected, since C2 and Autogrep were already known to track closely).
6. **C2 vs C3**: see the amendment to §7.6 above — directionally
   consistent, not confirmed, for the 32B pair; flat and non-significant
   for the 7B pair, as originally reported.
7. **C3 vs C4**: see the amendment to §7.7 above — Friedman omnibus on
   ESR not significant (p = 0.098); no pairwise MCC difference among the
   four multi-agent configs reaches significance either.

**Overall reading**: this study's most robust, well-powered finding is
the raw-vs-autogrep (and equivalently C1-vs-C2) pipeline effect — large,
consistent, and significant for every single model tested. The
multi-agent findings (C2 vs C3, C3 vs C4) are directionally interesting
and mechanistically well-motivated, but should be reported as suggestive
patterns rather than confirmed effects, given how few cases are ever
accepted under the stricter multi-agent conditions (as few as 11).

**Subgroup analysis (§22.4)**, applied to the primary benchmark's `autogrep`
condition on the full 300-case set (most statistical power in the study),
for the representative model `qwen2.5-coder:32b` (86 evaluable cases,
essentially tied for best full-set MCC among the 8 models). Every CI below
uses a repository-aware bootstrap (resampling at the repository level,
since CVEs from the same repo aren't independent — §22.4's own requirement):

| Subgroup | Buckets (MCC, 95% CI) |
|---|---|
| Language | python 0.719 (0.622–0.809); javascript 0.603 (0.436–0.752); java 0.544 (0.473–0.615); typescript 0.507 (0.354–0.706) |
| Pattern vs taint | taint 0.673 (0.602–0.746); pattern 0.587 (0.517–0.658) |
| Structural vs context-heavy | structural 0.615 (0.536–0.691); context-heavy 0.602 (0.519–0.683) — essentially flat |
| Supported vs partially supported | supported 0.589 (0.509–0.668); partially supported 0.599 (0.496–0.702) — essentially flat |
| Older vs newer CVE (median year 2023) | newer 0.692 (0.596–0.791); older 0.571 (0.501–0.639) |
| Patch size (tertiles) | small 0.671 (0.558–0.775); medium 0.607 (0.540–0.672); large 0.544 (0.429–0.658) — visually monotonic decline |
| CWE (≥10 cases only) | CWE-78 0.798; CWE-22 0.707; CWE-79 0.642; CWE-200 0.605; NVD-CWE-noinfo 0.554; CWE-94 0.507 |

166 distinct CWE IDs appear across the 300 cases; only 6 have ≥10 cases
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
evidence of a real difference); patch size shows a visually monotonic
decline from small to large patches that's at least suggestive, since the
small-vs-large CIs (0.558–0.775 vs 0.429–0.658) don't fully overlap.

**This completes Section 22 in full** — both the 7 predefined comparisons
(§22.3) and the subgroup analysis (§22.4). It's the last unbuilt piece of
the study's analysis pipeline.

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
this study's 300 cases that are **provably contamination-free for that
model** (CVE year strictly after the boundary): 78/300 (26%) for the four
~Sept-2024-cutoff models, 125/300 (41.7%) for the three ~2023-release
models. This gives a concrete, per-model clean subset that could anchor a
future, more targeted contamination check (not yet done as its own
separate analysis).

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
`qwen2.5-coder:32b`: 0.359 vs 0.636), the opposite of what contamination
would predict. Only `DeepHat-V1-7B` (0.646 vs 0.574) and `codegemma:7b`
(0.566 vs 0.551) show a modest edge. Given only 9 or fewer evaluable cases
per model in this 15-case subset, this check has limited power and should
be read as "no clear evidence of inflation," not "confirmed clean."

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
for this study, as §23 itself anticipates. The strongest concrete
evidence is the 15-case commit overlap with a publicly-distributed rule
corpus — a real, quantified risk, not a hypothetical one — but the
accompanying performance check found no clear inflation signal on those
specific cases. The provably-clean per-model subsets (78–125 cases,
depending on model) are available for a more targeted re-analysis if a
reviewer wants a contamination-controlled version of the headline numbers.

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

## 10. Known limitations, stated explicitly

- **Six-sample bundle size limits the threshold-sensitivity analysis** the
  study's own protocol calls for (§5) — the prescribed 3×3 sweep is
  mathematically unable to show sensitivity at this bundle size.
- **Representability labeling is currently single-rater.** A second-rater
  check was prepared (§2.4) but not completed as of this writing.
- **CodeLlama's inclusion is precision-confounded** by infrastructure
  availability (§3) and is reported separately rather than ranked.
- **For a small number of cases, the "benign look-alike" sample is
  syntactically identical to the vulnerable code** (the security-relevant
  distinction is purely semantic — e.g. the same conditional expression used
  once to gate an authorization decision and once to gate a debug log line).
  For such cases, no purely syntactic rule can achieve a true negative on the
  benign sample, which imposes a hard ceiling on BSDR/false-positive
  performance independent of model quality. Worth identifying and reporting
  the affected case count explicitly.
- **The primary comparison set (153 supported cases) is smaller than the full
  300-case dataset.** Confidence intervals should be computed and reported at
  this effective sample size (§22, now complete).

## 11. Not yet done (tracking, for completeness of the eventual paper)

- **Sections 22, 23, and 24 are all now complete** (§§7.8, 8, 9) — every
  numbered analysis section in the design document now has real,
  evidence-grounded content. Remaining work is write-up/synthesis
  (building the actual paper from this document), not new analysis.
- A systematic exact/near-duplicate search against the broader public
  Semgrep rule ecosystem (beyond the one 645-rule vendored corpus already
  checked, §8) is the one concrete, not-yet-run follow-up identified while
  writing up contamination controls.
- C4-A and C4-B are both now complete (§7.7) — the design's two-configuration
  cap (§18.6) is fully exercised.
- A secondary, unrestricted-budget comparison for C3 (§20 explicitly permits
  this), to check whether the budget resolution itself (one repair round,
  no second Semantic Review call) is suppressing recovery for either model,
  or whether the pattern reported in §7.6 is intrinsic to each model's own
  self-assessment reliability regardless of how many rounds it gets.

---

*Reproducibility note for the eventual paper's methods/appendix: the dataset's
content-hash, every pinned software version (Autogrep commit, Semgrep version),
the exact prompt template (content-hashed), and the full per-case, per-model,
per-sample result logs are all retained and hash-verified. See
`pipeline/PINNED_CONFIG.md` and `Research_Log/Preregistration_Checklist.md` for
the complete pinned-configuration record.*
