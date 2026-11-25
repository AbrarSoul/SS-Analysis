# Controlled 2x2 comparison: frozen protocol (DRAFT, pending sign-off)

Date: 2026-10-12. Status: **draft protocol, not yet frozen or executed**. No new inference or
scans have been launched to produce this document. This drafts the comparison
`Research_Direction_20261011.md` proposed ("Proposed controlled comparison"), incorporating
everything learned while completing the 5 bounded-investigation items (see
`Bounded_Investigation_Tracking.md` and `Correction_Log.md`'s 2026-10-12 entries) and four rounds
of independent review on that work, the last of which
(`Controlled_2x2_Protocol_Review_20261012.md`) reviewed this draft itself and found the
confirmation-set-size calculation substantially wrong (corrected in §8 below) plus several missing
operational decisions (added in §3/§4/§5/§6/§6a/§10 below). It is written to be frozen -- method, metrics,
candidate-selection policy, and stopping rule fixed before any confirmation-set outcome is looked
at -- but several numeric choices below are explicitly flagged as **draft values needing the user's
sign-off**, not unilateral decisions, since they encode value judgments (minimum worthwhile effect,
resource budget) this process should not impose on its own.

## 1. Research questions (unchanged from Research_Direction_20261011.md)

1. How well does passing validation on the original vulnerable/patched pair predict generalization
   to unseen vulnerability-preserving and vulnerability-removing transformations?
2. Which failures arise from rule construction, vulnerability inference, available context, target
   parsing, or evaluation labels?
3. Under equal resource budgets, does structured rule construction (a typed representation) and
   additional development-only behavioral feedback (probes) improve held-out complete success
   relative to the original prompt?

## 2. The 2x2 design (unchanged)

| Condition | Rule construction | Behavioral feedback |
|---|---|---|
| A | Original-prompt direct output (hand-typed YAML) | Original vulnerable/patched pair only |
| B | Typed representation + deterministic serialization | Original pair only |
| C | Original-prompt direct output | Original pair + development probes |
| D | Typed representation + deterministic serialization | Original pair + development probes |

A vs. B estimates the construction intervention. A vs. C estimates additional behavioral feedback.
D tests their combination and possible interaction. **B and D change the output contract -- their
difference from A/C must never be reported as a prompt-only improvement.**

## 3. Shared infrastructure across all 4 cells (fixed, not varied)

- **Engine**: pinned Semgrep 1.177.0, `semgrep_env()`'s PATH-prepending construction (the same
  pysemgrep-delegation guard now applied everywhere in `diagnostic_v2.py` and
  `verify_scan_integration.py`). `environment.json` records the actual resolved version per run,
  and the run aborts on any version other than 1.177.0 (existing `main()` preflight behavior,
  unchanged).
- **Sample bundle and location annotations**: the same 6-sample bundle, `load_merged_ann()`'s
  merged location ranges, and `resolve_target_path()`'s unconditional-per-call `.tsx` staging
  verification -- all as already fixed and tested this session (31/31 regression tests passing).
- **Acceptance policy: `corrected`, not `legacy`.** This is a deliberate departure from every
  historical run (which used `legacy`, the location-blind gate). Justification: this entire session
  demonstrated that `legacy_accepted` produces real false wins (a rule matching the right file but
  the wrong line) that `visible_correct` catches and that `--acceptance-policy corrected` gives the
  model a genuine chance to repair instead of silently banking. Running a NEW controlled comparison
  under the same known-lenient gate used historically would re-import a confound this project has
  already spent significant effort characterizing and fixing. `legacy` numbers are not needed for
  this comparison's own internal validity, but should still be recorded alongside (cheap: both
  fields are always computed) so this comparison remains comparable to the historical record if
  anyone asks "how would this have scored under the old gate."
- **Max attempts**: 3 (unchanged from every historical run).
- **Temperature**: 0 for the primary model. `Research_Direction_20261011.md` explicitly warns
  "temperature zero alone does not establish repeatability" -- see §6 (repeated trials) for how
  this is handled rather than assumed away.
- **Compiler-error feedback**: identical across all 4 cells (already true of the existing repair
  loop) -- "All cells can receive the same compiler-error feedback," per the Research Direction.
- **Token/call ceilings, matched across cells**: max output tokens 2048 per call (the existing
  `diagnostic_v2.py` default, carried over unchanged -- not re-derived). Input/context policy:
  identical prompt-construction code path across A/B (same `PatchInfo` fields, same surrounding
  instructions minus the output-contract-specific portion) and C/D (same, plus probe feedback text
  when applicable). Retry accounting: each of the 3 attempts counts as one call regardless of
  outcome; a parse/compile failure that triggers attempt N+1 is NOT free -- it consumes the same
  budget as a successful attempt. Timeout/error treatment: a request timeout or API error counts as
  a failed attempt (consumes budget, logged, retried up to the 3-attempt ceiling) rather than being
  silently retried outside the budget. **Equal ceilings do not imply equal actual expenditure** --
  actual calls, tokens, scans, and elapsed time must be reported per condition/model/trial, not just
  the ceiling that was offered (per the review's finding 3).
- **Legacy-comparability caveat** (added per review finding 5): recording both `legacy_accepted` and
  `visible_correct` on every candidate generated under the `corrected` policy answers "how would
  THIS candidate have scored under each gate" -- it does NOT reconstruct what a `legacy`-policy
  repair loop would actually have returned, since `legacy` can accept and stop after a DIFFERENT
  (worse) candidate than whatever `corrected` eventually settles on after further repair attempts.
  Any claim like "this is directly comparable to the historical legacy-policy runs" must be
  qualified to mean "the same candidates scored under both gates," not "the same attempt
  trajectory" -- a genuine head-to-head policy comparison would need either the full attempt
  trajectories preserved under both policies or a separately controlled run per policy. No
  historical score needs changing because of this -- it is a scope qualification on what the new
  comparison's own `legacy`-gated side-numbers can and cannot support.

## 4. Condition-specific specs

### A: original-prompt direct output
Exactly `autogrep_default`'s existing prompt and free-form YAML output, run through
`diagnostic_v2.py` with `--acceptance-policy corrected` (the only change from the historical
`qwen3_v3`/`qwen3_mechanism_v*` runs). This is the new baseline for this comparison -- not the old
`legacy`-gated 6/24, which remains a separate, historically-preserved number.

### B: typed representation + deterministic serialization
The model emits a `TypedRule`-shaped structure (JSON, since YAML-as-model-output was never the
actual constraint -- the constraint is "a constrained schema," not a serialization format); 
`pipeline/typed_rule.py`'s `TypedRule.validate()` + `to_semgrep_yaml()` do 100% of the
schema-validation and YAML assembly, never the model.

**Supported grammar, stated explicitly (Research Direction item 4: "if they restrict
expressiveness, report the restriction")**: a `TypedRule` supports exactly one of
`pattern` / `pattern_either` / `taint_sources`+`taint_sinks` as the base match, plus optionally
`pattern_inside`, `pattern_not` (one or more), and `pattern_not_inside`. Composition is **always**
`patterns:`-nested when any of `pattern_inside`/`pattern_not`/`pattern_not_inside` is present (never
a top-level sibling -- confirmed this session that the sibling form silently fails to exclude for
`pattern_not`, and is silently IGNORED entirely for `pattern_inside`; neither has a safe sibling
shortcut). Taint mode does not support combining with `pattern_not`/`pattern_inside`/
`pattern_not_inside` (unsupported, explicitly rejected by `validate()`, never silently dropped --
0/87 historically-accepted rules used taint mode, so there is no empirical precedent this
restriction removes). **Restriction this imposes relative to free-form YAML**: any Semgrep
construct outside this grammar -- `pattern-regex`, `metavariable-regex`,
`metavariable-pattern`, multiple distinct taint sinks with different messages, nested
`pattern-either` inside `pattern-not`, etc. -- is simply not expressible in condition B/D. Of the 24
reference rules, 2 use `pattern-regex` (`CASE-0063`, `CASE-0339`) and would need a different
`TypedRule` field to be expressible at all; this is a real, reportable restriction, not swept under
the rug. Any case whose minimal correct rule requires an unsupported construct is NOT disqualified
from condition B/D -- the model simply cannot express the exact reference form and must either find
an expressible equivalent or fail construction; this is itself part of what's being measured in
this condition, not a case-selection decision.

**Prompt/decoder spec (added per review finding 3 -- previously unspecified)**: the model is
instructed to emit a single JSON object with `TypedRule`'s field names
(`id`/`message`/`severity`/`languages`/`metadata`/`pattern`/`pattern_either`/`taint_sources`/
`taint_sinks`/`pattern_not`/`pattern_inside`/`pattern_not_inside`), decoded via `json.loads()` then
constructed as `TypedRule(**decoded)` and validated via `.validate()`. A `json.JSONDecodeError` or a
`TypeError`/`ValueError` from construction/validation is treated exactly like a YAML parse/validate
failure in condition A -- it produces the same class of repair-feedback message (the exception's
own message, naming the offending field) and consumes one of the 3 attempts, never silently
retried outside the budget or treated differently from A's failure path.

**Episode termination and final-candidate selection, for conditions A/B (no probes)**: an episode
accepts and stops on the first candidate that passes `visible_correct` (under the `corrected`
policy, §3) within 3 attempts. If no candidate passes within 3 attempts, the LAST generated
candidate (whether or not it even parsed) is retained for diagnostic/construction-validity scoring,
the episode is marked as an acceptance failure, and its `complete_success` is recorded as `False`
by definition -- an unaccepted episode can never be a complete success, regardless of what its
hidden-stage evaluation would say if run anyway. This mirrors `run_model_case()`'s existing behavior
exactly.

**CORRECTED 2026-10-12, same day, for conditions C/D**: a follow-up review
(`Controlled_2x2_Protocol_Followup_20261012.md`) found this rule, as written, contradicts §5's
probe-repair requirement when read as applying to all 4 conditions -- §5 says a probe failure after
visible-pair success must still trigger a repair attempt, but the rule above says to accept and
stop on `visible_correct` alone, with no carve-out. A literal implementation of the rule as
originally written would make C/D behave exactly like A/B, silently skipping probe evaluation
entirely. Fixed with one explicit combined gate, replacing the single rule above for C/D only:

```
A/B:                         accept and stop on visible_correct
C/D, case HAS an eligible probe pair:  accept and stop on
                              visible_correct AND vulnerable_probe_correct AND patched_probe_correct
C/D, case has NO eligible probe pair:  accept and stop on visible_correct alone
                              (the declared A/B fallback, §5's eligibility-filter path -- recorded
                              as a fallback with its reason, never silently indistinguishable from
                              a genuine probe pass)
```

`*_probe_correct` requires the probe's own Semgrep scan to have actually succeeded (`scan_ok`) AND
produced the correct detection outcome -- a scan error on a candidate's probe evaluation must NEVER
be silently treated as "no eligible probe" (that would wrongly collapse a real probe failure into
the no-probe fallback path); it is a failed check like any other, triggering repair feedback same as
a probe that scanned fine but got the wrong answer. If the 3rd attempt still fails the probe check,
the episode exhausts its budget and follows the same unaccepted-episode failure policy as A/B (last
candidate retained, marked a failure, `complete_success=False`). Before any C/D inference, this
combined gate's 4 paths (visible-pass/probe-fail -> repair; all-checks-pass -> stop;
budget-exhausted -> failure; ineligible-case -> declared fallback) must be exercised in an offline
test, not just read as a design -- this is a real engineering task §5 already schedules, not
something this document review itself tested.

### C: original-prompt output + development probes
Same as A, plus a probe-eligibility check and probe-based repair feedback -- see §5.

### D: typed representation + development probes
Same as B, plus §5.

## 5. Development-probe eligibility and construction (final design, after 2 rounds of correction)

This section summarizes Item 5's design as it stands after `Bounded_Investigation_Tracking.md`'s
three correction rounds (circular validation oracle -> AST-isomorphism oracle; "different family"
framing self-contradicting the renaming construction -> explicit within-family framing; no
reflection safety -> eligibility filter; parameter renaming breaking keyword callers -> local-only
non-parameter renaming). **Still NOT implemented or run** -- this remains a design, and implementing
it is new engineering this protocol schedules, not already-built infrastructure like §3-4.

- **Construction**: from `PatchInfo.vulnerable_function`/`patched_function` only (never the hidden
  variant files). A scope-binding-aware AST transform renames purely LOCAL bindings only -- never a
  function parameter/`arg` node, i.e. never anything part of the externally-visible signature (this
  specifically closes the keyword-caller-breakage failure mode found in round 3).
- **Eligibility filter, applied before any probe is constructed**: a candidate function is excluded
  from probe eligibility if its AST contains any `Call` whose `func` resolves to `locals`,
  `globals`, `getattr`, `setattr`, `vars`, `eval`, or `exec`. The exclusion rate must be recorded and
  reported as a finding if large, not silently discarded.
- **Validity check, never using any rule as the oracle**: (1) the transformed code parses as valid
  source in the target language, (2) an AST-isomorphism check against the original -- structurally
  identical except at renamed binding nodes.
- **Stated scope, honestly**: this is an explicitly WITHIN-family signal (the same renaming family
  reserved for the real hidden `variant_vulnerable_1`, just a freshly-constructed, independent
  instance never derived from or compared against the actual hidden file). Research Question 3 as
  testable by this construction is "does feedback from an additional, independently-renamed
  development instance improve held-out complete success" -- narrower than "does feedback from a
  genuinely different transform family generalize." A true different-family probe needs its own
  design pass and is out of scope for this protocol's first run.
- **Firewalling**: probes stored under `_dev_probes/<case_id>/`, never written into or read from
  `benchmark/cases/`. Conditions A and B's code path must not import the probe module at all.
- **Feedback mechanism**: fed into the REPAIR step only, after a rule already passes the visible
  pair, as "your rule must also correctly handle this additional test case" -- only when the current
  rule gets the probe wrong; not a mandatory addition every round.
- **Resource accounting**: C and D's probe checks consume additional Semgrep scans (not additional
  LLM calls, unless a probe failure triggers an extra repair attempt that would not otherwise have
  happened). Both must be counted and reported -- "different numbers of probes consume resources and
  must be accounted for, not treated as free evidence," per the Research Direction.
- **Operational specifics (added per review finding 3 -- previously unspecified)**:
  - **Probe count per case**: exactly 1 vulnerable + 1 patched probe pair per case, generated once
    and cached (not regenerated per attempt or per trial) -- deterministic given the same
    `vulnerable_function`/`patched_function` input, so caching introduces no inconsistency, and
    reusing the same case-level probe across models and trials is required for a fair A-vs-C/B-vs-D
    comparison (a different probe per trial would add uncontrolled variance to exactly the
    comparison this condition exists to isolate).
  - **Supported languages**: the AST-transform/eligibility-filter/isomorphism-check machinery must
    be implemented per language in the diagnostic's 4-language set (Python, Java, JavaScript,
    TypeScript) -- Python's `ast` module is the only one with existing project precedent; Java/JS/TS
    each need their own AST library and their own enumeration of reflection-equivalent constructs
    (e.g. Java's `Class.getDeclaredField`/`getMethod`, JS/TS's `obj[key]` dynamic property access
    alongside `eval`). This is real, language-specific engineering, not a single shared
    implementation -- `Call`/`arg` in the design above is Python `ast` terminology and must be
    translated per language, not assumed to generalize.
  - **Name-collision/scope checks**: the renamed local binding must not collide with an existing
    name already in scope (parameter, other local, enclosing-scope name) -- checked as part of the
    AST-isomorphism validity pass; a collision disqualifies that specific rename choice (try another
    candidate name) rather than disqualifying the whole function from probe eligibility.
  - **Eligibility/generation-failure fallback**: a case that fails the reflection-eligibility filter,
    or whose function has no renamable local binding at all, or whose probe fails the
    isomorphism/parse check, gets NO probe for that case -- condition C/D runs that case exactly
    like A/B for that case (no probe feedback available), and the episode remains in the primary
    denominator (never excluded). Probe coverage (the fraction of cases that actually got a working
    probe) must be reported as its own number, not silently absorbed into the headline comparison.

## 6. Models and repeated trials

- **Primary model**: `qwen3-coder:30b` (the model every historical diagnostic run used).
- **Contrasting model**: `gpt-4o`, for a stated reason -- already proven technically compatible with
  this exact pipeline (the `results/runs_openai_full_20261010/` and
  `results/runs_openai_diagnostic_20261009/` runs this session) and of a different
  hosting/training lineage (OpenAI-hosted vs. open-weight via GPT-Lab), which is itself a sufficient
  reason to include it as a contrast. **CORRECTED per review finding 4**: the earlier draft of this
  bullet additionally argued gpt-4o was chosen because it was "already shown to be in statistical
  parity" with qwen3-coder, framed as ruling out model-driven differences. That argument is
  withdrawn -- failing to detect a difference in an earlier, smaller comparison does not establish
  equivalence, and does not rule out a model-by-intervention INTERACTION (e.g. the typed
  representation helping one model and not the other) even if the two models' baseline A-condition
  rates happen to be similar. The lineage/hosting contrast alone is the actual, sufficient
  justification; the parity claim is not needed and should not be used as one.
- **Analysis implication**: because a model-by-intervention interaction cannot be ruled out a
  priori, every comparison (A vs B, A vs C, etc.) must be reported WITHIN each model first, with
  cross-model heterogeneity itself reported as a finding, not assumed away by pooling the two
  models together as if they were interchangeable replicates. See §6a.
- **Repeated trials per cell**: **3, as a draft value** -- small and fixed, per the Research
  Direction's explicit instruction, retaining all 3 trials (never selecting a winning replicate).
  **CORRECTED per review finding 4**: the earlier draft justified 3 as "the minimum that lets
  within-cell variance be estimated at all" -- that is also wrong; 2 repeats already permit a sample
  variance estimate. 3 is a reasonable small pilot allocation on cost/schedule grounds, not a
  mathematical minimum, and is retained on that basis alone. **This number needs the user's
  sign-off** -- a larger number (5?) would tighten the variance estimate at proportionally higher
  cost; 3 is a floor chosen for the development pilot, reassessed for the confirmation run using
  observed variability and cost (per the review's own recommendation).

## 6a. Statistical analysis plan (added per review finding 4 -- previously unspecified)

- **Repeat aggregation**: for each (case, condition, model) cell, the 3 trials' `complete_success`
  values are averaged to a per-case success RATE in [0, 1/3, 2/3, 1] before any cross-case
  comparison -- trials are never treated as 3 additional independent cases (repeated trials on the
  same case are not independent data points, per the Research Direction and the review).
- **Primary vs. secondary contrasts, predeclared**: for the full 2x2 (once C/D exist), the three
  estimable effects are the construction main effect `((B-A)+(D-C))/2`, the feedback main effect
  `((C-A)+(D-B))/2`, and the interaction `D-C-B+A`, each distinct from the simple pairwise effects
  B-A and C-A. **One of these must be designated the single primary/confirmatory contrast before
  the confirmation set is scored**. **Recommendation adopted from
  `Controlled_2x2_Protocol_Followup_20261012.md`**: during the A/B development pilot (before C/D
  exist), report B-A descriptively only -- it is not yet a confirmatory contrast on pilot data.
  For the eventual full-factorial confirmation, designate the construction main effect
  `((B-A)+(D-C))/2`, computed on `qwen3-coder:30b` specifically, as the single primary contrast; the
  feedback main effect, the interaction, and gpt-4o's replication/heterogeneity are all secondary or
  exploratory. If a confirmatory claim is also wanted on gpt-4o (not just as a heterogeneity check),
  that requires its own explicit multiplicity plan before testing, not an assumed free second
  confirmatory test. This is a recommendation, not yet the user's decision -- see §11.
- **Repository/case grouping preserved in uncertainty estimates**: paired-difference confidence
  intervals/tests must account for cases sharing a repository or CVE family (already a known
  consideration for the development set's own CVE sourcing), not treated as i.i.d. draws if any
  such clustering exists in the confirmation set. **Candidate concrete method (not yet decided),
  CORRECTED 2026-10-12 same day** (per `Protocol_Review_Closure_20261012.md` -- the prior wording
  called this a "repository-cluster bootstrap" but then described resampling at the case level,
  which does not preserve within-repository dependence and so isn't actually a cluster bootstrap at
  all; fixed to describe what a cluster bootstrap actually requires): sample REPOSITORY CLUSTERS
  with replacement, not individual cases -- each draw pulls an entire repository's cases together,
  preserving every case's full condition/model/repeat vector within that cluster; if a repository is
  drawn twice in one resample, its whole group of cases is included twice. Recompute the specified
  case-weighted statistic (e.g. mean case-level difference) on each resampled dataset and use the
  resulting distribution for the interval; reuse the same cluster draws for cross-model differences.
  Cross-repository CVE families still need their own explicit grouping rule (do they count as one
  cluster spanning repositories, or stay split by repository?) before this is usable -- not resolved
  here. If the confirmation set happens to have exactly one case per repository, case-level and
  cluster-level resampling coincide, but that is a special case, never a general assumption. Before
  adopting this, freeze the resampling seed/count, case weighting, and that cross-repository-family
  grouping rule, and simulate its power across
  plausible pilot-informed correlation/variance scenarios -- none of this is required to run the
  descriptive A/B pilot, only to finalize the confirmation analysis.
- **Cross-model reporting**: each contrast above is computed separately per model, with the two
  models' results reported side by side plus an explicit heterogeneity statistic (not pooled into
  one number) -- consistent with §6's interaction caveat.

## 7. Candidate selection

- **Development set**: the existing frozen 24-case diagnostic subset
  (`results/diagnostic_20261010/qwen3_v3/selection.json`). This set has been repeatedly consulted
  all session (every mechanism-prompt trial, the exclusion-composition ablation, Item 3's review) --
  per the Research Direction's own warning, "repeatedly consulting its hidden outcomes makes it
  unsuitable for fresh confirmation." It is used ONLY to pilot and debug conditions B/C/D's new
  infrastructure (confirm the typed-representation output contract actually parses model output,
  confirm probes actually get constructed and fed back) before any confirmation-set run. No
  confirmation claim may be based on this set's own numbers.
- **Confirmation set**: must be newly collected, repository-disjoint from both the development
  subset's and the existing 300-case final dataset's source repositories/CVEs, with an independent
  semantic review at selection time (not after). Candidate sourcing: the same MoreFixes-based
  curation pipeline and eligibility filters already established (Section 5-9 of the frozen
  experimental design), explicitly excluding any repository already contributing a development-set
  or primary-benchmark case. **Not yet collected -- sourcing this set is new work this protocol
  schedules**, not something already sitting in the repo.
- **Deduplication**: closely related patches (same CVE family, same upstream fix pattern) must be
  deduplicated within the confirmation set; any unavoidable remaining contamination/relatedness
  must be recorded as a stated limitation, not silently ignored.

## 8. Minimum worthwhile effect and confirmation-set size (DRAFT -- needs explicit sign-off)

Per the Research Direction: "Define a minimum worthwhile E2E improvement and acceptable cost before
confirmation. Select test-set size using that effect size and expected paired disagreement; 24
development cases are not adequate merely because they are convenient."

**Draft minimum worthwhile effect**: a **10 percentage-point** absolute improvement in
`complete_success` rate (e.g. a condition moving from 25% to 35% of requested cases). **CORRECTED
per review finding 2**: the earlier draft justified this against the 24-case set's own resolution
and observed prompt-to-prompt swings -- the review correctly notes that neither establishes
practical value or isolates sampling noise from a real effect; those were descriptive facts about
an unrelated small sample, not a justification for what counts as worthwhile. Retained as a
provisional planning target on cost grounds alone (per the review's own recommendation: justify it
against the cost of B/D's extra engineering and C/D's extra scans), not against the 24-case set's
resolution, alongside a 5-point sensitivity scenario (per §8's power table above) so the cost of
targeting a smaller effect is visible, not hidden. **This remains a value judgment needing the
user's sign-off**, now on the corrected basis.

**One more precision added per the followup review**: §8's power table shows power to detect a
TRUE 10-point effect, i.e. P(reject H0 | the real difference is 10 points). A study powered this
way and then reaching statistical significance does NOT thereby prove the real improvement is AT
LEAST 10 points -- it rejects the null of no difference, with an estimated effect that could be
smaller (or larger) than 10 points. The confirmation analysis must report the estimated effect size
with its own confidence interval, not treat "reached significance under a design powered for 10
points" as equivalent to "demonstrated a >=10-point improvement."

**Confirmation-set size: WITHDRAWN AND RECOMPUTED, 2026-10-12, same day.** The original draft
claimed 80-100 cases reaches 80% power for a 10-point effect at 25% discordance. An independent
review (`Controlled_2x2_Protocol_Review_20261012.md`) computed the actual exact-conditional-McNemar
power for that scenario and found it substantially lower; **independently reproduced here, exactly,
via a direct binomial-sum computation** (not taken on faith -- see verification below) before
accepting the correction:

| N (independent paired cases) | Power for a 10-point difference @ 25% discordance |
|---:|---:|
| 80 | 35.4% |
| 100 | 44.0% |
| 200 | 78.7% |
| 207 | 80.2% |

**207 is the first integer N reaching 80% power under these exact assumptions** -- not 80-100. The
80-100 figure in the original draft was a hand-waved "rule of thumb" McNemar sample-size estimate,
never actually computed; this is exactly the kind of unverified numeric claim this project's own
standing practice (compute/verify real numbers, never hand-wave) exists to catch, and it caught
itself here via external review rather than before publishing the draft. A 5-point effect at the
same discordance needs 817 cases -- small effects are dramatically more expensive to confirm.

**This is still a planning scenario, not the finalized requirement**, for reasons the review
correctly identifies and this draft had not yet accounted for:
- It treats each confirmation case as one independent paired observation. §6a's actual design
  averages 3 repeated trials per case into a success RATE, not a single binary outcome per case --
  the real estimator's variance (and therefore its required N) differs from the simple binomial
  McNemar scenario above and needs its own calculation once the primary contrast and repeat-
  aggregation method (§6a) are finalized, not assumed to match this table.
- It does not account for repository/case clustering (§6a) or for running this calculation once
  per model with a predeclared multiplicity policy across the construction/feedback/interaction
  contrasts (§6a) rather than treating "80% power for one pairwise comparison" as sufficient for the
  whole study.
- **CORRECTED 2026-10-12, same day** (per `Controlled_2x2_Protocol_Followup_20261012.md`): 207 and
  817 are specified single-independent-pair binary scenarios, not universal requirements or lower
  bounds for the actual averaged-repeated-trials design §6a describes. Neither should be read as
  "the real N must be at least this much" -- do not freeze a confirmation N from this table at all;
  207 and 817 are illustrative of the scenario's sensitivity to effect size, nothing more, until
  the real estimator (§6a) is specified and its own power is computed or simulated.

**Budget planning implication, stated directly, without freezing N**: the simple i.i.d.
10-point/25%-discordance scenario needs roughly 200+ cases for 80% power, nowhere near the original
draft's 80-100 -- that correction stands. But per the followup review, this table must not be used
to set the actual confirmation N; §6a's real estimator (repeat-averaged success rates, clustering,
multiplicity) needs its own power calculation or simulation before any N is chosen. Confirmation
size is an OPEN decision (§11), not a number this section settles. If the feasible sample, once
sourcing capacity (§7) is known, is smaller than whatever the finalized calculation requires,
report the attainable precision/power honestly rather than claiming any target was met.

**Independent verification of the power table above** (done before accepting it, per this
project's standing discipline of never taking a reviewing agent's claim on faith): recomputed the
exact two-sided conditional McNemar power directly in Python (summing, over every possible
discordant-pair count `d ~ Binomial(N, q)` and win count `w ~ Binomial(d, p_win/q)`, the exact
binomial two-sided test's rejection probability) for N in {80, 100, 200, 207} -- reproduced
35.37%, 43.99%, 78.68%, 80.18% respectively, matching the review's table to within rounding.

**All numbers in this section remain placeholders for a decision, not decisions.** Nothing
downstream (sourcing the confirmation set, running it) should proceed until the user confirms or
adjusts them, now on the corrected basis above.

## 9. Outcome metrics (from the Research Direction, unchanged)

- **Primary**: complete success over ALL requested cases (rejected and invalid outputs retained as
  failures, never dropped from the denominator).
- **Secondary**: construction validity (parsed/compiled), correct-location visible discrimination
  (`visible_correct`), hidden-positive recall, hidden-negative specificity, and resource cost
  (LLM calls, tokens, Semgrep scans, wall-clock time -- all of which §5/§6 already require tracking
  per condition).
- Unevaluated outputs and scan errors are reported separately from true negatives (the same
  `unclassified_scan_error`/`scan_ok` distinction already built into `audit_failure_categories.py`
  and `exclusion_composition_ablation.py` this session) -- never silently folded into either gate.
- Report paired differences (gained/lost cases individually listed, not just aggregate deltas) with
  repository-aware uncertainty. A small positive point estimate alone is not a demonstrated
  improvement.

## 10. Stopping rule and freeze conditions

**Episode-level stopping** is specified in §4 (accept-and-stop on first passing candidate within 3
attempts; last candidate retained, marked a failure, otherwise).

**Experiment-level stopping (added per review finding 3 -- previously missing)**: the confirmation
run executes a FIXED, pre-allocated number of episodes (every confirmation case x both models x 3
trials x all 4 cells, or A/B only per §11's open decision 4) and stops only when that fixed
allocation completes -- never stopped early because a favorable effect appears partway through, and
never extended because an unfavorable one does. Infrastructure interruptions (a crashed run, an API
outage mid-batch) are handled by resuming/re-running the exact missing episodes to complete the
original fixed allocation, never by substituting a different subset or treating a partial run as
final without saying so explicitly. **Precision added per the followup review**: "missing episode"
means one that never started or never finished its attempt sequence -- an episode that already
completed all 3 attempts and ended in the declared unaccepted-episode failure policy (§4) is NOT
missing and is NOT eligible for a fresh budget on resume; resuming preserves every already-consumed
attempt/call against that episode's original 3-attempt ceiling, it does not reset it. This is a
requirement implied by the 3-attempt budget already specified, stated explicitly here because the
review correctly flagged it as a real implementation detail an interruption-handling script could
otherwise get wrong by accident.

This protocol is not executable as-is: §6's trial count, §6a's primary-contrast designation, and
§8's effect-size/confirmation-size numbers need the user's sign-off, and §7's confirmation set does
not exist yet. Once those are resolved, this document (or its finalized successor) should be
treated as frozen -- method, metrics, candidate-selection policy, and both stopping rules above
fixed -- before any confirmation-set outcome is looked at, per the Research Direction's
"Confirmation and meaningful novelty" section. A split made after studying all cases cannot
retroactively become an untouched test set, so the confirmation set, once sourced, must not be used
for any further prompt/serializer/probe iteration -- that iteration happens only on the development
set (§7), exactly as this whole bounded investigation already did.

## 11. Open decisions requiring the user, listed together

Updated 2026-10-12, twice: first after `Controlled_2x2_Protocol_Review_20261012.md`, then after
`Controlled_2x2_Protocol_Followup_20261012.md` sharpened the primary-contrast and confirmation-size
recommendations further. Both reviews' recommendations are included alongside each item, not
substituted for the user's own decision.

1. §6: repeated trials per cell -- 3 for the development pilot (draft; both reviews: keep 3 for
   the pilot, reassess the confirmation allocation using observed variability and cost once the
   pilot runs).
2. §6a: which contrast is the single primary/confirmatory one for the eventual full-factorial
   confirmation -- construction main effect, feedback main effect, or a split-alpha plan across
   both; separately, whether gpt-4o gets its own confirmatory claim or stays a heterogeneity check.
   **Followup review's recommendation**: during the A/B pilot, report B-A descriptively only (not
   confirmatory); for the full confirmation, designate the construction main effect on
   `qwen3-coder:30b` as primary, with feedback/interaction/gpt-4o as secondary or exploratory unless
   a separate multiplicity plan is made for a second confirmatory model. Not the user's decision
   yet.
3. §8: minimum worthwhile effect size -- 10 points, now justified against cost rather than the
   24-case set's resolution (draft; reviews: keep 10 points provisionally, add a 5-point sensitivity
   analysis alongside it, and report any eventual significant result's estimated effect size with
   its own CI rather than treating "significant under a 10-point-powered design" as "proved >=10
   points").
4. §8: confirmation-set size -- **do not freeze yet**. 207/817 are illustrative single-independent-
   pair scenarios only, not the real target (sharpened by the followup review after the first
   review's own correction from the original draft's unverified 80-100 figure); the real number
   needs its own calculation once decision 2's estimator and primary contrast are fixed.
5. Whether to pursue C/D (the probe conditions) in the first run at all, given §5 is design-only and
   its combined accept/stop gate (§4, just corrected) is not yet implemented or offline-tested
   (both reviews: pilot A/B first; add C/D only after the combined gate and probe validity are
   implemented and verified offline -- an A/B-only pilot is preparation for the full 2x2, not the
   experiment itself).
6. Confirmation-set sourcing (§7) is new curation work -- confirming this is in scope now, not
   deferred further (both reviews: scientifically justified for a fresh generalization claim;
   define sourcing/eligibility/provenance/independent review now, defer the actual collection
   commitment until decision 4's number and sourcing feasibility are both known).

**Rough budget ceiling for the development pilot alone** (not a request to spend this, a planning
number): 24 development cases x 2 models x 2 conditions (A/B only, per decision 5's recommended
ordering) x 3 trials = 288 episodes, at most 864 calls under the 3-attempt cap. All 4 cells at the
same scale would be 576 episodes, at most 1,728 calls. These bound the development pilot only --
the confirmation run's budget depends entirely on decisions 2-4 above and is NOT the 80-100/model
figure the original draft used.
