# Review of Item 3 evidence and the proposed 2×2 protocol

Date: 2026-10-12. Status: review and recommendations, **not protocol approval or freeze**.
Reviewed `Controlled_2x2_Protocol_Draft_20261012.md`, Item 3 in
`Bounded_Investigation_Tracking.md`, the appended Correction Log, the original Research Direction,
and all 24 retained reference scan evaluations and raw Semgrep outputs. No model calls or new
Semgrep scans were made. No implementation, benchmark, historical results, or user-authored draft
was changed. C3/C4 remain deferred.

## Verified evidence

The new audit script, `verify_item3_and_protocol_power.py`, completed successfully through the
existing command journal. Its full output and input hashes are retained in
`commands/20261012T005357377354Z_item3_protocol_review_evidence.log`.

All 24 raw outputs identify Semgrep 1.177.0, report no scan errors, and contain all six requested
targets. The evaluations agree with the summary and raw finding lines. All 144 current sample
hashes agree with the retained evaluations. The recorded location-correctness fields classify all
72 positive samples as TP; annotations were not independently re-adjudicated in this review.

| Result | Verified count |
|---|---:|
| Reference rules with at least one false positive | 9/24 |
| False-positive negative samples | 12/72 |
| True-negative samples | 60/72 |
| Positive detections, recorded as location-correct | 72/72 |
| Reference complete successes | 15/24 |

The nine precision-gap cases match the report: CASE-0046, 0063, 0116, 0163, 0184, 0193, 0235,
0238, 0339. This is evidence about these diagnostic rules on their own bundles. It is not a new
model score, independent expert baseline, or generalization ceiling. The raw scan arithmetic is
sound; the main remaining issues concern interpretation and experimental specification.

## Findings to resolve before freezing

### 1. High: full semantic verification does not follow from reference-rule agreement

Tracking Item 3 explicitly says that 13 cases have received direct source comparisons (six earlier,
seven newly compared), while the remaining 11 rely on the reference rule passing the bundle.
It then calls that latter evidence non-confounded confirmation of vulnerability preservation.
That conclusion is unsupported. These rules were authored after inspecting those same samples.
Correctly rejecting three chosen negatives does not prove that a positive retains attacker control,
reachability, the relevant data flow, or the vulnerability's security consequence.

The original Research Direction explicitly states that passing six samples establishes only
sample-level fit. Thus the exhaustive **reference-rule behavior audit** is complete, while direct
semantic review remains incomplete for CASE-0323, 0276, 0221, 0136, 0340, 0124, 0222, 0171,
0298, 0231, and 0081. Independent review remains a separate unmet requirement, even after a
best-effort self-review is finished. The present review does not allege that those 11 transforms
are wrong; it identifies an evidence gap.

Recommended correction: describe coverage separately as 24/24 rule executions, 13/24 reported
direct restructuring comparisons, and 11/24 rule-based consistency checks. Complete the remaining
source-based checks with per-case rationale covering the vulnerability mechanism, input/control
flow, helper binding/call behavior, and prerequisites. Do not extend conclusions about the
restructured positive to all other positive/negative transformations without reviewing those too.
Preserve the distinction between self-review and independent adjudication.

### 2. High: the draft substantially understates confirmation sample size

For one independent paired binary outcome per case, take the draft's absolute improvement
delta = 0.10 and total discordance q = 0.25. These imply win probability 0.175 and loss probability
0.075. Let D ~ Binomial(N, 0.25), and W conditional on D ~ Binomial(D, 0.70). The script sums the
alternative probability of rejecting a two-sided exact conditional McNemar test at alpha = 0.05
over every possible D and W. The exact test's binomial formulation is documented by
[statsmodels](https://www.statsmodels.org/dev/generated/statsmodels.stats.contingency_tables.mcnemar.html).
The powers below are our calculation, not numbers quoted from that documentation.

| Independent paired cases | Power for a 10-point difference |
|---|---:|
| 80 | 35.4% |
| 100 | 44.0% |
| 200 | 78.7% |
| 207 | 80.2% |

207 is the first integer N reaching 80% in this specified calculation. A five-point effect at the
same discordance needs 817 cases. These are sensitivity scenarios, not a finalized recommendation
for the proposed repeated-trial design. Different tests and discordance assumptions change power.
Repository clustering and multiple confirmatory comparisons also need consideration. Repeated
trials on the same case cannot simply be counted as independent additional cases.

Recommended correction: withdraw the 80–100/80%-power statement. Define the primary contrast,
repeated-trial estimator and uncertainty procedure, then recalculate or simulate power for that
actual design. Budget for roughly 200 or more cases in the simple 10-point scenario, while keeping
the final number conditional on the chosen analysis and feasibility. With a smaller feasible
sample, report the attainable precision/power rather than claiming the original target.

### 3. Medium: several operational choices are still missing beyond the five listed decisions

The shared three-call cap is useful, but Research Direction also requires matched token ceilings.
Freeze the per-call output limit (2048 is the existing diagnostic setting), input/context policy,
retry accounting, timeout/error treatment, and total run budget. Equal ceilings do not imply equal
actual expenditure; report actual calls, tokens, scans and elapsed time separately.

Specify the typed JSON prompt/decoder and invalid-output repair feedback. The intervention includes
an output contract, restricted grammar and serializer, so its effect belongs to that construction
pipeline as a whole. The draft correctly acknowledges that restriction and retains hard cases.

For C/D, specify the number of vulnerable/patched probes, supported language implementations,
deterministic generation and caching, name-collision/scope checks, eligibility and generation-failure
behavior. The `Call`/`arg` terminology and reflection filter need a concrete implementation for
each supported language. Ineligible cases must remain in the primary denominator, with an explicit
fallback policy; report probe coverage. A/B can avoid loading the probe module while C/D reuse
the same case-level probes across models and trials.

Freeze episode termination and final-candidate selection: for example, choose the first candidate
passing all checks designated for its condition within three calls; otherwise retain the last
candidate for diagnostic scoring while marking acceptance failure, with E2E success explicitly
defined for this situation. Other choices are possible, but all must be stated before outcomes.
The current stopping-rule section chiefly describes freezing, rather than these actual rules.
Specify experiment-level stopping too: fixed allocated episodes, no stopping when a favorable
effect first appears, and a predefined policy for infrastructure interruptions.

### 4. Medium: the statistical analysis and model-selection rationale need correction

Prior failure to detect a model difference does not establish equivalence, nor exclude a
model-by-intervention interaction. Compare conditions within each model and report heterogeneity.
GPT-4o's different lineage and prior use in the project are sufficient reasons to include it;
the parity argument is unnecessary. Three repeats are a reasonable small pilot allocation, not
the mathematical minimum permitting a variance estimate (two already permit a sample variance).

Predeclare how repeats are aggregated (for example, average success per case and condition), the
primary contrast, secondary contrasts and multiplicity policy. Preserve case/repository grouping
in uncertainty estimates. For a full factorial analysis, distinguish the construction main effect
`((B-A)+(D-C))/2`, feedback main effect `((C-A)+(D-B))/2`, and interaction `D-C-B+A` from the simple
effects B-A and C-A. If only one contrast is confirmatory, designate it and label the rest exploratory.

### 5. Lower priority: legacy scoring does not recover the historical generation trajectory

Recording both scoring fields on new corrected-policy candidates is useful. It answers how those
particular candidates score under each gate. It does not reproduce the candidates a legacy-policy
loop would have returned, since legacy acceptance can stop earlier. Qualify the historical
comparability wording; a genuine policy comparison needs the corresponding attempt trajectories
or separately controlled runs. No historical score needs changing.

## Recommendations for the five proposed decisions

| Decision | Recommendation and reason |
|---|---|
| Repeats | Three per model/condition for the development pilot; retain every trial. Reassess confirmation allocation using observed variability and cost. |
| Worthwhile improvement | Keep 10 absolute percentage points as a provisional planning target, accompanied by cost and a five-point sensitivity analysis. Small-set resolution and past prompt swings do not establish practical value or isolate sampling noise. |
| Confirmation size | Derive it after specifying the estimator and primary contrast. The simple scenario needs 207, not 80–100; the final repeated-trial/clustered design needs its own calculation. |
| C/D timing | Pilot A/B first while probe engineering is unfinished. Add C/D after offline validity and feedback checks pass, before freezing a full 2×2 confirmation. An A/B-only pilot is not a completed 2×2 experiment. |
| New confirmation sourcing | It is scientifically justified for a fresh generalization claim. Define sourcing/eligibility/review now, assess feasibility before committing to a case count, and keep collection a separately budgeted task. No collection was initiated in this review. |

At 24 development cases, two models, two conditions and three repeats, an A/B pilot is 288 episodes
and at most 864 calls under the three-call cap. All four cells would be 576 episodes and at most
1,728 calls. These are budget ceilings, not requests sent or cost estimates. Confirmation needs
fresh cases; repeated development improvements cannot establish the final research claim.

## Verification and file accounting

The evidence script passed all assertions against retained artifacts and completed both power
calculations. The source/test hashes for `typed_rule.py` and `test_typed_rule.py` agree with the
previous closure record; the 31-test suite was not rerun for this documentation-only review.
The user's reported 31/31 is consistent with that previous verification, but is not represented
as a newly executed test run here.

Added: this review; `verify_item3_and_protocol_power.py`; the timestamped command log linked above.
Modified: `README.md` (review link) and append-only `events.jsonl` (command and review records).
The event record hashes the added artifacts and updated README. Read-only inspection and the
initial exploratory calculation preceded the retained reproducible run. No other files were
intentionally edited, and the draft, Tracking document and Correction Log retain their reviewed
hashes. The pre-existing working tree already contained modified/untracked research files; no
claim of a literally clean Git index or working tree is made.
