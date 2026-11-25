# Independent recount and interpretation of the A/B development pilot

Date: 2026-10-13 (Europe/Helsinki). Scope: read-only audit of the twelve retained pilot runs and
both updated research logs. No new inference, Semgrep scans, benchmark edits or regression reruns.
The production code and input hashes agree with the prepared allocation; repeating the unchanged
44-test suite was unnecessary for this result audit.

## Verified execution and headline results

`audit_ab_pilot_20261013.py` successfully checks all 288 episode records against the planned
model, condition, repetition, selection, source/annotation hashes, engine, temperature and limits.
All current allocation input hashes match. Recorded run-start order matches the allocation.
Every episode has one to three attempts; the retained raw captures independently account for all
486 calls, their input/output tokens and generation time. Accepted episodes terminate at the first
correct-location visible pass; none has an earlier passing attempt that was ignored. Final-rule
hashes and evaluated sample hashes match the current files. Per-run summary counts match episodes.

This verifies the retained completed experiment. The contents of the deleted stale directory and
the conversational approvals preceding each user-run command cannot be reconstructed independently
from these surviving result files; those remain execution-history statements in the user's log.

| Model | A successes by repeat | B successes by repeat | A mean E2E | B mean E2E | Difference |
|---|---|---|---:|---:|---:|
| Qwen3-Coder-30B | 6, 6, 6 | 7, 7, 7 | 25.00% | 29.17% | +4.17 percentage points |
| GPT-4o | 6, 5, 5 | 5, 5, 7 | 22.22% | 23.61% | +1.39 percentage points |

These are descriptive averages on the 24 repeatedly consulted development cases. Repeated episode
counts below are used for accounting, not treated as independent cases in a significance test.

| Model/condition | Actual calls | Input tokens | Output tokens | Summed generation seconds |
|---|---:|---:|---:|---:|
| Qwen A | 108 | 101,246 | 32,700 | 277.60 |
| Qwen B | 132 | 138,916 | 32,245 | 311.27 |
| GPT-4o A | 121 | 115,316 | 28,864 | 266.11 |
| GPT-4o B | 125 | 129,371 | 21,648 | 205.35 |
| Total | 486 | 484,849 | 115,457 | 1,060.32 |

The resource table is correct. Generation seconds are summed request durations, not total
experiment wall-clock time or monetary spend. Qwen B uses 22.22% more calls than A; GPT-4o B uses
3.31% more. 486/864 = 56.25% of the proposed ceiling.

## Paired case changes and a correction to the written summary

Qwen has one changed case: CASE-0340 moves from 0/3 to 3/3. The other 23 cases have identical
binary E2E outcomes across all six A/B episodes: six always succeed, seventeen always fail.
This is stability of the observed E2E vector, not absence of variability in generated text,
construction, acceptance or costs. Qwen B's accepted counts vary 15,16,16 and one repeat has a
typed-schema failure; the broader statement "zero within-model variance" needs the E2E qualifier.

| GPT-4o case | A successes /3 | B successes /3 | Change in per-case mean |
|---|---:|---:|---:|
| CASE-0136 | 1 | 3 | +2/3 |
| CASE-0239 | 0 | 1 | +1/3 |
| CASE-0276 | 0 | 3 | +1 |
| CASE-0063 | 3 | 0 | -1 |
| CASE-0220 | 3 | 1 | -2/3 |

Three cases improve and two worsen, but their magnitudes differ. The tracking document's
"net +1 case on average" is incorrect: the sum of per-case mean changes is **+1/3 case**, hence
+1.39 percentage points over 24 cases. There is one additional successful episode across the
three repeated full-set evaluations (17 versus 16), not one additional mean success per repeat.
The headline table and later +0.33/24 wording in the same document already contain the right value.

For Qwen's gain, all repeats remove the CASE-0340 benign-lookalike FP while retaining the positives.
The first-repeat A rule matches broad `execSync($CMD, ...)`; B uses string/template/concatenation
forms. This supports a specificity/generalization explanation from the retained rules and
outcomes, rather than demonstrating that serialization alone caused the gain. GPT-4o's CASE-0063
loss is also a benign-lookalike FP, showing that construction alone does not ensure specificity.

## The construction finding is useful, but needs stage-specific interpretation

| Model/condition | First-response decode/schema failures | First-attempt rule-parse errors | First attempt parsed and scan succeeded |
|---|---:|---:|---:|
| Qwen A | 0/72 | 3/72 | 69/72 |
| Qwen B | 1/72 | 18/72 | 53/72 |
| GPT-4o A | 0/72 | 4/72 | 68/72 |
| GPT-4o B | 0/72 | 3/72 | 69/72 |

All counted first-attempt scanner errors are retained Semgrep **Rule parse error** records, not
target parsing, missing files, timeouts or JSON decoding. Qwen B's one separate typed-schema
failure is CASE-0173, repeat 2: `pattern_not` was a string rather than a list of strings.
All other first-attempt B outputs reach Semgrep. Thus the extra Qwen failures primarily concern
language-specific pattern text inside a valid typed structure, not failure to emit JSON or to
assemble operator lists.

Examples from Qwen B repeat 1:

- CASE-0063: an incomplete `.exec(` expression in the positive pattern.
- CASE-0193: an invalid multi-statement Java exclusion.
- CASE-0235: an exclusion containing an unfinished `if (...) {` fragment.
- CASE-0298: invalid TypeScript string/template pattern text.
- CASE-0323: CSS-selector-like text used as a JavaScript code pattern.

Correct composition also makes exclusions/scopes active compiler inputs. Some A rules still use
the previously documented ignored sibling form. This makes activated invalid constraints a
plausible contributor, alongside changes to positive patterns. The saved errors locate offending
fragments, but isolating the causal contribution would need a separate frozen offline ablation;
this audit did not run one and does not attribute every extra failure to composition.

GPT-4o A's scanner-error sequence is **2,1,1**; B's is **1,1,1**. Correct the tracking table's
"1 (2 of 3 repeats)" to "1 in all 3 repeats." The entire aggregate improvement in this metric
comes from one fewer error in repeat 1. The Correction Log's description of a demonstrated
model-by-intervention interaction is too strong as an inferential conclusion. There is a
**descriptive difference in the observed responses**; no confirmatory interaction test or fresh
holdout supports a general model-level interaction claim. The within-model reporting requirement
is sensible, but this pilot does not prove a population interaction or explain it by lineage.

Also retain the correct E2E denominator: 7/24 is over all requested cases. The phrase "among
accepted episodes (7/24)" mixes denominators. Accepted-only metrics, if provided, must use each
run's 15 or 16 accepted episodes and be labeled conditional.

## Takeaway and next work

The experiment supports a more precise research claim to investigate: typed construction can
ensure the outer representation and operator composition while leaving embedded-pattern validity,
specificity and transformation robustness as separate bottlenecks. Its effects and costs can
differ across the observed model samples. The present data do not demonstrate a worthwhile
general improvement from B, and do not justify a confirmation-scale inference campaign yet.

There is a concrete rationale for the planned probe mechanism. Among accepted Qwen B episodes,
the renamed hidden variant is missed eleven times across five cases (CASE-0163/0239/0171 in all
three repeats, CASE-0173 in repeat 2, CASE-0238 in repeat 3). These are conditional descriptive
counts, not a matched-denominator improvement estimate against A. They show failures an
independently constructed visible-source renaming probe might expose before final evaluation.
Whether it actually does so, and whether the model repairs successfully, remains untested.
Probe feedback after visible success will not directly address candidates that never compile.

Recommended sequence:

1. Correct the reporting details above and preserve these twelve runs as the A/B pilot record.
2. Use retained failures to separate representation validation, pattern compilation, visible
   discrimination and hidden generalization. The audit JSON already provides first-attempt
   categories and offending pattern paths for this bounded analysis; no inference rerun is needed.
3. Implement and offline-validate the existing within-family probe design and combined C/D gate
   if the next question is the added value of behavioral feedback. Keep any new pattern-authoring
   prompt intervention separately versioned, rather than silently changing B before comparison.
4. Use observed variability, call use and failure coverage to inform pilot-repeat and resource
   decisions. Fresh confirmation sourcing and power remain separate decisions requiring the
   finalized estimator. The old 207-case binary scenario does not become the required sample size
   for this repeat-averaged estimator merely because the pilot has now run.

The six open decisions remain decisions; the pilot provides evidence relevant to them. Calling
it "not a step toward any of them" understates its value. It informs what is worth implementing
and budgeting next without automatically resolving the full protocol.

## Evidence and file accounting

Added: this review; `audit_ab_pilot_20261013.py`; `AB_Pilot_Verification_20261013.json` (full per-run,
per-case, first-error and input-hash evidence); and
`commands/20261012T224901954570Z_completed_ab_pilot_review.log` (successful executable recount).
The UTC command timestamp falls on October 12; the local research date is October 13.
Modified: `README.md` (review link) and append-only `events.jsonl` (command/milestone records).
No implementation, user-authored Tracking/Correction entries, existing results or benchmark
files were edited. Prior read-only inspection and supplementary case-level interpretation are
documented above. The final event records hashes of the added artifacts and verifies that all
audited inputs remained unchanged during this review.

## Documentation closure, 2026-10-13

The subsequent user revision resolves the substantive reporting findings above. Before this
closure's edits, the only changes among the 814 previously audited files were the Tracking and
Correction logs; every allocation input hash still matched. The previously verified numerical
results and per-case evidence therefore remain applicable without another scan or inference run.

Applied three small text corrections to `Bounded_Investigation_Tracking.md`: three positive samples
rather than four for the CASE-0340 explanation; `scan_errors` excludes response/schema failures
rather than combining them; and the 207-case scenario does not directly size a repeat-averaged
confirmation study. Appended a correction/closure entry to `Research_Log/Correction_Log.md`.
This review file and append-only `events.jsonl` record that work. No new files, implementation
changes, result edits, tests, Semgrep scans or model calls were introduced. The pilot-results
review is closed; the next work remains probe implementation and offline validation.
