# Qwen3 mechanism run v3: fixed-example prompt review

The user supplied terminal output for command label `qwen3_mechanism_v2_fixed_examples`, using prompt `diagnostic_mechanism_v2` and output directory `qwen3_mechanism_v3`. These identifiers refer to the same run. The recorded start is 2026-10-10 23:22:14 UTC. Exit 0 and 24 completed episodes mean the experiment finished; individual generation and scan failures remain in the recorded outcomes.

## Verified fixes

Captured Python, JavaScript and Java example sections now pass `yaml.safe_load` after dedenting. Each contains two example rules. The TypeScript example section remains empty. This confirms the YAML indentation repair, not complete Semgrep DSL validation; examples were not compiled by this review.

The environment records a distinct `diagnostic_mechanism_v2` prompt identifier, resolving the previous ambiguity between changed prompts sharing the same name. Model, selection, temperature 0, 2048-output-token limit, three-call budget, schema policy and Semgrep 1.177.0 remain the same.

The runner still stops using `legacy_accepted` and scans the frozen `.ts` bundle. Thus the corrected location gate and TSX staging are still not integrated into this model experiment.

## Results

| Iterative metric | Original prompt (`qwen3_v3`) | Mechanism run v2 | Mechanism run v3 |
|---|---:|---:|---:|
| E2E success | 6/24 (25.0%) | 5/24 (20.8%) | 5/24 (20.8%) |
| Visible acceptance | 19 | 15 | 14 |
| Correct-location visible acceptance | 18 | 13 | 12 |
| Accepted hidden-positive hits / all requested positives | 30/48 | 21/48 | 20/48 |
| Hidden false positives / evaluated accepted negatives | 8/38 | 4/30 | 4/28 |
| Model calls | 34 | 44 | 45 |

V3 succeeds on CASE-0134, CASE-0136, CASE-0220, CASE-0276 and CASE-0323. Compared with the immediately previous mechanism run, it gains CASE-0276 and CASE-0323 and loses CASE-0063 and CASE-0221: unchanged total, different successful cases. Compared with the original prompt it has no newly successful cases and loses CASE-0221.

All five complete successes occur on the first attempt. Thirteen cases used one call, one used two calls and ten used three calls. Twenty-one extra calls beyond one per requested case add only CASE-0184 to visible acceptance, with incorrect original location, and add zero complete successes. Correct-location visible acceptance is 12 in both raw and iterative conditions.

Reported totals: 60,705 input tokens, 11,755 output tokens, approximately 144.60 seconds of provider-call elapsed time. All 45 finish reasons are `stop`; no API exceptions or truncated responses were recorded. Provider elapsed time is not total experiment runtime. No monetary cost is inferred.

## Case-level failure evidence

- **CASE-0221:** each of the three raw responses is a YAML document containing two rules. Every attempt fails with `Expected exactly one rule mapping`; none reaches a hidden scan. This is an output-contract violation, not a demonstrated inability of either individual candidate to detect the vulnerability. The prompt examples themselves contain two rules while the required response is exactly one; that inconsistency is a plausible influence, not an established causal explanation. A future prompt should demonstrate the exact intended single-rule response shape. Do not silently select one candidate after inspecting hidden outcomes or retrospectively count this episode as successful.
- **CASE-0238:** all three attempts still fail YAML parsing at the unquoted code fragment containing `escapeFormulae: true`. Correcting example indentation did not solve this separate scalar-quoting failure.
- **CASE-0063:** the accepted rule detects the three positives but also flags the benign sample, losing the previous run's E2E success.
- **CASE-0298:** target syntax errors persist in all attempts because the recorded model-run scans use `.ts` rather than `.tsx` staging.
- **CASE-0231:** first attempt has a rule parse error; second misses the original; third flags the patched sample. No candidate is accepted.
- **CASE-0184 and CASE-0081:** accepted by the legacy gate despite incorrect original finding locations; neither qualifies as E2E success.

The raw summary has 22 evaluations because CASE-0221 and CASE-0238 never produce an accepted rule envelope. Two raw evaluations have scan errors. The iterative summary has 14 evaluations, all error-free, because only accepted final rules are scanned in that condition; the ten missing iterative evaluations remain failures in the denominator of 24.

## Interpretation and next decision

The YAML examples and condition naming are improved, but this run shows no net E2E gain over mechanism run v2 and remains below the original prompt. It does not establish a causal effect of the formatting fix or general population performance. All results are exploratory on the previously selected development subset.

Pause broad prompt reruns. The next bounded work is to validate one-rule examples, explicit YAML quoting/block-scalar guidance and the actual evaluation adapter offline. Inspect retained CASE-0221 and CASE-0238 outputs before making more inference calls; preserve their current failures and treat any repaired output as a separate diagnostic condition. Once the changed workflow is validated, use a small visible-only smoke check before another full 24-case development run. Hidden cases/results must not enter repair or candidate selection, and any chosen workflow needs fresh held-out confirmation.

## Evidence and changes made by this review

- Source: `results/diagnostic_20261010/qwen3_mechanism_v3/`, including all episode/request/response artifacts.
- Command log: `Research_Log/Diagnostic_20261010/commands/20261010T232210311451Z_qwen3_mechanism_v2_fixed_examples.log`.
- Runner SHA-256: `5a64d612a33489a9ce3055012d2a0d867f2dc6e8d4d606a898e768eee9350d0d`.
- LLM client SHA-256: `98974a368b4a551c469e42a32857790f725d5e151753961dbf64e117913734f0`.

This review adds this document, updates the audit README with a pointer and appends a milestone with hashes to `events.jsonl`. It does not modify implementation, prompts, labels, recorded run results or `Correction_Log.md`. No model calls or Semgrep scans were launched. Earlier inventories remain snapshots of their recorded checkpoint time.
