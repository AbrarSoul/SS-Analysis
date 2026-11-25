# Qwen3 mechanism prompt v1: terminal and saved-artifact review

The user supplied terminal output for `qwen3_mechanism_v1`. The saved environment, summary, all case episodes and provider finish reasons were inspected alongside `qwen3_v3`. This review launches no model calls or scans and changes no implementation, model outputs or labels.

## Result

The revised condition completed all 24 requested cases with process exit 0. Complete E2E success fell from 6/24 (25.0%) in the legacy-prompt diagnostic to 4/24 (16.7%), a decrease of two cases or 8.3 percentage points. No new cases passed. CASE-0134 and CASE-0220 lost their previous success; CASE-0136, CASE-0221, CASE-0276 and CASE-0323 remained successful.

| Metric | Legacy prompt, iterative | Mechanism v1, first attempt | Mechanism v1, iterative |
|---|---:|---:|---:|
| Requested cases | 24 | 24 | 24 |
| Accepted by legacy visible gate | 19 | 6 | 11 |
| Correct original location and patched rejection | 18 | 6 | 10 |
| Complete successes | 6 | 4 | 4 |
| Accepted hidden-positive hits / all requested positives | 30/48 | 12/48 | 16/48 |
| Hidden-negative false positives / evaluated accepted negatives | 8/38 | 2/12 | 4/22 |
| Model calls for the complete workflow | 34 | — | 55 |

Retries recovered visible acceptance on five cases (CASE-0184, CASE-0173, CASE-0222, CASE-0163 and CASE-0081), but recovered zero complete successes. CASE-0081 still passes the any-original-finding gate despite missing the accepted original location.

The smaller false-positive count is not evidence of better specificity: the revised condition accepts fewer rules and evaluates fewer hidden negatives. Likewise, zero iterative scan errors only describes the 11 accepted final rules, not all 24 requested cases. Two first attempts never parsed and therefore have no raw hidden scan; three other first attempts have scan errors.

## Configuration and comparability

Both runs use the same frozen 24-case selection, Qwen3-Coder 30B, temperature 0, 2048 output tokens per call, at most three calls per case, `semgrep_search_taint_v2`, and Semgrep 1.177.0. The new environment labels its prompt `EXPLICIT_REVISED_CONDITION:diagnostic_mechanism_v1`.

The revised prompt is a combined intervention. In addition to explicitly allowing composite/taint forms and adding mechanism guidance, it removes the legacy prompt's language-specific examples and response template. The saved CASE-0134 requests confirm the old example section and `pickle.loads` example were present in the baseline and absent in mechanism v1. The new builder's docstring claims it keeps the same per-language examples; its implementation and actual captured requests contradict that claim. Consequently this run does not isolate the effect of mechanism guidance.

The run still scans the frozen `.ts` targets and stops generation using `legacy_accepted`. It therefore does not implement the complete corrected evaluator proposed earlier. CASE-0298 retains target syntax errors in all three attempts. Previously added annotation rescoring files are not automatically used by this runner.

This is a descriptive result on an outcome-stratified development subset. It is not a new full-population rate or a significance claim. It does not establish that mechanism reasoning is inherently harmful, nor that composite/taint support has no value.

## Concrete failures

- CASE-0238: all three responses fail YAML parsing. The unquoted scalar containing `Papaparse.unparse(..., { escapeFormulae: true })` contains a colon-space sequence that breaks the YAML mapping. This is a generated-output formatting failure, not a network failure.
- CASE-0116: first response ended with provider `finish_reason="length"` at exactly 2048 output tokens and was rejected for a missing `message` field. The response was truncated; it should not be described solely as forgetting a required field. Subsequent parsed candidates miss the original vulnerability.
- CASE-0134: all three attempts miss the original vulnerable sample. The first candidate uses `re.compile` patterns and describes path traversal/injection, while the reference review identified an ambiguous nested-regex repetition. This warrants rule-level diagnosis before another prompt revision.
- CASE-0220: all three attempts miss the original. The first candidate places two separate header calls under `patterns`, suggesting a mistaken use of conjunction for alternatives, and also emits questionable exclusions. This is an observed rule-construction issue; no corrected candidate was tested in this review.
- CASE-0173 and CASE-0171: first attempts have rule/schema parse errors. CASE-0173 eventually passes visible validation but still misses a hidden positive; CASE-0171 never becomes accepted.

There were zero recorded API exceptions. Finish reasons were `stop` for 54 calls and `length` for one. The baseline had 34 `stop` completions. Mechanism v1 used 60,991 reported input tokens and 15,564 output tokens, versus baseline 32,919 and 10,090. It used 21 additional calls (approximately 62% more). Recorded provider-call elapsed time was about 211.79 seconds versus 256.50 seconds; these are not total experiment runtimes and do not establish a speed improvement.

## Next step

Do not promote mechanism v1 or rerun all models with it. Preserve it as a negative development result. Complete the versioned evaluator fixes and replay retained candidates first. For a subsequent prompt trial, explicitly control changes to examples and formatting guidance, use validated YAML/DSL examples, and separate a schema/formatting change from an added reasoning instruction. A small offline check of retained failures can identify what each proposed change actually addresses before paid inference. Keep the token/call budget fixed for a matched comparison; changing it to handle truncation would be another named condition.

Never provide hidden samples or hidden outcomes to the repair loop. Any workflow selected using this development subset needs fresh held-out confirmation.

## Provenance and file accounting

- Source run: `results/diagnostic_20261010/qwen3_mechanism_v1/`.
- Baseline: `results/diagnostic_20261010/qwen3_v3/`.
- Command log: `commands/20261010T215941464094Z_qwen3_mechanism_v1.log` under this audit directory.
- Recorded run start: 2026-10-10 21:59:43 UTC.
- Runner SHA-256 recorded by the run: `82bcb158e3b7f13d4d10302e1be9d1e54e82e8eabe84401207f40fa91175976f`.
- LLM client SHA-256 recorded by the run: `0319a039721f75f6ec461e8b32963c630c2ae78c04dbc98c9e4c83aa7428e59f`.

This review adds this document, updates the audit README with its link, and appends a milestone with source/document hashes to `events.jsonl`. Existing inventories remain snapshots of their stated checkpoint time. No edits were made to `Correction_Log.md`, prompt code, runner code, or historical results.
